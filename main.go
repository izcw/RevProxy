package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fsnotify/fsnotify"
)

const iniFile = "proxy.ini"

// 全局版本
var version = "v1.0.6" // 版本号更新

// Route 表示一条代理规则
type Route struct {
	Prefix        string   // 原始配置中的前缀（对于 regex 为正则表达式文本）
	Target        *url.URL // 解析后的目标 URL（Host + Scheme）
	Proxy         *httputil.ReverseProxy
	Regex         bool           // 是否使用正则匹配
	Generic       bool           // generic 标志（保留原语义）
	Re            *regexp.Regexp // 若 Regex == true，则保存编译后的正则
	TargetPathT   string         // 目标路径模板（允许包含 $1/$2 替换）
	reSubexpCount int            // 正则捕获组数量（用于保护性校验）
}

// ConfigRuntime 保存运行时配置
type ConfigRuntime struct {
	sync.RWMutex
	Port    int
	Routes  []*Route
	Updated time.Time
	Valid   bool // 新增：标记配置是否有效
}

var cfg = &ConfigRuntime{
	Valid: false, // 初始状态为无效
}

// Stats 保存运行指标
type Stats struct {
	StartTime      time.Time
	TotalRequests  uint64
	PerRouteCounts map[string]uint64
	UniqueClients  map[string]struct{}
	Mutex          sync.Mutex
	QPS            int64
	lastQPSReset   time.Time
}

var stats = &Stats{
	StartTime:      time.Now(),
	PerRouteCounts: make(map[string]uint64),
	UniqueClients:  make(map[string]struct{}),
	lastQPSReset:   time.Now(),
}

// reloadChan 用于通知主循环重启（平滑重启服务器）
var reloadChan = make(chan struct{}, 1)

// loggingResponseWriter 捕获响应状态和字节数
type loggingResponseWriter struct {
	http.ResponseWriter
	status  int
	written int64
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	if l.status == 0 {
		l.status = code
	}
	l.ResponseWriter.WriteHeader(code)
}

func (l *loggingResponseWriter) Write(b []byte) (int, error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err := l.ResponseWriter.Write(b)
	l.written += int64(n)
	return n, err
}

// -----------------------------
// URL 校验
// -----------------------------
// validateTarget 校验并返回解析后的 url.URL
func validateTarget(raw string) (*url.URL, error) {
	// 如果没有 scheme，默认 http
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("不支持的 scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("目标 URL 缺少 host")
	}
	hostOnly := u.Host
	if strings.Contains(hostOnly, ":") {
		hostOnly, _, _ = net.SplitHostPort(hostOnly)
	}
	// 简单校验 host：localhost 或 IP 或包含点的域名
	if hostOnly != "localhost" && net.ParseIP(hostOnly) == nil && !strings.Contains(hostOnly, ".") {
		return nil, fmt.Errorf("目标 host 非法: %s (需为 IP 或合法域名)", hostOnly)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// -----------------------------
// 配置文件解析与热加载
// -----------------------------
func loadOrCreateIni() error {
	if _, err := os.Stat(iniFile); os.IsNotExist(err) {
		if err := createDefaultIni(); err != nil {
			return fmt.Errorf("自动创建默认配置失败: %v", err)
		}
		log.Printf("已自动创建默认配置 %s", iniFile)
	}

	if err := parseIniAndApply(iniFile); err != nil {
		backup := iniFile + ".broken." + time.Now().Format("20060102150405")
		_ = os.Rename(iniFile, backup)
		log.Printf("配置解析失败，已备份为 %s: %v", backup, err)
		if err := createDefaultIni(); err != nil {
			return fmt.Errorf("解析失败且自动重建默认配置失败: %v", err)
		}
		// 重建后再次尝试解析
		if err := parseIniAndApply(iniFile); err != nil {
			return fmt.Errorf("重建配置后仍然解析失败: %v", err)
		}
	}
	return nil
}

func createDefaultIni() error {
	content := `# 使用文档：https://github.com/izcw/RevProxy

# 服务监听端口（配置文件中首次出现的纯数字）
4288

# 路由规则格式：路径前缀  目标地址  [匹配类型]
/MFP62                        192.168.0.100
^/DynamicPort/(\d+)/(.*)$     192.168.0.$1/$2     regex
/printer                      192.168.0.101       generic`
	return os.WriteFile(iniFile, []byte(content), 0644)
}

// parseIniAndApply 解析配置文件并应用到运行时配置
func parseIniAndApply(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开配置文件: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var port int
	var parsedRoutes []*Route
	lineNo := 0
	hasRoutes := false

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 第一行（或第一处非注释非空）优先解析为端口（只有当尚未设置端口时）
		if port == 0 {
			if p, err := strconv.Atoi(line); err == nil {
				if p < 1 || p > 65535 {
					return fmt.Errorf("第 %d 行端口超出范围: %d", lineNo, p)
				}
				port = p
				continue
			}
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			return fmt.Errorf("第 %d 行格式错误（应为: /prefix target [type]）: %s", lineNo, line)
		}
		prefix := parts[0]
		targetRaw := parts[1]

		// 允许 target 中包含 $1/$2（仅用于 path 部分替换），但 validateTarget 仍然需要能解析 host
		targetURL, verr := validateTarget(targetRaw)
		if verr != nil {
			return fmt.Errorf("第 %d 行目标地址无效: %v", lineNo, verr)
		}

		isRegex := false
		isGeneric := false
		if len(parts) >= 3 {
			if parts[2] == "regex" {
				isRegex = true
			} else if parts[2] == "generic" {
				isGeneric = true
			}
		}

		// 复制 target，以免后续被修改
		targetCopy := *targetURL

		// 预处理：将目标 URL 的 Path 作为模板保存（可能包含 $1/$2）
		targetPathTemplate := targetCopy.Path
		// 如果没有显式 path，设为 "/"
		if targetPathTemplate == "" {
			targetPathTemplate = "/"
		}

		var compiled *regexp.Regexp
		var subexpCount int
		if isRegex {
			// 将 prefix 当作正则表达式编译
			re, err := regexp.Compile(prefix)
			if err != nil {
				return fmt.Errorf("第 %d 行正则表达式编译失败: %v", lineNo, err)
			}
			compiled = re
			subexpCount = re.NumSubexp()
			// 如果模板中使用了 $n，但 n 大于 re 的子表达数量，记录警告（但不致命）
			templateMax := maxDollarIndex(targetPathTemplate)
			if templateMax > subexpCount {
				log.Printf("警告: 第 %d 行目标 path 模板引用了 $%d，但正则只有 %d 个捕获组，替换可能为空", lineNo, templateMax, subexpCount)
			}
		} else {
			// 对非 regex 的 prefix 做常规清理：保留原样，但统一移除尾部斜杠（除了根 /）
			if len(prefix) > 1 {
				prefix = strings.TrimRight(prefix, "/")
			}
		}

		// 创建 ReverseProxy 并为其设置默认 Director（后面根据 route 类型覆盖）
		proxy := httputil.NewSingleHostReverseProxy(&targetCopy)

		// 设置更健壮的 Transport（连接池、超时）
		proxy.Transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   20,
		}

		// 设置 ModifyResponse 以便记录后端返回错误并进行防御性处理
		proxy.ModifyResponse = func(resp *http.Response) error {
			// 若后端返回 5xx，则记录详细日志（保留 body 的前 1KB）
			if resp.StatusCode >= 500 {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				// 重新填充 body 以便后续读
				resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(string(bodyBytes)), resp.Body))
				log.Printf("后端 %s 返回 %d，响应体（前1KB）：%s", targetCopy.String(), resp.StatusCode, string(bodyBytes))
			}
			return nil
		}

		// 错误处理
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error -> %s | %v", r.URL.String(), err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": 502,
				"msg":    "后端服务不可用",
				"detail": err.Error(),
			})
		}

		route := &Route{
			Prefix:        prefix,
			Target:        &targetCopy,
			Proxy:         proxy,
			Regex:         isRegex,
			Generic:       isGeneric,
			Re:            compiled,
			TargetPathT:   targetPathTemplate,
			reSubexpCount: subexpCount,
		}

		// 对 regex 路由，覆盖 Director 为基于正则替换的 Director
		if isRegex {
			// 用 targetCopy 的拷贝（避免引用共享）
			targetCopy2 := targetCopy
			route.Proxy.Director = makeDirectorForRegex(compiled, &targetCopy2, targetPathTemplate)
		} else {
			// 非 regex 使用先前的 Director（基于 prefix 的普通替换）
			targetCopy2 := targetCopy
			route.Proxy.Director = makeDirector(prefix, &targetCopy2)
		}

		parsedRoutes = append(parsedRoutes, route)
		hasRoutes = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取配置文件出错: %v", err)
	}

	if port == 0 {
		port = 4288
	}

	// 关键修复：确保至少有一条路由
	if !hasRoutes {
		log.Printf("警告: 配置文件中没有定义任何路由，将使用默认路由")
		// 创建一个默认路由避免空路由列表
		defaultTarget, _ := validateTarget("http://127.0.0.1:8080")
		defaultProxy := httputil.NewSingleHostReverseProxy(defaultTarget)
		defaultRoute := &Route{
			Prefix:  "/",
			Target:  defaultTarget,
			Proxy:   defaultProxy,
			Regex:   false,
			Generic: false,
		}
		defaultRoute.Proxy.Director = makeDirector("/", defaultTarget)
		parsedRoutes = append(parsedRoutes, defaultRoute)
	}

	// 按照 Prefix 长度降序排序（以便更长的 prefix 拥有更高匹配优先级）
	sort.Slice(parsedRoutes, func(i, j int) bool {
		// 对 regex 路由，优先级以在文件中出现的顺序为主（保持稳定），但为了兼容原有逻辑：
		// 仍然对非 regex 前缀按长度降序排序以保证长前缀优先
		li := parsedRoutes[i]
		lj := parsedRoutes[j]
		// 非 regex 比 regex 更具确定性，优先放前面（但保持长度优先）
		if li.Regex != lj.Regex {
			return !li.Regex && lj.Regex
		}
		return len(li.Prefix) > len(lj.Prefix)
	})

	cfg.Lock()
	cfg.Port = port
	cfg.Routes = parsedRoutes
	cfg.Updated = time.Now()
	cfg.Valid = true // 标记配置为有效
	cfg.Unlock()

	log.Printf("配置加载成功: 端口 %d, 路由数 %d", port, len(parsedRoutes))
	return nil
}

// maxDollarIndex 返回模板中使用的最大 $n 索引（用于警告）
func maxDollarIndex(t string) int {
	re := regexp.MustCompile(`\$(\d+)`)
	max := 0
	matches := re.FindAllStringSubmatch(t, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			if idx, err := strconv.Atoi(m[1]); err == nil && idx > max {
				max = idx
			}
		}
	}
	return max
}

// -----------------------------
// Director 函数生成（非 regex 版本）
// -----------------------------
// makeDirector 用于常规前缀路由，基于 prefix 截断请求路径并拼接到 target.Path
func makeDirector(prefix string, target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		origPath := req.URL.Path
		// 将匹配到的 prefix 从原路径中截断
		trimmed := strings.TrimPrefix(origPath, prefix)
		if trimmed == "" {
			trimmed = "/"
		}
		if !strings.HasPrefix(trimmed, "/") {
			trimmed = "/" + trimmed
		}
		var newPath string
		if target.Path != "/" && strings.HasPrefix(trimmed, target.Path) {
			newPath = trimmed
		} else {
			newPath = joinURLPath(target.Path, trimmed)
		}

		// 保留查询字符串
		if req.URL.RawQuery != "" {
			newPath = newPath + "?" + req.URL.RawQuery
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		// 注意：ReverseProxy 会根据 req.URL.Path/RawPath 拼请求，Query 由 RawQuery 控制
		u, _ := url.Parse(newPath)
		req.URL.Path = u.Path
		req.URL.RawPath = u.RawPath
		req.URL.RawQuery = u.RawQuery
		req.Host = target.Host

		// 设置或追加 X-Forwarded-For
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			prior := req.Header.Get("X-Forwarded-For")
			if prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		}
	}
}

// makeDirectorForRegex 用于正则路由：
// - 使用 re 匹配请求路径
// - 将 target 模板中的 $1/$2 替换为捕获组
// - 如果目标路径模板以 / 开头则直接使用，否则以 target.Path 与替换结果做拼接（常见情况 target.Path 为 / 或 /api）
// makeDirectorForRegex 用于正则路由，支持主机名和路径的替换
func makeDirectorForRegex(re *regexp.Regexp, target *url.URL, targetPathTemplate string) func(*http.Request) {
	return func(req *http.Request) {
		origPath := req.URL.Path
		matches := re.FindStringSubmatch(origPath)

		// 替换目标主机名中的 $1/$2
		targetHost := target.Host
		if len(matches) > 0 {
			targetHost = replaceDollarRefs(targetHost, matches)
		}

		// 替换目标路径模板中的 $1/$2
		replacedPath := targetPathTemplate
		if len(matches) > 0 {
			replacedPath = replaceDollarRefs(targetPathTemplate, matches)
		} else {
			if targetPathTemplate == "/" {
				replacedPath = origPath
			} else {
				replacedPath = joinURLPath(target.Path, origPath)
			}
		}

		// 构建新路径
		var newPath string
		if strings.HasPrefix(replacedPath, "/") {
			newPath = replacedPath
		} else {
			newPath = joinURLPath(target.Path, replacedPath)
		}

		// 保留查询字符串
		if req.URL.RawQuery != "" {
			newPath = newPath + "?" + req.URL.RawQuery
		}

		// 进行最终赋值
		u, _ := url.Parse(newPath)
		req.URL.Scheme = target.Scheme
		req.URL.Host = targetHost // 使用替换后的主机名
		req.URL.Path = u.Path
		req.URL.RawPath = u.RawPath
		req.URL.RawQuery = u.RawQuery
		req.Host = targetHost // 使用替换后的主机名

		// 保留原始客户端 IP 到 X-Forwarded-For
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			prior := req.Header.Get("X-Forwarded-For")
			if prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		}
	}
}

// replaceDollarRefs 将模板中的 $1/$2/... 替换为 matches 中对应的捕获组
// matches[0] 是整个匹配，matches[1] 是第一个捕获组
func replaceDollarRefs(template string, matches []string) string {
	// 使用正则找到 $n 模式并替换
	// 注意：$0 -> 整体匹配
	re := regexp.MustCompile(`\$(\d+)`)
	return re.ReplaceAllStringFunc(template, func(m string) string {
		// 提取数字
		sub := re.FindStringSubmatch(m)
		if len(sub) < 2 {
			return ""
		}
		idxStr := sub[1]
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx >= len(matches) {
			return ""
		}
		return matches[idx]
	})
}

// joinURLPath
func joinURLPath(a, b string) string {
	if a == "/" {
		return b
	}
	if strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/") {
		return a + strings.TrimPrefix(b, "/")
	}
	if !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/") {
		return a + "/" + b
	}
	return a + b
}

// -----------------------------
// 热加载监控（监控文件变化并平滑 reload）
// -----------------------------
func watchIniFile(path string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("无法创建 fsnotify 监控: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := watcher.Add(dir); err != nil {
		log.Printf("无法添加监控目录: %v", err)
		return
	}

	var reloadMu sync.Mutex
	var lastReload time.Time

	for {
		select {
		case ev := <-watcher.Events:
			// 仅对目标 path 的写入、创建、重命名等事件做处理（避免对临时文件重复触发）
			if ev.Name == path && (ev.Op&fsnotify.Write == fsnotify.Write ||
				ev.Op&fsnotify.Create == fsnotify.Create ||
				ev.Op&fsnotify.Rename == fsnotify.Rename) {

				reloadMu.Lock()
				if time.Since(lastReload) < time.Second {
					reloadMu.Unlock()
					continue
				}
				lastReload = time.Now()
				reloadMu.Unlock()

				log.Printf("配置文件发生更改（文件系统事件）：%s", ev.String())

				// 关键修复：增加延迟，等待文件写入完成
				time.Sleep(100 * time.Millisecond)

				// 尝试平滑重载配置；若解析失败，则保留现有配置并记录错误
				if err := reloadConfig(); err != nil {
					log.Printf("平滑重载配置失败：%v；将保持现有配置", err)
					// 如果解析失败且问题严重，可以考虑 full restart（safeRestart），但此处保守处理
				} else {
					// 发送信号触发主循环重启 listener（不会完全退出进程）
					select {
					case reloadChan <- struct{}{}:
						log.Printf("已发送重载信号")
					default:
						log.Printf("重载通道已满，跳过本次重载")
					}
				}
			}
		case err := <-watcher.Errors:
			log.Printf("fsnotify 错误: %v", err)
		}
	}
}

// reloadConfig 解析配置并应用（用于热加载）
func reloadConfig() error {
	// 关键修复：先备份当前有效配置
	cfg.RLock()
	oldPort := cfg.Port
	oldRoutes := cfg.Routes
	cfg.RUnlock()

	if err := parseIniAndApply(iniFile); err != nil {
		// 如果新配置解析失败，恢复旧配置
		cfg.Lock()
		cfg.Port = oldPort
		cfg.Routes = oldRoutes
		cfg.Updated = time.Now()
		cfg.Valid = len(oldRoutes) > 0
		cfg.Unlock()
		return fmt.Errorf("配置重载失败，已恢复旧配置: %v", err)
	}
	log.Printf("配置已重新加载并应用 (time: %s)", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

// safeRestart 程序自重启（保留以备不可恢复情况）
func safeRestart() {
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("获取可执行文件路径失败: %v", err)
		return
	}

	log.Println("检测到配置文件变更，正在重启服务（新进程）...")

	cmd := exec.Command(execPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("启动新进程失败: %v", err)
		return
	}

	log.Println("新进程已启动，退出当前进程...")
	os.Exit(0)
}

// -----------------------------
// HTTP 处理（含恢复、限流、安全措施）
// -----------------------------

// safeHandler 包装 handler，捕获 panic 并记录
func safeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 限制单次请求体大小（防止恶意大 body，限制为 10MB）
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

		defer func() {
			if rec := recover(); rec != nil {
				// 记录 panic 信息与堆栈（简短）
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				log.Printf("panic recovered: %v\nstack: %s", rec, string(buf[:n]))
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": 500,
					"msg":    "服务器内部错误",
				})
			}
		}()

		h.ServeHTTP(w, r)
	})
}

// handler 是核心路由匹配与转发逻辑
func handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr
	path := r.URL.Path
	method := r.Method

	stats.Mutex.Lock()
	stats.TotalRequests++
	stats.UniqueClients[clientIP] = struct{}{}
	stats.QPS++
	stats.Mutex.Unlock()

	cfg.RLock()
	// 关键修复：检查配置是否有效
	if !cfg.Valid || len(cfg.Routes) == 0 {
		cfg.RUnlock()
		log.Printf("警告: 配置无效或路由列表为空，拒绝请求 %s %s", method, path)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": 503,
			"msg":    "服务配置无效，请检查代理配置",
		})
		return
	}
	routes := make([]*Route, len(cfg.Routes))
	copy(routes, cfg.Routes) // 复制一份快照供遍历，避免锁持有过久
	cfg.RUnlock()

	matched := false
	for _, route := range routes {
		// 先判断 regex 路由
		if route.Regex && route.Re != nil {
			// 使用编译后的正则进行匹配（MatchString 比 FindStringSubmatch 更快）
			if route.Re.MatchString(path) {
				matches := route.Re.FindStringSubmatch(path)

				// 计算实际的目标地址用于日志显示
				var actualTarget string
				if len(matches) > 0 {
					// 替换主机名中的 $1/$2
					targetHost := replaceDollarRefs(route.Target.Host, matches)
					// 替换路径模板中的 $1/$2
					replacedPath := replaceDollarRefs(route.TargetPathT, matches)

					// 构建完整的目标URL
					actualTarget = fmt.Sprintf("%s://%s%s", route.Target.Scheme, targetHost, replacedPath)
				} else {
					actualTarget = route.Target.String()
				}

				matched = true
				// 在转发前把必要的限制与超时放入上下文，防止后端挂死
				ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
				defer cancel()
				r2 := r.WithContext(ctx)

				lw := &loggingResponseWriter{ResponseWriter: w}
				route.Proxy.ServeHTTP(lw, r2)
				stats.Mutex.Lock()
				stats.PerRouteCounts[route.Prefix]++
				stats.Mutex.Unlock()
				duration := time.Since(start)
				// 使用实际的目标地址而不是模板
				log.Printf("%-4s %-5s -> %-30s | %3d | %7.2fms | %6dB | %s", method, path, actualTarget, lw.status, float64(duration.Microseconds())/1000.0, lw.written, clientIP)
				return
			}
		} else {
			// 非正则按前缀匹配：完全等于或以 prefix/ 开始
			if path == route.Prefix || strings.HasPrefix(path, route.Prefix+"/") {
				matched = true
				ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
				defer cancel()
				r2 := r.WithContext(ctx)

				lw := &loggingResponseWriter{ResponseWriter: w}
				route.Proxy.ServeHTTP(lw, r2)
				stats.Mutex.Lock()
				stats.PerRouteCounts[route.Prefix]++
				stats.Mutex.Unlock()
				duration := time.Since(start)
				log.Printf("%-4s %-5s -> %-30s | %3d | %7.2fms | %6dB | %s", method, path, route.Target.String(), lw.status, float64(duration.Microseconds())/1000.0, lw.written, clientIP)
				return
			}
		}
	}

	// 未匹配到任何路由
	if matched {
		// 这个分支理论上不会到达，因为匹配成功就会return
		log.Printf("错误: 路由匹配逻辑异常，路径 %s 应该已被处理", path)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": 404,
		"msg":    "没有这个前缀的代理路由，请检查配置文件",
	})
}

// -----------------------------
// 状态监控接口
// -----------------------------
func statusHandler(w http.ResponseWriter, r *http.Request) {
	stats.Mutex.Lock()
	defer stats.Mutex.Unlock()

	cfg.RLock()
	configInfo := map[string]interface{}{
		"port":        cfg.Port,
		"routesCount": len(cfg.Routes),
		"updated":     cfg.Updated.Format("2006-01-02 15:04:05"),
		"valid":       cfg.Valid,
	}
	cfg.RUnlock()

	data := map[string]interface{}{
		"startTime":      stats.StartTime.Format("2006-01-02 15:04:05"),
		"uptime":         int(time.Since(stats.StartTime).Seconds()),
		"totalRequests":  stats.TotalRequests,
		"perRouteCounts": stats.PerRouteCounts,
		"uniqueClients":  len(stats.UniqueClients),
		"qps":            stats.QPS,
		"config":         configInfo,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)

	if time.Since(stats.lastQPSReset) > time.Second {
		stats.QPS = 0
		stats.lastQPSReset = time.Now()
	}
}

// -----------------------------
// Banner
// -----------------------------
func printStartupBanner() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	cfg.RLock()
	port := cfg.Port
	routes := cfg.Routes
	updated := cfg.Updated
	valid := cfg.Valid
	cfg.RUnlock()

	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println("            Go · 多目标反向代理服务", version)
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Printf("监听端口: %d\n", port)
	fmt.Printf("配置文件: %s (最后更新时间: %s)\n", iniFile, updated.Format("2006-01-02 15:04:05"))
	fmt.Printf("配置状态: %v\n", valid)
	fmt.Printf("内存占用: %d MB\n", mem.Alloc/1024/1024)
	fmt.Printf("Go 版本: %-10s  CPU: %d 核  Goroutines: %d\n", runtime.Version(), runtime.NumCPU(), runtime.NumGoroutine())
	fmt.Printf("启动时间: %s\n", stats.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("状态监控: http://127.0.0.1:%d/status\n", port)
	fmt.Println("────────────────────────────────────────────────────────")
	if valid && len(routes) > 0 {
		fmt.Println("路由列表:")
		for i := len(routes) - 1; i >= 0; i-- {
			r := routes[i]
			typ := "prefix"
			if r.Regex {
				typ = "regex"
			}
			fmt.Printf("  %-25s -> %-30s  (%s)\n", r.Prefix, r.Target.String(), typ)
		}
	} else {
		fmt.Println("警告: 当前没有有效的路由配置")
	}
	fmt.Println("════════════════════════════════════════════════════════")
}

// startServer 启动 http.Server，返回 server 对象
func startServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", statusHandler)
	// 将主 handler 包装入 safeHandler（包含 panic 捕获与 body 限制）
	mux.Handle("/", http.HandlerFunc(handler))

	cfg.RLock()
	port := cfg.Port
	cfg.RUnlock()

	// 设置更严格的服务器超时以提高稳定性
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      safeHandler(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		// MaxHeaderBytes: 1 << 20,
	}

	go func() {
		log.Printf("开始监听端口 %d ...", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	return server
}

// -----------------------------
// main
// -----------------------------
func main() {
	// 先加载或创建配置
	if err := loadOrCreateIni(); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	// 【新增】设置控制台窗口标题（仅Windows生效）
	if runtime.GOOS == "windows" {
		// 加载kernel32.dll
		kernel32, err := syscall.LoadDLL("kernel32.dll")
		if err != nil {
			log.Printf("加载系统库失败: %v", err)
		} else {
			// 查找SetConsoleTitleW函数（宽字符版本）
			setTitleProc, err := kernel32.FindProc("SetConsoleTitleW")
			if err != nil {
				log.Printf("获取系统函数失败: %v", err)
			} else {
				// 自定义窗口标题
				customTitle := fmt.Sprintf("Go · MockServe %s | %d", version, cfg.Port)
				// 调用系统函数设置标题（需要将Go字符串转为UTF-16指针）
				_, _, err := setTitleProc.Call(
					uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(customTitle))),
				)
				if err != nil && err != syscall.Errno(0) {
					log.Printf("设置窗口标题失败: %v", err)
				}
			}
		}
	}

	// 监控配置文件变更，尝试平滑重载
	go watchIniFile(iniFile)

	printStartupBanner()
	log.Printf("服务已启动，监听端口 %d\n", cfg.Port)

	currentServer := startServer()

	// 信号处理：支持优雅关闭与 SIGHUP 平滑重载
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-stop:
			if sig == syscall.SIGHUP {
				// 收到 SIGHUP，尝试平滑重载配置（不退出进程）
				log.Printf("收到 SIGHUP，尝试热加载配置...")
				if err := reloadConfig(); err != nil {
					log.Printf("热加载失败：%v，保留现有配置", err)
				} else {
					// 关闭旧 server，启动新 server（平滑切换 listener）
					log.Printf("配置热加载成功，正在重启监听服务...")
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := currentServer.Shutdown(ctx); err != nil {
						log.Printf("关闭旧服务时出错: %v（将继续尝试启动新服务）", err)
					}
					cancel()
					printStartupBanner()
					currentServer = startServer()
				}
				continue
			}
			// 其他终止信号：优雅退出
			log.Printf("接收到退出信号 %v，正在关闭服务器...", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := currentServer.Shutdown(ctx); err != nil {
				log.Fatalf("Server Shutdown Failed:%+v", err)
			}
			cancel()
			log.Printf("服务器已关闭")
			return
		case <-reloadChan:
			// 当文件监控触发平滑重载时走这里
			log.Printf("配置变更生效：准备重启服务以应用新配置...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := currentServer.Shutdown(ctx); err != nil {
				log.Printf("关闭旧服务时出错: %v（将继续尝试启动新服务）", err)
			}
			cancel()
			printStartupBanner()
			currentServer = startServer()
		}
	}
}
