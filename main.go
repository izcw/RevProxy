package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
var version = "v1.0.4"

// Route 表示一条代理规则
type Route struct {
	Prefix      string   // 原始配置中的前缀（对于 regex 为正则表达式文本）
	Target      *url.URL // 解析后的目标 URL（Host + Scheme）
	Proxy       *httputil.ReverseProxy
	Regex       bool           // 是否使用正则匹配
	Generic     bool           // generic 标志（保留原语义）
	Re          *regexp.Regexp // 若 Regex == true，则保存编译后的正则
	TargetPathT string         // 目标路径模板（允许包含 $1/$2 替换）
}

// ConfigRuntime 保存运行时配置
type ConfigRuntime struct {
	sync.RWMutex
	Port    int
	Routes  []*Route
	Updated time.Time
}

var cfg = &ConfigRuntime{}

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

// reloadChan 用于通知主循环重启
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
		return fmt.Errorf("配置文件格式错误，已备份为 %s，请检查并重启: %v", backup, err)
	}
	return nil
}

func createDefaultIni() error {
	content := `# 监听端口
4288

# 路由配置：格式为
# prefix target [type]
# 如果 type 为 regex，则 prefix 被解释为 Go 正则表达式（支持 (?i) 等标志）
# 当 target 的 path 部分包含 $1/$2 等时，会替换为正则捕获组
/api       http://127.0.0.1:3000
/MFP62     http://192.168.0.100
^/v[0-9]/.*$ http://127.0.0.1:3001 regex
/printer   http://192.168.0.101 generic
`
	return os.WriteFile(iniFile, []byte(content), 0644)
}

// parseIniAndApply 解析配置文件并应用到运行时配置
func parseIniAndApply(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var port int
	var parsedRoutes []*Route
	lineNo := 0
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
		// 为此我们先尝试解析 targetRaw（如果 path 含 $xx，这不会妨碍 url.Parse）
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
		if isRegex {
			// 将 prefix 当作正则表达式编译
			re, err := regexp.Compile(prefix)
			if err != nil {
				return fmt.Errorf("第 %d 行正则表达式编译失败: %v", lineNo, err)
			}
			compiled = re
		} else {
			// 对非 regex 的 prefix 做常规清理：保留原样，但统一移除尾部斜杠（除了根 /）
			if len(prefix) > 1 {
				prefix = strings.TrimRight(prefix, "/")
			}
		}

		// 创建 ReverseProxy 并为其设置默认 Director（后面根据 route 类型覆盖）
		proxy := httputil.NewSingleHostReverseProxy(&targetCopy)

		// 这里先设置一个默认 Director（会在下面根据 route 类型覆盖为更适合的版本）
		proxy.Director = makeDirector(prefix, &targetCopy)
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
			Prefix:      prefix,
			Target:      targetURL,
			Proxy:       proxy,
			Regex:       isRegex,
			Generic:     isGeneric,
			Re:          compiled,
			TargetPathT: targetPathTemplate,
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
	}

	if port == 0 {
		port = 4288
	}

	// 按照 Prefix 长度降序排序（以便更长的 prefix 拥有更高匹配优先级）
	sort.Slice(parsedRoutes, func(i, j int) bool {
		return len(parsedRoutes[i].Prefix) > len(parsedRoutes[j].Prefix)
	})

	cfg.Lock()
	cfg.Port = port
	cfg.Routes = parsedRoutes
	cfg.Updated = time.Now()
	cfg.Unlock()

	return nil
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
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = newPath
		req.URL.RawPath = newPath
		req.Host = target.Host

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
func makeDirectorForRegex(re *regexp.Regexp, target *url.URL, targetPathTemplate string) func(*http.Request) {
	// 返回的闭包会在请求到达时根据当前 req.URL.Path 做匹配并替换
	return func(req *http.Request) {
		origPath := req.URL.Path
		// 尝试匹配
		matches := re.FindStringSubmatch(origPath)
		replacedPath := targetPathTemplate
		if len(matches) > 0 {
			// 用捕获组替换目标模板中的 $1/$2...
			replacedPath = replaceDollarRefs(targetPathTemplate, matches)
		}
		// 如果替换后得到的路径不是以 / 开头，则我们尝试以 target.Path 为基础拼接
		var newPath string
		if strings.HasPrefix(replacedPath, "/") {
			// 如果模板直接给出绝对路径，直接使用
			newPath = replacedPath
		} else {
			// 否则以 target.Path 与 replacedPath 拼接
			newPath = joinURLPath(target.Path, replacedPath)
		}

		// 进行最终赋值
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = newPath
		req.URL.RawPath = newPath
		req.Host = target.Host

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
// 热加载监控
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

				log.Printf("配置文件发生更改：%s", ev.String())
				safeRestart()
			}

		case err := <-watcher.Errors:
			log.Printf("fsnotify 错误: %v", err)
		}
	}
}

// safeRestart 程序自重启
func safeRestart() {
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("获取可执行文件路径失败: %v", err)
		return
	}

	log.Println("检测到配置文件变更，正在重启服务...")

	cmd := exec.Command(execPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("启动新进程失败: %v", err)
		return
	}

	log.Println("新进程已启动，退出当前进程...\n\n\n\n\n\n")
	os.Exit(0)
}

// -----------------------------
// HTTP 处理
// -----------------------------
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
	defer cfg.RUnlock()
	for _, route := range cfg.Routes {
		if route.Regex && route.Re != nil {
			// 使用编译后的正则进行匹配
			if route.Re.MatchString(path) {
				lw := &loggingResponseWriter{ResponseWriter: w}
				route.Proxy.ServeHTTP(lw, r)
				stats.Mutex.Lock()
				stats.PerRouteCounts[route.Prefix]++
				stats.Mutex.Unlock()
				duration := time.Since(start)
				log.Printf("%-4s %-5s -> %-20s | %3d | %7.2fms | %6dB | %s", method, path, route.Target.String(), lw.status, float64(duration.Microseconds())/1000.0, lw.written, clientIP)
				return
			}
		} else {
			// 非正则按前缀匹配：完全等于或以 prefix/ 开始
			if path == route.Prefix || strings.HasPrefix(path, route.Prefix+"/") {
				lw := &loggingResponseWriter{ResponseWriter: w}
				route.Proxy.ServeHTTP(lw, r)
				stats.Mutex.Lock()
				stats.PerRouteCounts[route.Prefix]++
				stats.Mutex.Unlock()
				duration := time.Since(start)
				log.Printf("%-4s %-5s -> %-20s | %3d | %7.2fms | %6dB | %s", method, path, route.Target.String(), lw.status, float64(duration.Microseconds())/1000.0, lw.written, clientIP)
				return
			}
		}
	}
	// 未匹配到任何路由
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

	data := map[string]interface{}{
		"startTime":      stats.StartTime.Format("2006-01-02 15:04:05"),
		"uptime":         int(time.Since(stats.StartTime).Seconds()),
		"totalRequests":  stats.TotalRequests,
		"perRouteCounts": stats.PerRouteCounts,
		"uniqueClients":  len(stats.UniqueClients),
		"qps":            stats.QPS,
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
	cfg.RUnlock()

	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println("            Go · 多目标反向代理服务", version)
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Printf("监听端口: %d\n", port)
	fmt.Printf("配置文件: %s (最后更新时间: %s)\n", iniFile, updated.Format("2006-01-02 15:04:05"))
	fmt.Printf("内存占用: %d MB\n", mem.Alloc/1024/1024)
	fmt.Printf("Go 版本: %-10s  CPU: %d 核  Goroutines: %d\n", runtime.Version(), runtime.NumCPU(), runtime.NumGoroutine())
	fmt.Printf("启动时间: %s\n", stats.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("状态监控: http://127.0.0.1:%d/status\n", port)
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Println("路由列表:")
	for i := len(routes) - 1; i >= 0; i-- {
		r := routes[i]
		typ := "prefix"
		if r.Regex {
			typ = "regex"
		}
		fmt.Printf("  %-25s -> %-30s  (%s)\n", r.Prefix, r.Target.String(), typ)
	}
	fmt.Println("════════════════════════════════════════════════════════")
}

// startServer 启动 http.Server
func startServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", statusHandler)
	mux.HandleFunc("/", handler)

	cfg.RLock()
	port := cfg.Port
	cfg.RUnlock()

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
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

	go watchIniFile(iniFile)

	printStartupBanner()
	log.Printf("服务已启动，监听端口 %d\n", cfg.Port)

	currentServer := startServer()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-stop:
			log.Printf("接收到退出信号，正在关闭服务器...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := currentServer.Shutdown(ctx); err != nil {
				log.Fatalf("Server Shutdown Failed:%+v", err)
			}
			cancel()
			log.Printf("服务器已关闭")
			return
		case <-reloadChan:
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
