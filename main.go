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

// 全局变量
var (
	version = "v1.0.2"
)

// Route 表示一条前缀->目标的代理规则
type Route struct {
	Prefix string
	Target *url.URL
	Proxy  *httputil.ReverseProxy
}

// ConfigRuntime 保存运行时代理配置（并发安全）
type ConfigRuntime struct {
	sync.RWMutex
	Port    int
	Routes  []*Route
	Updated time.Time
}

var cfg = &ConfigRuntime{}

// Stats 保存运行时指标
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

// reloadChan 用于通知主循环重启服务（配置已生效且需要重启）
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
func validateTarget(raw string) (*url.URL, error) {
	// 如果未带 scheme，默认 http://
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
	// host 校验：允许 localhost、IP 或包含点的域名
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
	content := `# 第一处出现的端口号（纯数字）将被视为监听端口（可在任意位置）
# 每个路由行格式：/prefix http://host:port/optionalPath
# 空行和 # 注释会被忽略

4288

/api http://127.0.0.1:3000
/MFP62 http://192.168.0.100
`
	return os.WriteFile(iniFile, []byte(content), 0644)
}

// parseIniAndApply 解析配置文件并应用到 cfg（覆盖式）
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
		if line == "" || strings.HasPrefix(line, "#") || line == "/" {
			continue
		}

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
			return fmt.Errorf("第 %d 行格式错误（应为: /prefix target）: %s", lineNo, line)
		}
		prefix := parts[0]
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("第 %d 行前缀必须以 / 开头: %s", lineNo, prefix)
		}
		targetRaw := parts[1]
		targetURL, verr := validateTarget(targetRaw)
		if verr != nil {
			return fmt.Errorf("第 %d 行目标地址无效: %v", lineNo, verr)
		}

		for _, r := range parsedRoutes {
			if r.Prefix == prefix {
				return fmt.Errorf("第 %d 行重复定义路由前缀: %s", lineNo, prefix)
			}
		}

		// 复制 target，创建代理并设置 Director / ErrorHandler
		targetCopy := *targetURL
		proxy := httputil.NewSingleHostReverseProxy(&targetCopy)
		proxy.Director = makeDirector(prefix, &targetCopy)
		proxy.ErrorHandler = defaultProxyErrorHandler

		if len(prefix) > 1 {
			prefix = strings.TrimRight(prefix, "/")
		}
		parsedRoutes = append(parsedRoutes, &Route{Prefix: prefix, Target: targetURL, Proxy: proxy})
	}

	if port == 0 {
		port = 4288
	}

	// 按前缀长度从长到短排序，避免短前缀抢先匹配
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

// defaultProxyErrorHandler 统一的代理错误处理
func defaultProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("proxy error -> %s | %v", r.URL.String(), err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": 502,
		"msg":    "后端服务不可用",
		"detail": err.Error(),
	})
}

// Director 函数生成
func makeDirector(prefix string, target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		origPath := req.URL.Path
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

// joinURLPath 合并路径，保证斜杠正确
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
// 热加载监控（检测到文件变化后直接自重启）
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
			// 仅对目标文件的写/创建/重命名事件响应
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
				// 直接自重启整个进程，保证行为一致（不会尝试热替换）
				safeRestart()
			}

		case err := <-watcher.Errors:
			log.Printf("fsnotify 错误: %v", err)
		}
	}
}

// safeRestart 程序自重启：启动新进程并退出当前进程
func safeRestart() {
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("获取可执行文件路径失败: %v", err)
		return
	}

	log.Println("检测到配置文件变更，正在重启服务...")

	// 使用原可执行文件路径重启（不带额外参数）
	cmd := exec.Command(execPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Printf("启动新进程失败: %v", err)
		return
	}

	log.Println("新进程已启动，退出当前进程...")
	// 退出当前进程，由系统或外部进程管理器负责保持服务（如果需要）
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

	// 每秒重置 qps
	if time.Since(stats.lastQPSReset) > time.Second {
		stats.QPS = 0
		stats.lastQPSReset = time.Now()
	}
}

// -----------------------------
// Banner（启动信息）
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
		fmt.Printf("  %-10s -> %s\n", r.Prefix, r.Target.String())
	}
	fmt.Println("════════════════════════════════════════════════════════")
}

// startServer 启动 http.Server 并在后台运行，返回 server 指针
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
// 命令行实时路由管理（模式 A）
// 支持：list / add / del / update
// 注意：仅在运行期生效，不会写回 proxy.ini
// -----------------------------
func startCommandInput() {
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			line, err := reader.ReadString('\n')
			if err != nil {
				// 读取 stdin 出错（可能是管道关闭），短暂休眠后继续尝试
				log.Printf("读取命令输入失败: %v", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Fields(line)
			cmd := strings.ToLower(parts[0])

			switch cmd {
			case "list":
				// 列出全部路由（按前缀长度排序，长前缀先显示）
				cfg.RLock()
				fmt.Println("当前路由列表：")
				for _, r := range cfg.Routes {
					fmt.Printf("  %s -> %s\n", r.Prefix, r.Target.String())
				}
				cfg.RUnlock()

			case "add":
				// add /path http://target/
				if len(parts) != 3 {
					fmt.Println("用法: add /path http://target/")
					continue
				}
				prefix := parts[1]
				targetRaw := parts[2]
				if !strings.HasPrefix(prefix, "/") {
					fmt.Println("前缀必须以 '/' 开头")
					continue
				}
				if len(prefix) > 1 {
					prefix = strings.TrimRight(prefix, "/")
				}

				// 校验 target
				targetURL, err := validateTarget(targetRaw)
				if err != nil {
					fmt.Printf("目标地址无效: %v\n", err)
					continue
				}

				// 创建代理
				targetCopy := *targetURL
				proxy := httputil.NewSingleHostReverseProxy(&targetCopy)
				proxy.Director = makeDirector(prefix, &targetCopy)
				proxy.ErrorHandler = defaultProxyErrorHandler

				// 写入 cfg（并发安全）
				cfg.Lock()
				exists := false
				for _, r := range cfg.Routes {
					if r.Prefix == prefix {
						exists = true
						break
					}
				}
				if exists {
					cfg.Unlock()
					fmt.Println("路由已存在，请使用 update 命令或先删除后重试")
					continue
				}
				cfg.Routes = append(cfg.Routes, &Route{Prefix: prefix, Target: targetURL, Proxy: proxy})
				// 重新排序
				sort.Slice(cfg.Routes, func(i, j int) bool {
					return len(cfg.Routes[i].Prefix) > len(cfg.Routes[j].Prefix)
				})
				cfg.Unlock()

				fmt.Printf("已新增路由: %s -> %s\n", prefix, targetURL.String())

			case "del":
				// del /path
				if len(parts) != 2 {
					fmt.Println("用法: del /path")
					continue
				}
				prefix := parts[1]
				if !strings.HasPrefix(prefix, "/") {
					fmt.Println("前缀必须以 '/' 开头")
					continue
				}
				if len(prefix) > 1 {
					prefix = strings.TrimRight(prefix, "/")
				}

				cfg.Lock()
				found := false
				newRoutes := make([]*Route, 0, len(cfg.Routes))
				for _, r := range cfg.Routes {
					if r.Prefix == prefix {
						found = true
						continue
					}
					newRoutes = append(newRoutes, r)
				}
				if found {
					cfg.Routes = newRoutes
					cfg.Unlock()
					fmt.Printf("已删除路由: %s\n", prefix)
				} else {
					cfg.Unlock()
					fmt.Println("路由不存在:", prefix)
				}

			case "update":
				// update /path http://new-target/
				if len(parts) != 3 {
					fmt.Println("用法: update /path http://new-target/")
					continue
				}
				prefix := parts[1]
				targetRaw := parts[2]
				if !strings.HasPrefix(prefix, "/") {
					fmt.Println("前缀必须以 '/' 开头")
					continue
				}
				if len(prefix) > 1 {
					prefix = strings.TrimRight(prefix, "/")
				}

				targetURL, err := validateTarget(targetRaw)
				if err != nil {
					fmt.Printf("目标地址无效: %v\n", err)
					continue
				}

				// 创建代理
				targetCopy := *targetURL
				proxy := httputil.NewSingleHostReverseProxy(&targetCopy)
				proxy.Director = makeDirector(prefix, &targetCopy)
				proxy.ErrorHandler = defaultProxyErrorHandler

				cfg.Lock()
				updated := false
				for i, r := range cfg.Routes {
					if r.Prefix == prefix {
						cfg.Routes[i] = &Route{Prefix: prefix, Target: targetURL, Proxy: proxy}
						updated = true
						break
					}
				}
				// 若不存在则提示
				if !updated {
					cfg.Unlock()
					fmt.Println("路由不存在:", prefix)
					continue
				}
				// 重新排序以防前缀长度变化影响匹配顺序
				sort.Slice(cfg.Routes, func(i, j int) bool {
					return len(cfg.Routes[i].Prefix) > len(cfg.Routes[j].Prefix)
				})
				cfg.Unlock()

				fmt.Printf("已修改路由: %s -> %s\n", prefix, targetURL.String())

			default:
				fmt.Println("命令无效，可用命令: list / add / del / update")
			}
		}
	}()
}

// -----------------------------
// main
// -----------------------------
func main() {
	// 初始化配置（文件不存在则创建；存在则解析）
	if err := loadOrCreateIni(); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	// 启动配置文件监控（当检测到变更时会自重启）
	go watchIniFile(iniFile)

	// 启动命令行交互（模式 A）
	startCommandInput()

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
				customTitle := fmt.Sprintf("Go · RevProxy %s | %d", version, cfg.Port)
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

	// 打印启动信息与路由
	printStartupBanner()
	log.Printf("服务已启动，监听端口 %d\n", cfg.Port)

	// 启动第一个 server
	currentServer := startServer()

	// 优雅退出与重启控制（用于接收系统信号）
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-stop:
			// 收到退出信号，关闭当前服务器并退出程序
			log.Printf("接收到退出信号，正在关闭服务器...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := currentServer.Shutdown(ctx); err != nil {
				log.Fatalf("Server Shutdown Failed:%+v", err)
			}
			cancel()
			log.Printf("服务器已关闭")
			return

		case <-reloadChan:
			// 若你仍使用 reloadChan 的场景保留该逻辑（当前 watchIniFile 直接调用 safeRestart）
			log.Printf("配置变更生效：准备重启服务以应用新配置...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := currentServer.Shutdown(ctx); err != nil {
				log.Printf("关闭旧服务时出错: %v（将继续尝试启动新服务）", err)
			}
			cancel()

			// 打印新配置 Banner
			printStartupBanner()

			// 启动新 server（注意：如果新端口被占用，ListenAndServe 会触发 fatal 并退出）
			currentServer = startServer()
		}
	}
}
