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

	"github.com/fsnotify/fsnotify"
)

const iniFile = "proxy.ini"

// 全局版本
var version = "v1.0.0"

// Route 表示一条代理规则
type Route struct {
	Prefix  string
	Target  *url.URL
	Proxy   *httputil.ReverseProxy
	Regex   bool
	Generic bool
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
func validateTarget(raw string) (*url.URL, error) {
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

# 路由配置
/api       http://127.0.0.1:3000
/MFP62     http://192.168.0.100
^/v[0-9]/.*$ http://127.0.0.1:3001 regex
/printer   http://192.168.0.101 generic
`
	return os.WriteFile(iniFile, []byte(content), 0644)
}

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

		targetCopy := *targetURL
		proxy := httputil.NewSingleHostReverseProxy(&targetCopy)
		proxy.Director = makeDirector(prefix, &targetCopy)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error -> %s | %v", r.URL.String(), err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": 502,
				"msg":    "后端服务不可用",
				"detail": err.Error(),
			})
		}

		if len(prefix) > 1 {
			prefix = strings.TrimRight(prefix, "/")
		}
		parsedRoutes = append(parsedRoutes, &Route{
			Prefix:  prefix,
			Target:  targetURL,
			Proxy:   proxy,
			Regex:   isRegex,
			Generic: isGeneric,
		})
	}

	if port == 0 {
		port = 4288
	}

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

	log.Println("新进程已启动，退出当前进程...")
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
		if route.Regex {
			// 正则匹配
			matched := strings.HasPrefix(path, route.Prefix) // 简单版，可改为 regexp.MatchString
			if matched {
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
	json.NewEncoder(w).Encode(map[string]interface{}{
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
	json.NewEncoder(w).Encode(data)

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
		fmt.Printf("  %-15s -> %s\n", r.Prefix, r.Target.String())
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
