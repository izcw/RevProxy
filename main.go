package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"syscall"  // 新增：用于调用Windows系统API（设置窗口标题）
	"runtime"  // 新增：用于判断操作系统（仅Windows生效）
	"unsafe"   // 新增：用于处理指针转换（适配系统API参数）
)

const iniFile = "proxy.ini"

type config struct {
	Backend string
	Port    int
}

// 加载配置文件，不存在或格式错误则交互式创建
func loadOrCreateConfig() config {
	if _, err := os.Stat(iniFile); os.IsNotExist(err) {
		log.Println("配置文件不存在，开始创建新配置")
		return interactiveNewConfig()
	}

	file, err := os.Open(iniFile)
	if err != nil {
		log.Printf("打开配置文件失败: %v，开始创建新配置", err)
		return interactiveNewConfig()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		log.Printf("配置文件内容为空或读取失败: %v，开始创建新配置", scanner.Err())
		return interactiveNewConfig()
	}

	// 解析配置内容
	parts := strings.Fields(scanner.Text())
	if len(parts) != 2 {
		log.Println("配置文件格式错误，正确格式: [后端地址] [端口]，开始重新创建")
		return interactiveNewConfig()
	}

	backend := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		log.Println("配置文件中端口无效（必须是1-65535的整数），开始重新创建")
		return interactiveNewConfig()
	}

	if _, err := url.Parse(backend); err != nil {
		log.Printf("配置文件中后端地址格式无效: %v，开始重新创建", err)
		return interactiveNewConfig()
	}

	return config{Backend: backend, Port: port}
}

// 交互式录入配置，带格式验证
func interactiveNewConfig() config {
	reader := bufio.NewReader(os.Stdin)
	var backend string
	var port int


	// 后端地址输入及验证
	for {
		fmt.Print(">请输入后端服务地址 (例如: 192.168.x.x): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("输入错误: %v，请重试", err)
			continue
		}
		backend = strings.TrimSpace(input)

		if backend == "" {
			fmt.Println("后端地址不能为空，请重新输入")
			continue
		}

		// 自动添加http://前缀
		if !strings.HasPrefix(backend, "http://") && !strings.HasPrefix(backend, "https://") {
			backend = "http://" + backend
			fmt.Printf("已自动添加 http:// 前缀，当前地址: %s\n", backend)
		}

		if _, err := url.Parse(backend); err != nil {
			fmt.Printf("地址格式不正确: %v，请重新输入\n", err)
			continue
		}
		break
	}

	// 端口输入及验证
	for {
		fmt.Print(">请输入本地监听端口 (1-65535): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("输入错误: %v，请重试", err)
			continue
		}
		portStr := strings.TrimSpace(input)

		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			fmt.Println("端口必须是1-65535之间的整数，请重新输入")
			continue
		}
		break
	}

	config := config{Backend: backend, Port: port}
	if err := saveConfig(config); err != nil {
		log.Fatalf("保存配置失败: %v", err)
	}
	fmt.Println("配置已成功保存到", iniFile)
	return config
}

// 保存配置到文件
func saveConfig(c config) error {
	file, err := os.Create(iniFile)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%s %d\n", c.Backend, c.Port)
	return err
}

// 日志中间件：记录请求信息和响应时间
func logMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &logResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(lw, r)
		log.Printf("[%.3fms] %s %s -> %d",
			time.Since(start).Seconds()*1000,
			r.Method, r.URL.Path, lw.status)
	}
}

// 用于捕获HTTP响应状态码的包装器
type logResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *logResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

func main() {

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
				customTitle := "Golang · 反向代理服务"
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
	
	// 加载或创建配置
	c := loadOrCreateConfig()

	// 解析后端地址
	target, err := url.Parse(c.Backend)
	if err != nil {
		log.Fatalf("后端地址解析失败: %v", err)
	}

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.Host = "127.0.0.1"
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("代理错误: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// 组合日志中间件和代理处理器
	handler := logMiddleware(proxy.ServeHTTP)

	// 打印启动信息
	banner := `
═══════════════════════════════════════════
            Golang · 反向代理服务            
───────────────────────────────────────────
代理地址: http://127.0.0.1:%d           
目标服务: %s           
配置文件: ./%s		           
═══════════════════════════════════════════
服务启动成功！

`
	fmt.Printf(banner, c.Port, c.Backend, iniFile)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.Port), handler))
}