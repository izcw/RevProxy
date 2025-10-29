# GO_Reverse_Proxy —— 单文件绿色反向代理

用 Go 标准库实现的轻量级反向代理，**零依赖、单 exe 即可运行**。  
首次启动交互式录入后端地址与本地端口，自动记忆；后续双击即可复用配置。

## 快速开始

初始化模块（仅需一次）

```bash
go mod init proxy
```

直接运行

```bash
go run main.go
```

> 按提示输入后端地址（如 http://192.168.0.102:80）与本地端口（如 4166），程序会自动生成 > proxy.ini 配置文件。

编译成可执行文件（绿色单文件，拷到任何 Windows 机器双击运行）

```bash
go build -ldflags "-s -w" -o Proxy.exe
```

生成图标资源文件（可选）
icon 转换工具：https://d1tools.com/tools/ico-generator/

```bash
rsrc -ico favicon.ico -arch amd64 -o rsrc.syso
```

## 目录结构

```bash
Reverse_Proxy/
├─ main.go      # 源码
├─ proxy.exe    # 编译后产物（可随意改名）
├─ proxy.ini    # 自动生成的配置文件（首次运行后产生）
├─ favicon.ico  # 图标
├─ rsrc.syso    # 生成的图标资源文件（可选）
└─ README.md
```
