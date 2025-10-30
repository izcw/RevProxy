# GO_Reverse_Proxy —— 单文件绿色多服务反向代理

用 Go 标准库实现的轻量级反向代理，零依赖、单 exe 即可运行。
支持多路由规则、配置文件热重载、实时状态监控，无需重启即可更新代理配置。

## 特性亮点

- 🚀 绿色单文件 - 零依赖，编译后单个 exe 直接运行

- ⚡ 热重载配置 - 修改 proxy.ini 自动生效，无需重启服务

- 🔄 多路由支持 - 支持多个前缀映射到不同后端服务

- 📊 实时监控 - 内置状态接口，查看请求统计、QPS、客户端信息

- 🛡️ 错误处理 - 友好的错误提示和 JSON 响应格式

- 🎯 路径重写 - 智能处理 URL 路径前缀匹配和重写

- 🖥️ 控制台美化 - Windows 下自动设置控制台标题，启动信息清晰展示

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
go build -ldflags "-s -w" -o GO_Proxy.exe
```

生成图标资源文件（可选）
icon 转换工具：https://d1tools.com/tools/ico-generator/

```bash
rsrc -ico icon.ico -arch amd64 -o rsrc.syso
```

## 目录结构

```bash
Reverse_Proxy/
├─ main.go          # 主程序源码
├─ GO_Proxy.exe     # 编译后的可执行文件（可随意改名）
├─ proxy.ini        # 配置文件（首次运行自动生成）
├─ icon.ico         # 程序图标
├─ rsrc.syso        # 生成的图标资源文件（可选）
└─ README.md        # 说明文档
```
