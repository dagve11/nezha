# Nezha Monitoring - Custom Edition

基于 [哪吒监控](https://github.com/nezhahq/nezha) 的定制版本。

## 功能特性

- 服务器状态监控（CPU、内存、磁盘、网络）
- HTTP/TCP/Ping 服务监控
- SSL 证书监控
- 告警通知
- 定时任务
- Web 终端
- TSDB 时序数据存储

## 定制内容

### 用户面板（nezha-dash）
- 顶栏显示 "Monitor" 替代 "哪吒监控"
- 移除 "管理后台" 入口按钮
- 底部版权显示站点名称
- 快捷键说明优化

### 管理后台（admin-frontend）
- 登录页移除 Logo
- 登录页显示 "请先登录" 提示
- 顶栏布局优化

## 技术栈

- **后端**: Go + Gin + gRPC + SQLite
- **前端**: React + TypeScript + Vite + Tailwind CSS
- **部署**: 单二进制文件，前端静态文件内嵌

## 快速开始

### 编译

**Windows (Docker)**
```bash
docker run --rm -v "C:/Users/72366/Desktop/nezha/nezha-master:/build" golang:1.26 sh -c "cd /build && apt-get update -qq && apt-get install -y -qq gcc > /dev/null 2>&1 && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o dashboard.exe ./cmd/dashboard"
```

**Linux (Docker)**
```bash
docker run --rm -v "C:/Users/72366/Desktop/nezha/nezha-master:/build" golang:1.26 sh -c "cd /build && apt-get update -qq && apt-get install -y -qq gcc > /dev/null 2>&1 && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o dashboard-linux-amd64 ./cmd/dashboard"
```

### 运行

```bash
./dashboard-linux-amd64
```

首次运行会自动生成 `data/config.yaml` 配置文件。

### 配置

编辑 `data/config.yaml`：

```yaml
listen_port: 8008
agent_secret_key: your-secret-key
site_name: My Server

# 启用 TSDB 历史数据
tsdb:
  data_path: "data/tsdb"
  retention_days: 90
```

## 项目结构

```
├── cmd/dashboard/          # Dashboard 主程序
│   ├── admin-dist/         # 管理后台前端（编译后）
│   ├── user-dist/          # 用户面板前端（编译后）
│   └── main.go             # 入口文件
├── model/                  # 数据模型
├── service/singleton/      # 核心服务
├── cmd/dashboard/controller/  # API 控制器
└── data/                   # 运行时数据
```

## 相关仓库

- [nezha-admin-frontend](https://github.com/dagve11/nezha-admin-frontend) - 管理后台前端源码
- [nezha-dash-frontend](https://github.com/dagve11/nezha-dash-frontend) - 用户面板前端源码

## 许可证

基于 [Apache 2.0](LICENSE) 许可证。
