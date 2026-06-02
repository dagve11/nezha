# Nezha Dashboard Custom

这是基于 [nezhahq/nezha](https://github.com/nezhahq/nezha) 定制的 Dashboard 后端仓库，用于运行监控面板、管理后台、Agent gRPC 接入、告警、服务监控、定时任务和历史数据存储。

本仓库重点负责 **dashboard 后端与最终二进制编译**。前台用户面板和后台管理前端由独立前端仓库构建后，以静态资源形式放入 `cmd/dashboard/*-dist`，再由 Go 编译进 dashboard 二进制文件。

## 当前定制内容

- 用户面板使用自定义 `user-dist`，站点显示与交互已按当前项目调整。
- 管理后台使用自定义 `admin-dist`，包含设置页、登录页和相关后台交互调整。
- 支持 TSDB 时序数据存储，并可在后台设置页切换是否启用。
- 支持服务器删除时下发 Agent 销毁任务，Agent 在线后可执行自删除。
- 前端静态文件通过 Go `embed` 内嵌进 dashboard，可单文件部署。
- GeoIP 国家地区识别通过 `pkg/geoip/geoip.db` 编译期内嵌。

## 相关仓库

| 项目 | 目录 | 说明 |
| --- | --- | --- |
| Dashboard 后端 | `C:/Users/72366/Desktop/nezha-1/nezha` | 当前仓库，编译最终 dashboard |
| 管理后台前端 | `C:/Users/72366/Desktop/nezha-1/nezha-admin-frontend` | 构建后输出到 `cmd/dashboard/admin-dist` |
| 用户面板前端 | `C:/Users/72366/Desktop/nezha-1/nezha-dash-frontend` | 构建后输出到 `cmd/dashboard/user-dist` |
| Agent | `C:/Users/72366/Desktop/nezha-1/agent` | Agent 安装包、上报、自删除逻辑 |

## 技术栈

- Go 1.26
- Gin / gRPC / SQLite
- React / TypeScript / Vite
- TSDB 自定义时序数据存储
- 单二进制部署，静态前端资源内嵌

## 目录结构

```text
cmd/dashboard/
  main.go              Dashboard 入口
  admin-dist/          管理后台前端构建产物，会被 Go 内嵌
  user-dist/           用户面板前端构建产物，会被 Go 内嵌
model/                 配置、数据库模型、API 数据结构
pkg/geoip/             GeoIP 数据库与查询逻辑
pkg/tsdb/              TSDB 读写与维护逻辑
proto/                 Agent gRPC 协议
service/               核心服务、缓存、任务、告警、TSDB 初始化
data/                  运行时配置和数据库，不应作为发布内容提交
```

## 前端资源内嵌说明

Dashboard 编译时会执行：

```go
//go:embed *-dist
```

因此 `cmd/dashboard/admin-dist` 和 `cmd/dashboard/user-dist` 会直接嵌入最终二进制。

结论：

- 如果只改 Go 后端，重新编译 dashboard 即可。
- 如果改了后台前端，需要先构建 `nezha-admin-frontend`，再更新 `cmd/dashboard/admin-dist`，最后重新编译 dashboard。
- 如果改了用户面板，需要先构建 `nezha-dash-frontend`，再更新 `cmd/dashboard/user-dist`，最后重新编译 dashboard。
- 线上运行时不会再读取本地前端源码目录，只使用已经嵌入二进制的 dist。

注意：`script/fetch-frontends.sh` 会根据 `service/singleton/frontend-templates.yaml` 下载官方前端模板，可能覆盖当前自定义 dist。使用自定义前端时不要随意执行该脚本。

## GeoIP 数据库

`pkg/geoip/geoip.db` 是编译期内嵌文件。源码中的占位文件不能用于正式编译，否则地区/旗帜不会显示，日志中可能出现：

```text
NEZHA>> geoip.Lookup: error opening database: invalid MaxMind DB file
```

正式编译前需要用有效的 IPinfo `country.mmdb` 覆盖：

```powershell
$token='你的 IPINFO_TOKEN'
```

```powershell
Invoke-WebRequest "https://ipinfo.io/data/free/country.mmdb?token=$token" -OutFile "C:/Users/72366/Desktop/nezha-1/nezha/pkg/geoip/geoip.db"
```

检查文件大小：

```powershell
Get-Item "C:/Users/72366/Desktop/nezha-1/nezha/pkg/geoip/geoip.db" | Select-Object FullName,Length
```

如果仍是几字节大小，说明下载失败，不能用于编译。

## 编译

执行目录：

```text
C:/Users/72366/Desktop/nezha-1/nezha
```

Linux amd64：

```powershell
docker run --rm -v "C:/Users/72366/Desktop/nezha-1/nezha:/build" golang:1.26 sh -c "cd /build && apt-get update -qq && apt-get install -y -qq gcc > /dev/null 2>&1 && env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o dashboard-linux-amd64 ./cmd/dashboard"
```

Windows amd64：

```powershell
docker run --rm -v "C:/Users/72366/Desktop/nezha-1/nezha:/build" golang:1.26 sh -c "cd /build && apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 > /dev/null 2>&1 && env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o dashboard.exe ./cmd/dashboard"
```

编译前确认：

- `cmd/dashboard/admin-dist` 是要发布的后台前端版本。
- `cmd/dashboard/user-dist` 是要发布的用户面板版本。
- `pkg/geoip/geoip.db` 已替换为有效 MMDB 文件。
- `data/config.yaml`、`data/sqlite.db` 是运行时文件，不参与编译内嵌。

## 运行

Linux：

```bash
chmod +x ./dashboard-linux-amd64
```

```bash
./dashboard-linux-amd64
```

Windows：

```powershell
.\dashboard.exe
```

默认配置文件：

```text
data/config.yaml
```

默认数据库：

```text
data/sqlite.db
```

也可以指定路径：

```bash
./dashboard-linux-amd64 -c data/config.yaml -db data/sqlite.db
```

首次运行会自动生成必要配置。默认端口是 `8008`。

## 常用配置

```yaml
listen_host: ""
listen_port: 8008
site_name: Monitor
language: zh_CN
agent_secret_key: your-agent-secret

tls: false
install_host: 47.74.5.204:8008

tsdb:
  enabled: true
  data_path: data/tsdb
  retention_days: 90
```

说明：

- `listen_port` 是 dashboard HTTP/gRPC 共用入口端口。
- `agent_secret_key` 是 Agent 接入密钥，安装 Agent 时必须一致。
- `install_host` 会影响后台生成的 Agent 安装命令。
- `tls` 用于生成 Agent 安装命令中的 `NZ_TLS`。
- `tsdb.enabled` 控制是否启用 TSDB。
- `tsdb.data_path` 是 TSDB 数据目录。

## Agent 接入

Windows 安装命令示例：

```powershell
$env:NZ_SERVER="47.74.5.204:8008";$env:NZ_TLS="false";$env:NZ_CLIENT_SECRET="你的 agent_secret_key";[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;set-ExecutionPolicy RemoteSigned;Invoke-WebRequest https://raw.githubusercontent.com/dagve11/agent/main/install.ps1 -OutFile C:\install.ps1;powershell.exe C:\install.ps1
```

Agent 下载地址由 `install.ps1` 指向 `dagve11/agent` 的 GitHub Release：

```text
https://github.com/dagve11/agent/releases/latest/download/agent_windows_amd64.zip
```

如果重复执行安装命令，应优先复用同一台机器的配置，避免后台产生重复服务器记录。Agent 自删除和重装逻辑需要与当前 dashboard 后端版本、agent 版本同时保持一致。

## TSDB

TSDB 用于保存服务器指标和服务监控历史。当前版本支持在后台设置页开启或关闭。

开启后：

- 服务器指标写入 `tsdb.data_path`。
- 服务监控历史优先读取 TSDB。
- 维护任务会执行 TSDB flush 和清理。

关闭后：

- Dashboard 会关闭 TSDB 实例。
- 服务监控会回到非 TSDB 路径。

注意：启用 TSDB 时，旧的 `service_histories` 历史数据不会自动迁移。

## 地区/旗帜不显示排查

前台地区字段来自 WebSocket：

```text
/api/v1/ws/server
```

浏览器 Console 检查：

```js
const ws = new WebSocket('wss://你的域名/api/v1/ws/server');
ws.onmessage = e => {
  const j = JSON.parse(e.data);
  console.table(j.servers?.map(s => ({
    id: s.id,
    name: s.name,
    country_code: s.country_code,
    keys: Object.keys(s).join(',')
  })));
  ws.close();
};
```

如果没有 `country_code` 字段，优先检查：

- `pkg/geoip/geoip.db` 是否是有效 MMDB。
- dashboard 是否在替换 GeoIP 数据库后重新编译。
- Agent 是否已重新连接并触发 GeoIP 上报。

## 本地检查

Go 测试：

```bash
go test ./service/singleton ./cmd/dashboard/controller
```

查看当前修改：

```bash
git status --short
```

查看 README 修改：

```bash
git diff -- README.md
```

## 发布注意事项

发布 dashboard 前至少确认：

- 后台前端 dist 已更新。
- 用户前端 dist 已更新。
- GeoIP 数据库有效。
- dashboard 已重新编译。
- 新二进制已部署并重启。
- Agent 使用的版本与后端任务协议匹配。

## License

本项目基于 [Apache License 2.0](LICENSE)。
