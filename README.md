# cf-ech

DNS 代理服务器，为 DNS 查询注入 Cloudflare ECH (Encrypted Client Hello) 配置。

## 功能特性

- 本地 DNS 代理：监听 UDP+TCP 5353 端口
- 多协议上游：支持 DoH (`https://`) 与 DoQ (`quic://`) 转发查询到上游服务器
- ECH 注入：自动获取并缓存 Cloudflare ECH 配置，注入到 DNS 响应中
- 主备切换：支持主备两个上游服务器，自动故障转移
- 定时刷新：定期更新 ECH 配置缓存
- 附带测速工具：`cmd/dnsspeed` 读取 `dns_over_https.csv` 对公共 DoH/DoQ 服务器测速并排名（见下文）

## 工作原理

1. 接收客户端 DNS 查询请求
2. 按上游 URL 的协议（DoH 或 DoQ）转发到上游 DNS 服务器
3. 定期从上游获取 `cloudflare-ech.com` 的 HTTPS 记录（与查询共用同一上游）
4. 提取 ECH 配置并缓存
5. 在返回给客户端的 DNS 响应中注入 ECH 配置
6. 客户端可使用该 ECH 配置连接 Cloudflare 站点，防止 SNI 审查

## 编译

### 环境要求

- Go 1.26 或更高版本（quic-go v0.62 要求）

### 主要依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| [github.com/miekg/dns](https://github.com/miekg/dns) | v1.1.73 | DNS 报文解析、UDP/TCP 服务端 |
| [github.com/quic-go/quic-go](https://github.com/quic-go/quic-go) | v0.62.0 | DoQ（DNS over QUIC）上游 |

### 本地编译

```bash
go build -o cf-ech .
```

### OpenWrt 交叉编译

需要先安装 OpenWrt 交叉编译工具链，然后：

```bash
# 设置交叉编译环境
export GOARCH=mips  # 或其他目标架构
export GOOS=linux
export CGO_ENABLED=0

# 编译
go build -o cf-ech .
```

## 使用方法

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `:5353` | DNS 监听地址 |
| `-upstream` | `https://doh.dns4all.eu/dns-query` | 主上游 URL（`https://` 为 DoH，`quic://` 为 DoQ） |
| `-fallback` | `https://doh.dns4all.eu/dns-query` | 备用上游 URL（同上，留空表示不启用） |
| `-timeout` | `5s` | 单次上游查询超时 |
| `-refresh` | `5m` | ECH 配置刷新间隔 |
| `-verbose` | `false` | 启用详细日志 |

### 运行示例

```bash
# 使用默认配置
./cf-ech

# 指定监听地址和上游服务器
./cf-ech -listen :53 -upstream https://dns.google/dns-query -fallback https://cloudflare-dns.com/dns-query

# 使用 DoQ 上游（默认端口 853）
./cf-ech -upstream quic://doh.dns4all.eu/dns-query -fallback https://doh.dns4all.eu/dns-query

# 用 IP 连接 DoQ 上游，并指定证书域名
./cf-ech -upstream "quic://1.1.1.1:853?sni=cloudflare-dns.com"

# 启用详细日志
./cf-ech -verbose

# 设置刷新间隔为 10 分钟
./cf-ech -refresh 10m
```

## 配置说明

### 上游服务器

推荐使用以下公共 DoH 服务器：

- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Google: `https://dns.google/dns-query`
- dns4all: `https://doh.dns4all.eu/dns-query`

### DoQ 上游

以 `quic://` 开头的上游使用 DNS over QUIC（RFC 9250），例如：

- dns4all: `quic://doh.dns4all.eu/dns-query`（未指定端口时使用 853）
- AdGuard DNS: `quic://dns.adguard-dns.com`
- 指定端口和证书域名: `quic://1.1.1.1:853?sni=cloudflare-dns.com`

DoQ 上游的行为：

- 默认端口 853，ALPN 固定为 `doq`，仅使用 TLS 1.3
- URL 中的路径会被忽略，因此 `quic://host/dns-query` 与 `quic://host` 等价
- 所有查询复用同一条 QUIC 连接（空闲时发送 keep-alive 保活），每个查询使用一条独立的双向流，符合 RFC 9250 的要求
- 连接被上游关闭或超时后自动重连；单次查询失败会在新连接上重试一次
- 上游以 IP 形式配置时，可用 `?sni=` 指定证书校验所用的域名

### ECH 配置

程序会自动从上游获取 `cloudflare-ech.com` 的 HTTPS 记录，提取其中的 ECH 配置。ECH 配置会定期刷新（默认每 5 分钟），确保使用最新的加密配置。

## 测试

```bash
go test ./...
```

`doq_test.go` 内置了一个最小化的 DoQ 服务端，不需要外网即可验证消息分帧、消息 ID、连接重连与失败重试逻辑。

```bash
# 只运行测速工具的测试（同样内置本地 DoH/DoQ 服务端，无需外网）
go test ./cmd/dnsspeed
```

## 测速工具：dnsspeed

`cmd/dnsspeed` 是本项目附带的加密 DNS 测速工具：读取仓库中的 `dns_over_https.csv`（264 条公共 DNS 记录），逐个测速并按延迟排名，支持 DoH 与 DoQ。

### 编译与运行

```bash
# 编译成独立可执行文件
go build -o dnsspeed ./cmd/dnsspeed

# 在仓库根目录直接运行（默认 CSV 就是 ./dns_over_https.csv）
go run ./cmd/dnsspeed

# 只测 DoH，显示最快的 20 个
go run ./cmd/dnsspeed -protocol doh -top 20

# 只测声明支持 DoQ 的服务器，每端点 10 次查询，输出报告文件
go run ./cmd/dnsspeed -protocol doq -count 10 -report-json speed.json -report-csv speed.csv
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-csv` | `dns_over_https.csv` | 服务器列表 CSV 文件 |
| `-protocol` | `doh,doq` | 测试的协议：`doh`、`doq`、`all`（可逗号分隔） |
| `-count` | `5` | 每个端点的计时查询次数 |
| `-timeout` | `5s` | 单次查询超时 |
| `-domain` | `example.com` | 用于测试的域名 |
| `-qtype` | `A` | 查询类型（A、AAAA、HTTPS 等） |
| `-concurrency` | `8` | 并行测试的端点数 |
| `-limit` | `0` | 只测试前 N 个端点（0 表示全部） |
| `-filter` | 空 | 只测试服务商或地址匹配该正则的端点 |
| `-top` | `0` | 排名表只显示最快的 N 个端点（0 表示全部） |
| `-sort` | `median` | 排名依据：`median`、`avg`、`p95`、`min`、`score`（中位延迟+抖动） |
| `-doq-port` | `853` | 从 DoH 地址推导 DoQ 端点时使用的端口 |
| `-doh-method` | `GET` | DoH 请求方法：`GET` 或 `POST` |
| `-insecure` | `false` | 跳过 TLS 证书校验 |
| `-bar` | `true` | 在排名表中绘制速度条 |
| `-wide` | `false` | 排名表额外显示最小/最大延迟 |
| `-report-json` | 空 | 把完整结果写入 JSON 文件 |
| `-report-csv` | 空 | 把完整结果写入 CSV 文件 |
| `-verbose` | `false` | 进度信息中显示端点完整地址 |

### 测速方法

- 每个端点先发 1 次“握手查询”，其耗时包含 TCP+TLS(DoH) 或 QUIC+TLS(DoQ) 握手，表格中记为 `首查(含握手)`
- 随后在同一连接上做 `-count` 次计时查询（DoQ 复用同一条 QUIC 连接、每次查询一条独立双向流，符合 RFC 9250）
- 统计中位、平均、P95、最小、最大延迟与抖动（标准差）；只有返回 `NOERROR` 且包含应答记录的查询才算成功，超时、HTTP 错误、SERVFAIL 等计入失败率
- 排名默认按中位延迟升序；`-sort score` 使用“中位延迟 + 抖动”，兼顾速度与稳定性
- 打不开的端点单独列在“失败端点”表中，不参与排名

### 输出示例

```text
== 测试配置 ==
  服务器列表: dns_over_https.csv（264 条记录，去重后）
  测试域名:   example.com A
  协议:       DoH+DoQ（10 个端点：DoH 6，DoQ 4）
  每端点:     3 次计时查询 + 1 次握手查询
  超时/并发:  4s / 5

[  2/ 10] DoQ adfreedns.top:853              中位 225.4ms  平均 225.4ms  成功 2/3
[  3/ 10] DoH family.adguard-dns.com         失败: do: context deadline exceeded

== 速度排名（按中位延迟排序，10 个端点，成功 2 个）==

# 协议 服务商     服务器             首查(含握手)    中位    平均     P95    抖动 成功    评分 速度
---------------------------------------------------------------------------------------------------------------
1 DoQ  Adfreedns  adfreedns.top:853       607.5ms 225.4ms 225.4ms 225.8ms   341µs  2/3 225.8ms ████████████████
2 DoH  meddy94.de adguard.meddy94.de        2.15s 386.0ms 386.0ms 536.6ms 150.7ms  2/3 536.6ms █████████
```

### DoQ 端点的来源

CSV 只提供 DoH 地址。对于 `Protocols` 列声明了 `DoQ` 的服务器，工具用相同主机名加 853 端口推导 DoQ 端点（RFC 9250），例如 `https://dns.adguard-dns.com/dns-query` → `quic://dns.adguard-dns.com:853`；地址为 IP 的记录无法推导证书域名，会被跳过。

### 说明

- 测速结果取决于本机网络与出口线路，只反映“当前网络到该服务器”的速度
- 部分服务器位于境外，在国内网络下可能全部超时，属正常现象
- 测速只做只读查询，不会修改任何配置

## 注意事项

1. ECH 配置仅对 Cloudflare 站点有效
2. 客户端需要支持 ECH 才能使用注入的配置
3. 建议将监听端口设置为 53 或其他标准 DNS 端口
4. 在 OpenWrt 环境中，可能需要配置防火墙规则

## 许可证

GNU Affero General Public License v3.0 - 详见 [LICENSE](LICENSE) 文件