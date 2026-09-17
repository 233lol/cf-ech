# cf-ech

DNS 代理服务器，为 DNS 查询注入 Cloudflare ECH (Encrypted Client Hello) 配置。

## 功能特性

- 本地 DNS 代理：监听 UDP+TCP 5353 端口
- DoH 转发：通过 DNS over HTTPS 转发查询到上游服务器
- ECH 注入：自动获取并缓存 Cloudflare ECH 配置，注入到 DNS 响应中
- 主备切换：支持主备两个上游 DoH 服务器，自动故障转移
- 定时刷新：定期更新 ECH 配置缓存

## 工作原理

1. 接收客户端 DNS 查询请求
2. 通过 DoH 转发到上游 DNS 服务器
3. 定期从上游获取 `cloudflare-ech.com` 的 HTTPS 记录
4. 提取 ECH 配置并缓存
5. 在返回给客户端的 DNS 响应中注入 ECH 配置
6. 客户端可使用该 ECH 配置连接 Cloudflare 站点，防止 SNI 审查

## 编译

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
| `-upstream` | `https://doh.dns4all.eu/dns-query` | 主上游 DoH URL |
| `-fallback` | `https://doh.dns4all.eu/dns-query` | 备用上游 DoH URL |
| `-refresh` | `5m` | ECH 配置刷新间隔 |
| `-verbose` | `false` | 启用详细日志 |

### 运行示例

```bash
# 使用默认配置
./cf-ech

# 指定监听地址和上游服务器
./cf-ech -listen :53 -upstream https://dns.google/dns-query -fallback https://cloudflare-dns.com/dns-query

# 启用详细日志
./cf-ech -verbose

# 设置刷新间隔为 10 分钟
./cf-ech -refresh 10m
```

## 配置说明

### 上游 DoH 服务器

推荐使用以下公共 DoH 服务器：

- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Google: `https://dns.google/dns-query`
- dns4all: `https://doh.dns4all.eu/dns-query`

### ECH 配置

程序会自动从上游获取 `cloudflare-ech.com` 的 HTTPS 记录，提取其中的 ECH 配置。ECH 配置会定期刷新（默认每 5 分钟），确保使用最新的加密配置。

## 注意事项

1. ECH 配置仅对 Cloudflare 站点有效
2. 客户端需要支持 ECH 才能使用注入的配置
3. 建议将监听端口设置为 53 或其他标准 DNS 端口
4. 在 OpenWrt 环境中，可能需要配置防火墙规则

## 许可证

GNU Affero General Public License v3.0 - 详见 [LICENSE](LICENSE) 文件