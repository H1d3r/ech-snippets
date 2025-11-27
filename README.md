# ECH-Tunnel

一个基于 WebSocket 的安全隧道代理工具，支持 TCP 端口转发、SOCKS5 代理和 HTTP 代理，采用 ECH (Encrypted Client Hello) 技术增强隐私保护。

## 功能特性

- **多种代理模式**
  - TCP 端口转发（支持多规则）
  - SOCKS5 代理（支持 TCP CONNECT 和 UDP ASSOCIATE）
  - HTTP/HTTPS 代理（支持 CONNECT 隧道）

- **安全特性**
  - 强制 TLS 1.3 加密传输
  - ECH (Encrypted Client Hello) 支持，隐藏真实 SNI
  - 可选的身份验证令牌
  - 支持用户名密码认证（SOCKS5/HTTP）
  - IP 白名单（CIDR 格式）

- **高性能设计**
  - **预连接多通道池** - 启动时即建立连接，请求到来时零等待
  - WebSocket 多路复用
  - 智能通道竞选，自动选择最优路径
  - 自动重连机制

## 核心优势：预连接多通道架构

### 传统代理 vs 预连接代理

**传统代理模式（按需连接）：**
```
用户请求 ──► 建立TCP连接 ──► TLS握手 ──► WebSocket握手 ──► 发送数据
                │
                └──► 每次请求都需要完整握手流程，延迟高达 200-500ms
```

**本工具的预连接模式：**
```
程序启动时：
    └──► 预先建立 N 个 WebSocket 长连接（含TLS握手）
    
用户请求到来时：
    └──► 直接复用已建立的连接 ──► 发送数据
                │
                └──► 无需握手，延迟仅 1-10ms
```

### 预连接的核心优势

| 特性 | 传统模式 | 预连接模式 |
|------|----------|------------|
| **首包延迟** | 200-500ms（需完整握手） | **1-10ms**（直接复用） |
| **连接稳定性** | 每次新建，不可预测 | **预先验证，稳定可靠** |
| **故障感知** | 请求时才发现问题 | **实时检测，提前预警** |
| **负载分散** | 单点连接 | **多通道并行** |
| **网络抖动影响** | 直接影响用户体验 | **连接池缓冲，影响最小化** |

### 多通道竞选机制

```
┌─────────┐
│  客户端  │
└────┬────┘
     │ 启动时预建立连接
     ├──► 通道 0 (WebSocket) ━━━━━━━► 服务端
     ├──► 通道 1 (WebSocket) ━━━━━━━► 服务端  
     └──► 通道 2 (WebSocket) ━━━━━━━► 服务端

新请求到来时：
┌─────────────────────────────────────────────────────────┐
│ 1. 同时向所有通道发送 CLAIM 竞选请求                      │
│ 2. 记录各通道的响应时间                                   │
│ 3. 选择最先响应的通道（延迟最低）处理该连接                 │
│ 4. 后续数据通过选中的通道传输                             │
└─────────────────────────────────────────────────────────┘

效果：
  • 自动选择当前网络状况最优的路径
  • 单通道故障时自动切换到其他通道
  • 网络波动时选择最稳定的通道
```

### 性能对比示例

假设网络环境：RTT = 50ms，TLS握手 = 2 RTT，WebSocket握手 = 1 RTT

| 场景 | 传统模式延迟 | 预连接模式延迟 | 提升 |
|------|-------------|---------------|------|
| 首次HTTPS请求 | 150ms+ | **~5ms** | **30倍** |
| DNS查询(UDP) | 150ms+ | **~5ms** | **30倍** |
| 连续10个请求 | 1500ms+ | **~50ms** | **30倍** |

### 适用场景

预连接模式特别适合：

- **高频短连接** - 如网页浏览、API调用
- **实时性要求高** - 如游戏、视频通话
- **网络不稳定环境** - 如移动网络、跨境网络
- **需要低延迟** - 如交易系统、实时监控

## 技术原理

### 整体架构

```
┌──────────────────┐                                    ┌──────────────────┐
│      客户端       │                                    │      服务端       │
│                  │                                    │                  │
│  ┌────────────┐  │      WebSocket (TLS 1.3 + ECH)     │  ┌────────────┐  │
│  │ TCP 转发   │  │◄━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━►│  │ TCP 转发   │  │
│  ├────────────┤  │         预连接多通道池               │  ├────────────┤  │
│  │ SOCKS5    │  │          (N个长连接)                │  │ UDP 转发   │  │
│  ├────────────┤  │                                    │  └────────────┘  │
│  │ HTTP 代理  │  │                                    │                  │
│  └────────────┘  │                                    │                  │
└──────────────────┘                                    └──────────────────┘
```

### ECH (Encrypted Client Hello)

ECH 是 TLS 1.3 的扩展协议，用于加密 ClientHello 消息中的敏感字段，特别是 SNI (Server Name Indication)。

**传统 TLS 握手的问题：**
```
客户端 ──► 明文 SNI: "example.com" ──► 服务器
              ↑
         中间人可见
```

**启用 ECH 后：**
```
客户端 ──► 加密的 SNI ──► 服务器
              ↑
         中间人只能看到外层 SNI (如 cloudflare-ech.com)
```

**本工具的 ECH 实现：**

```
1. 启动时通过 DoH 查询 ECH 配置
   ┌─────────┐  DoH 查询 HTTPS RR   ┌─────────┐
   │  客户端  │ ────────────────────► │   DoH   │
   │         │ ◄──────────────────── │  服务器  │
   └─────────┘   ECH 公钥配置        └─────────┘

2. 建立预连接时使用 ECH
   ┌─────────┐  加密的 ClientHello  ┌─────────┐
   │  客户端  │ ━━━━━━━━━━━━━━━━━━━► │  服务端  │
   │         │    (SNI 被隐藏)      │         │
   └─────────┘   预建立N个连接       └─────────┘
```

### WebSocket 多路复用

单个 WebSocket 连接承载多个 TCP/UDP 会话，通过连接 ID 区分：

```
┌─────────────────────────────────────────────────────────┐
│              预建立的 WebSocket 连接 (通道 0)             │
├─────────────────────────────────────────────────────────┤
│  [ConnID-1] TCP 会话 1 ◄──► example.com:80              │
│  [ConnID-2] TCP 会话 2 ◄──► example.org:443             │
│  [ConnID-3] UDP 会话 1 ◄──► 8.8.8.8:53                  │
│  ...                                                    │
└─────────────────────────────────────────────────────────┘
```

**消息格式：**

| 类型 | 格式 | 说明 |
|------|------|------|
| 通道竞选 | `CLAIM:<id>\|<channelID>` | 多通道竞选请求 |
| 竞选确认 | `CLAIM_ACK:<id>\|<channelID>` | 竞选成功响应 |
| TCP 建连 | `TCP:<id>\|<target>\|<data>` | 建立 TCP 连接并发送首帧 |
| 数据传输 | `DATA:<id>\|<payload>` | 双向数据传输 |
| 关闭连接 | `CLOSE:<id>` | 关闭指定会话 |
| UDP 建连 | `UDP_CONNECT:<id>\|<target>` | 建立 UDP 关联 |
| UDP 数据 | `UDP_DATA:<id>\|<data>` | UDP 数据传输 |
| UDP 关闭 | `UDP_CLOSE:<id>` | 关闭 UDP 关联 |

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 监听地址 | 必填 |
| `-f` | WebSocket 服务端地址（客户端模式必填） | - |
| `-ip` | 指定连接的目标 IP 地址 | - |
| `-cert` | TLS 证书文件路径 | 自动生成自签名证书 |
| `-key` | TLS 密钥文件路径 | 自动生成 |
| `-token` | 身份验证令牌（WebSocket Subprotocol） | - |
| `-cidr` | 允许的来源 IP 范围 | `0.0.0.0/0,::/0` |
| `-dns` | ECH 公钥查询 DoH 服务器地址 | `dns.alidns.com/dns-query` |
| `-ech` | ECH 公钥查询域名 | `cloudflare-ech.com` |
| `-n` | **预连接通道数量**（连接池大小） | `3` |

## 使用方法

### 服务端

#### 基本启动

```bash
# WSS 服务端（自动生成自签名证书）
ech-tunnel -l wss://0.0.0.0:8443/tunnel

# WS 服务端（不加密，仅测试用）
ech-tunnel -l ws://0.0.0.0:8080/tunnel
```

#### 使用自定义证书

```bash
ech-tunnel -l wss://0.0.0.0:443/tunnel -cert /path/to/cert.pem -key /path/to/key.pem
```

#### 启用身份验证

```bash
ech-tunnel -l wss://0.0.0.0:8443/tunnel -token your-secret-token
```

#### 限制来源 IP

```bash
# 仅允许指定网段
ech-tunnel -l wss://0.0.0.0:8443/tunnel -cidr 192.168.0.0/16,10.0.0.0/8

# 仅允许单个 IP
ech-tunnel -l wss://0.0.0.0:8443/tunnel -cidr 203.0.113.50/32
```

### 客户端

#### SOCKS5/HTTP 代理模式

```bash
# 基本代理（默认3个预连接通道）
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel

# 带认证的代理
ech-tunnel -l proxy://user:pass@127.0.0.1:1080 -f wss://server.example.com:8443/tunnel

# 使用服务端 token
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -token your-secret-token

# 增加预连接通道数（高并发场景）
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -n 5

# 减少预连接通道数（节省资源）
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -n 1
```

#### TCP 端口转发模式

```bash
# 单端口转发
ech-tunnel -l tcp://127.0.0.1:8080/example.com:80 -f wss://server.example.com:8443/tunnel

# 多端口转发
ech-tunnel -l tcp://127.0.0.1:8080/example.com:80,127.0.0.1:8443/example.com:443 -f wss://server.example.com:8443/tunnel

# 内网服务转发
ech-tunnel -l tcp://127.0.0.1:3389/192.168.1.100:3389 -f wss://server.example.com:8443/tunnel
```

#### 指定连接 IP

当需要绕过 DNS 或指定特定 IP 时：

```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -ip 203.0.113.10
```

#### 自定义 ECH 配置

```bash
# 使用腾讯 DoH
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -dns doh.pub/dns-query

# 使用 360 DoH
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -dns doh.360.cn/dns-query

# 使用其他 ECH 域名
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -ech cloudflare.com
```

## 使用场景

### 场景 1：安全代理

**服务端部署在云服务器：**
```bash
ech-tunnel -l wss://0.0.0.0:443/ws -cert cert.pem -key key.pem -token secret123
```

**本地客户端：**
```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://your-server.com/ws -token secret123
```

配置浏览器使用 `127.0.0.1:1080` 作为 SOCKS5 或 HTTP 代理。

### 场景 2：通过 CDN 中转

将服务端域名接入 Cloudflare 等支持 WebSocket 的 CDN：

**服务端：**
```bash
ech-tunnel -l wss://0.0.0.0:443/tunnel -cert cert.pem -key key.pem
```

**客户端：**
```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://your-cdn-domain.com/tunnel
```

### 场景 3：内网穿透

访问内网中的服务：

**服务端（公网）：**
```bash
ech-tunnel -l wss://0.0.0.0:8443/tunnel
```

**客户端：**
```bash
# 将内网 RDP 服务映射到本地
ech-tunnel -l tcp://127.0.0.1:3389/192.168.1.100:3389 -f wss://server.com:8443/tunnel

# 将内网数据库映射到本地
ech-tunnel -l tcp://127.0.0.1:3306/192.168.1.50:3306 -f wss://server.com:8443/tunnel
```

### 场景 4：多服务转发

同时转发多个服务：

```bash
ech-tunnel -l tcp://127.0.0.1:8080/web.internal:80,127.0.0.1:8443/web.internal:443,127.0.0.1:3306/db.internal:3306 -f wss://server.com:8443/tunnel
```

### 场景 5：高并发场景

需要处理大量并发连接时，增加预连接通道数：

```bash
# 10个预连接通道，适合高并发
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.com:8443/tunnel -n 10
```

## 代理协议支持

### SOCKS5

完整支持 SOCKS5 协议 (RFC 1928)：

- **认证方式**：无认证 / 用户名密码认证
- **命令支持**：
  - `CONNECT` - TCP 连接
  - `UDP ASSOCIATE` - UDP 转发
- **地址类型**：IPv4 / IPv6 / 域名

### HTTP 代理

- **CONNECT 方法**：用于 HTTPS 隧道
- **普通请求**：GET / POST / PUT / DELETE 等
- **认证**：Basic 认证

## 安全建议

1. **始终使用 WSS** - 生产环境必须使用 `wss://`，避免使用 `ws://`
2. **启用 Token 认证** - 使用 `-token` 设置复杂的认证令牌
3. **限制来源 IP** - 使用 `-cidr` 仅允许可信 IP 连接
4. **使用有效证书** - 生产环境使用 Let's Encrypt 等 CA 签发的证书
5. **定期更换凭据** - 定期更换 token 和代理密码

## 故障排查

### ECH 相关

**问题**：`DoH 请求失败`
```
[客户端] DNS 查询失败: DoH 请求失败: ...，2秒后重试...
```
**解决**：更换 DoH 服务器 `-dns doh.pub/dns-query` 或 `-dns doh.360.cn/dns-query`

**问题**：`未找到 ECH 参数`
```
[客户端] 未找到 ECH 参数（HTTPS RR key=echconfig/5），2秒后重试...
```
**解决**：更换支持 ECH 的域名 `-ech cloudflare.com`

**问题**：`服务器拒绝 ECH`
```
服务器拒绝 ECH（禁止回退）
```
**解决**：ECH 公钥可能已轮换，程序会自动刷新重试

### 连接相关

**问题**：WebSocket 连接失败
**排查**：
- 确认服务端正在运行
- 检查端口是否开放
- 验证 token 是否匹配
- 检查证书是否有效

**问题**：连接超时
**解决**：增加预连接通道数 `-n 5` 或检查网络质量

### 国内常用 DoH 服务器

| 提供商 | 地址 | 说明 |
|--------|------|------|
| **阿里云 DNS** | `dns.alidns.com/dns-query` | 默认，稳定可靠 |
| **腾讯 DNSPod** | `doh.pub/dns-query` | 国内访问快 |
| **360 安全 DNS** | `doh.360.cn/dns-query` | 备选 |

### 海外常用 DoH 服务器

| 提供商 | 地址 |
|--------|------|
| Cloudflare | `cloudflare-dns.com/dns-query` |
| Google | `dns.google/dns-query` |
| Quad9 | `dns.quad9.net/dns-query` |

## 许可证

[MIT](LICENSE)
