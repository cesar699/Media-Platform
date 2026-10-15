# TLCore-Native · 天龙核心（原生版）

**协议内核完全自研**的多协议代理核心 + 可视化管理面板。不嵌入
sing-box / Xray：`internal/engine` 里的每个协议都是按公开规范手写的
Go 实现（QUIC 系基于 quic-go 库），并尽可能与官方实现做了互通对验。
二进制约 15MB。

## 协议与验证状态（2026-10-15，本地实测）

| 协议 | 实现要点 | 验证结论 |
|---|---|---|
| Shadowsocks 2022 | SIP022：BLAKE3 子密钥派生、首包随机填充、AEAD 分帧；TCP+UDP | TCP ✅ 与官方双向互通 + 错密码被拒；UDP 见下方说明 |
| Trojan | TLS + SHA-224 密码哈希 + SOCKS 地址帧；TCP+UDP（命令 0x03） | TCP ✅ 双向互通；UDP 见下方说明 |
| VLESS | 原生 VLESS 请求/响应帧（无 Reality）；TCP+UDP（命令 0x02） | TCP ✅ 双向互通；UDP 见下方说明 |
| VMess | AEAD：AuthID、嵌套 HMAC KDF、双层头部 AEAD、SHAKE128 掩码分帧（0x05）与 auth-len（0x11）两种数据剖面；TCP+UDP | TCP ✅ 双向互通；UDP 见下方说明 |
| AnyTLS v2 | SHA-256 密码哈希认证、会话多路复用帧、默认填充方案的记录塑形（stop=8）、Settings/SYNACK v2 协商 | ✅ 与官方 sing-box 双向互通（我的客户端→官方服务端、官方客户端→我的服务端）+ 错密码被拒 |
| TUIC v5 | QUIC（ALPN h3）：TLS 1.3 Exporter 令牌认证、Connect 流、Packet 报文（数据报/单向流双通道）、分片重组、心跳 | ⚠️ 见下方说明 |
| Hysteria2 | QUIC + HTTP/3 认证（233 状态码）、0x401 原始流分发、UDP 数据报会话、随机填充 | ⚠️ 见下方说明 |

**关于 UDP 与 QUIC 的验证边界（如实说明）**：开发沙箱会丢弃一切真实
UDP 数据报，因此 SS2022/Trojan/VLESS/VMess 的 UDP 中继与 TUIC /
Hysteria2 无法在本环境与官方实现做真实网络互通。已完成的验证是：
线格式逐行对照官方源码转写 + 独立转写的编解码向量测试（字节级）+
自研客户端↔自研服务端在**内存 PacketConn 传输**（线上字节与真实
网络完全一致）上的端到端穿透（TCP+UDP 回显、错密码拒绝）。真实网络
下与官方客户端/服务端的互通请在部署后自行复核；TCP 协议与 AnyTLS
不受此限，均已与官方双向实测通过。

## 功能

- 网页面板：登录（bcrypt + HttpOnly 会话）、状态总览、入站增删改、
  启用/停用、分享链接 + 二维码、服务器地址、改密
- **订阅链接**：`/sub/<令牌>` 公开端点（令牌可重置），一次导入全部
  已启用节点（通用 base64 格式），面板内有复制/二维码/重置
- **流量统计**：每入站累计上/下行字节与连接数（当前/累计），
  30 秒落盘 + 配置变更时落盘，重启后自动恢复
- 热切换与回滚：候选状态先校验再应用，失败自动回到上一个可用集合，
  磁盘状态永不与运行中的内核脱节
- 状态持久化在 `data/state.json`；自签证书在 `data/certs/`

## 构建与运行

```bash
go build -o tlcore-native .
TLCORE_ADMIN_PASSWORD='你的密码' ./tlcore-native -addr 0.0.0.0:8080 -data ./data
```

构建依赖 Go 1.26+；QUIC 协议使用 `github.com/sagernet/quic-go`
（sing-box 的 quic-go 分叉）作为传输库，协议逻辑均为自研。

## 一键部署到 VPS

在 VPS 上以 root 运行（一行）：

```bash
curl -fsSL https://raw.githubusercontent.com/cesar699/tlcore-native/main/deploy.sh | sudo bash
```

脚本会：装 Go 工具链（如缺）→ 拉代码编译 → 装 systemd 服务并开机自启 →
放行面板端口 → 打印面板地址和初始管理员密码。重复运行即更新（数据不动）。

可选：`PANEL_PORT=8080 ADMIN_USER=admin ADMIN_PASSWORD=...` 以环境变量传入。
面板自带登录（bcrypt），公网暴露前请务必改掉初始密码。

## 项目结构

```
main.go                  入口：管理员预置、核心自恢复、流量落盘、HTTP 服务
internal/
  engine/                自研协议引擎（本项目的核心）
    addr.go              SOCKS 地址编解码、中继管道
    engine.go            监听生命周期与协议分发（TCP/TLS/QUIC）
    meter.go             流量计量（每入站原子计数 + 连接包裹）
    udp.go               UDP 工具（地址转换、回包泵）
    ss2022.go            Shadowsocks 2022 TCP（服务端+客户端）
    ss2022_udp.go        Shadowsocks 2022 UDP（会话/ECB 头/AEAD/重放窗）
    trojan.go            Trojan（服务端+客户端，含 UDP）
    vless.go             VLESS（服务端+客户端，含 UDP）
    vmess.go             VMess AEAD（服务端+客户端，含 UDP）
    anytls.go            AnyTLS v2（服务端+客户端，多路复用+填充塑形）
    tuic.go              TUIC v5（服务端+客户端，QUIC）
    hysteria2.go         Hysteria2（服务端+客户端，QUIC + HTTP/3 认证）
    socks.go             SOCKS5/HTTP 混合入口（本地网关/测试用）
  proto/                 协议目录、密钥/证书生成、引擎 Spec、分享链接
  core/                  状态→引擎的应用/回滚管理器 + 流量种子/快照
  store/                 状态持久化（JSON，原子写；含订阅令牌与流量记录）
  api/                   HTTP API（会话认证、入站 CRUD、二维码、订阅、统计）
  web/                   内嵌单页管理 UI（流量/订阅面板）
tools/
  probe/                 本地网关→自研客户端的互通测试工具（7 协议）
  server/                单入站测试服务
  vmprobe/               VMess 直连调试工具
```

## 尚未实现（如实标注）

- VLESS Reality / Encryption（需定制 TLS 栈）
- Trojan 认证失败回落（fallback）未做，当前直接断开
- AnyTLS 的 UDP-over-stream（当前 AnyTLS 只做 TCP 流）
- Hysteria2 的 Salamander/Gecko 混淆与端口跳跃
- TUIC / Hysteria2 与官方实现的真实网络互通（受沙箱 UDP 限制未验，
  见上方验证边界说明）

## 许可

个人项目，自用为主。仅使用公开协议规范、标准密码学库与 quic-go
传输库实现互通。
