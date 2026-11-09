# render-node — Render 免费版 VLESS + WebSocket 节点

在 Render 免费套餐上跑一个 sing-box VLESS 节点。Render 只出 HTTP/WebSocket，
裸 TCP 端口出不去，所以用 WS 传输走它自带的 443（Render 边缘自动做 TLS）。

## 部署

1. 在 Render 后台新建 **Web Service**，连这个仓库，Root Directory 填 `render-node`，
   Runtime 选 **Docker**，Plan 选 **Free**。
2. 在 Environment Variables 里加两个变量（不要写进仓库）：
   - `UUID`：VLESS 用户 UUID，随便生成一个，例如 `uuidgen` 的输出
   - `WS_PATH`：WebSocket 路径，例如 `/` + 一串随机字符
3. 部署完成后会得到一个地址，如 `https://xxx.onrender.com`。

## 客户端

分享链接（把 `xxx.onrender.com` 换成实际地址，`UUID` / `WS_PATH` 换成实际值）：

```
vless://UUID@xxx.onrender.com:443?encryption=none&security=tls&sni=xxx.onrender.com&type=ws&path=%2Fxxxx#Render-VLESS
```

## 保活

免费版 15 分钟没人访问会休眠。定时每 10 分钟请求一次首页即可唤醒
（任何 HTTP 请求都会唤醒服务，不必走 WS 路径）。

## 注意

- 免费版没有持久硬盘，节点本身不需要存数据，没影响。
- 免费套餐跑代理节点有封号风险，别放重要东西。
