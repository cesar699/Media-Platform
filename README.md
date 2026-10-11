# CSMP · 畅搜媒体平台

Smooth Search Media Platform — 视频搜索下载站 (单用户个人使用)。

粘贴视频 / 播放列表 / 频道链接, 或输入关键词选站点搜索,
自动列出视频, 勾选后一键下载。

## 功能

- 🔍 链接 / 关键词搜索 (YouTube / PornHub, yt-dlp 支持 1700+ 站点)
- 🖼️ 缩略图 + 标题 + 时长 + 作者, 卡片式勾选
- ⚡ 直接播: 粘贴链接后点卡片上的"直接播", 服务器实时转发视频流, 不用先下载
- ⬇️ 后台批量下载, 实时进度
- 🎚️ 清晰度选择 (最高 / 1080p / 720p / 480p)
- ✨ 尽量无水印模式
- 📁 已下载文件管理 (▶ 在线预览 / ⬇ 存到本地 / 删除)
- 🍪 会员 Cookie: 保存登录态后可搜/下/播会员视频 (Cookie 仅存服务器, 权限 600, 不进 Git)
- 🔒 Caddy 自动申请并续期 Let's Encrypt 证书

> 会员视频需先点 🍪 会员 Cookie 保存登录态 (浏览器 F12 控制台输 `document.cookie` 复制,
> 或用「Get cookies.txt」插件导出)。没有该网站会员则无法观看会员内容。

## 本地运行

```bash
pip install -r requirements.txt   # 需要 python3, 另需系统安装 ffmpeg
python3 app.py 5000
# 浏览器打开 http://127.0.0.1:5000
```

## 服务器部署 (Ubuntu/Debian)

VPS 上一行搞定，脚本会自动判断：

```bash
curl -fsSL https://raw.githubusercontent.com/cesar699/Media-Platform/main/deploy.sh | sudo bash
```

- **本机无 nginx** → 装 Caddy，自动申请并续期 Let's Encrypt 证书，零手动操作
- **本机有 nginx** (如已有 VPN 代理) → 自动切换共存模式：只部署后端，不装 Caddy 不碰现有站点，证书走你自己的 acme.sh
- 默认用根域名 `csmp.si` (A 记录已指向 VPS); 换别的域名在 sudo 后加 `DOMAIN=xxx`
- 有 nginx 但仍想用 Caddy：加 `FORCE_CADDY=1`
- 需放行 80/443 端口 (含云厂商安全组)

### 已有 nginx 共存部署说明 (证书走 acme.sh)

首次运行只配好 80 端口，按提示签发证书：

```bash
acme.sh --issue -d csmp.si --nginx
acme.sh --install-cert -d csmp.si --key-file /etc/nginx/ssl/csmp.si.key \
  --fullchain-file /etc/nginx/ssl/csmp.si.cer --reloadcmd "systemctl reload nginx"
```

签发后重跑一遍部署命令，自动配好 443。已有证书可直接带上：
`... | sudo SSL_CERT=/path/x.cer SSL_KEY=/path/x.key bash`

## 说明

仅供个人学习与备份自己的作品使用。
