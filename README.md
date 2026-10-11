# CSMP · 畅搜媒体平台

Smooth Search Media Platform — 视频搜索下载站 (单用户个人使用)。

粘贴视频 / 播放列表 / 频道链接, 或输入关键词选站点搜索,
自动列出视频, 勾选后一键下载。

## 功能

- 🔍 链接 / 关键词搜索 (YouTube / PornHub, yt-dlp 支持 1700+ 站点)
- 🖼️ 缩略图 + 标题 + 时长 + 作者, 卡片式勾选
- ⬇️ 后台批量下载, 实时进度
- 🎚️ 清晰度选择 (最高 / 1080p / 720p / 480p)
- ✨ 尽量无水印模式
- 📁 已下载文件管理 (查看 / 删除)
- 🔒 Caddy 自动申请并续期 Let's Encrypt 证书

## 本地运行

```bash
pip install -r requirements.txt   # 需要 python3, 另需系统安装 ffmpeg
python3 app.py 5000
# 浏览器打开 http://127.0.0.1:5000
```

## 服务器部署 (Ubuntu/Debian, 自动 HTTPS)

```bash
sudo DOMAIN=dl.csmp.si bash deploy.sh
```

- 域名需已解析到本机 (如 `dl.csmp.si` 的 A 记录指向 VPS)
- Caddy 自动完成 Let's Encrypt 证书申请与续期, 零手动操作
- 部署脚本会自动生成访问账号密码 (basic_auth) 并打印出来, 请妥善保存
- 需放行 80/443 端口 (含云厂商安全组)

## 说明

仅供个人学习与备份自己的作品使用。
