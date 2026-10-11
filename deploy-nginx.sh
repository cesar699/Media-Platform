#!/bin/bash
# CSMP 畅搜媒体平台一键部署 (nginx 共存版, Ubuntu/Debian)
# 适用场景: 本机已有 nginx 占用 80/443 (比如已有代理), 证书走你自己的 acme.sh
# 做法: 只部署 CSMP 后端服务 (127.0.0.1:5000), 并写一份 nginx 反代配置, 不碰你现有的证书和站点
#
# VPS 上一行搞定:
#   curl -fsSL https://raw.githubusercontent.com/cesar699/Media-Platform/main/deploy-nginx.sh | sudo bash
#
# (默认用根域名 csmp.si, 需已解析到本机; 换别的域名则加 DOMAIN=xxx;
#  如已有 acme.sh 证书, 可加 SSL_CERT=/path/x.cer SSL_KEY=/path/x.key 一起部署, 自动配好 443)
set -e

DOMAIN="${DOMAIN:-csmp.si}"
REPO="cesar699/Media-Platform"
INSTALL_DIR="/opt/csmp"
SERVICE_USER="${SUDO_USER:-$USER}"

# 确定代码来源: 在仓库里直接运行就用本地, 否则从 GitHub 拉最新
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
if [ -f "$SCRIPT_DIR/app.py" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
  SRC_DIR="$SCRIPT_DIR"
  echo "== 使用本地代码: $SRC_DIR =="
else
  echo "== 从 GitHub 拉取最新代码 =="
  rm -rf /tmp/csmp-src
  mkdir -p /tmp/csmp-src
  curl -fsSL "https://github.com/$REPO/archive/refs/heads/main.tar.gz" \
    | tar xz -C /tmp/csmp-src
  SRC_DIR="/tmp/csmp-src/Media-Platform-main"
fi

echo "== 安装到 $INSTALL_DIR (域名: $DOMAIN) =="
# 重装保留已下载文件和 Cookie, 不丢数据
PRESERVE_DIR="/tmp/csmp-preserve"
rm -rf "$PRESERVE_DIR"
mkdir -p "$PRESERVE_DIR"
if [ -d "$INSTALL_DIR/downloads" ]; then
  cp -a "$INSTALL_DIR/downloads" "$PRESERVE_DIR/"
fi
if [ -f "$INSTALL_DIR/cookies.txt" ]; then
  cp -a "$INSTALL_DIR/cookies.txt" "$PRESERVE_DIR/"
fi
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/downloads"
cp "$SRC_DIR/app.py" "$SRC_DIR/requirements.txt" "$INSTALL_DIR/"
cp -r "$SRC_DIR/templates" "$INSTALL_DIR/"
if [ -d "$PRESERVE_DIR/downloads" ]; then
  cp -a "$PRESERVE_DIR/downloads/." "$INSTALL_DIR/downloads/"
fi
if [ -f "$PRESERVE_DIR/cookies.txt" ]; then
  cp -a "$PRESERVE_DIR/cookies.txt" "$INSTALL_DIR/"
fi
rm -rf "$PRESERVE_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
APP_DIR="$INSTALL_DIR"

echo "== 1/5 环境检测 =="
need_cmd() { command -v "$1" >/dev/null 2>&1; }
TO_INSTALL=""
need_cmd python3 || TO_INSTALL="$TO_INSTALL python3"
need_cmd pip3    || TO_INSTALL="$TO_INSTALL python3-pip"
need_cmd ffmpeg  || TO_INSTALL="$TO_INSTALL ffmpeg"
need_cmd curl    || TO_INSTALL="$TO_INSTALL curl"
if [ -n "$TO_INSTALL" ]; then
  echo "缺少:$TO_INSTALL, 将自动安装"
else
  echo "python3 / pip3 / ffmpeg / curl 齐全"
fi
if ! need_cmd nginx; then
  echo "错误: 本机没装 nginx。"
  echo "如果你没有现成的 nginx, 请用普通版一键部署 (自动装 Caddy + 证书):"
  echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy.sh | sudo bash"
  exit 1
fi
# 域名是否已有 server 块, 避免重复 (跳过我们自己上次写的配置, 允许重跑升级)
NGINX_CONF="$NGINX_CONF_DIR/csmp.conf"
if [ ! -f "$NGINX_CONF" ]; then
  DOMAIN_RE="${DOMAIN//./\\.}"
  if nginx -T 2>/dev/null | grep -Eq "server_name[^;{}]*[[:space:]]$DOMAIN_RE([[:space:];]|$)"; then
    echo "错误: nginx 已有 $DOMAIN 的配置, 请先检查 /etc/nginx/ 下的现有站点再部署。"
    exit 1
  fi
fi

echo "== 2/5 安装系统依赖 =="
if [ -n "$TO_INSTALL" ]; then
  apt-get update -qq
  # shellcheck disable=SC2086
  apt-get install -y -qq $TO_INSTALL > /dev/null
fi
# 安装后复查: 缺一不可, 否则直接报错退出
for cmd in python3 pip3 ffmpeg curl; do
  need_cmd "$cmd" || { echo "错误: $cmd 安装失败, 请检查网络后重试"; exit 1; }
done
echo "  $(python3 --version 2>&1)"
echo "  $(ffmpeg -version 2>/dev/null | head -n 1)"
pip3 install --break-system-packages -q -r "$APP_DIR/requirements.txt"

echo "== 3/5 systemd 服务 =="
cat > /etc/systemd/system/csmp.service <<EOF
[Unit]
Description=CSMP 畅搜媒体平台
After=network.target

[Service]
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
# 单 worker + 多线程: 任务状态存在内存中, 多 worker 会导致查不到任务;
# gthread 让长连接 (视频推流) 不阻塞其他请求
ExecStart=/usr/local/bin/gunicorn -w 1 -k gthread --threads 8 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now csmp
sleep 3
if ! systemctl is-active csmp > /dev/null; then
  echo "错误: csmp 服务启动失败，日志如下:"
  journalctl -u csmp -n 25 --no-pager || true
  exit 1
fi

echo "== 4/5 nginx 反代配置 =="
# acme.sh webroot 验证目录: 证书申请时 HTTP 验证走这个目录, 不打扰后端
WEBROOT="/var/www/html"
mkdir -p "$WEBROOT/.well-known/acme-challenge"

# 有证书就配 443 + 强制跳转, 否则先只开 80 (申请完证书再加 443)
if [ -n "$SSL_CERT" ] && [ -n "$SSL_KEY" ] && [ -f "$SSL_CERT" ] && [ -f "$SSL_KEY" ]; then
  cat > "$NGINX_CONF" <<EOF
# CSMP 畅搜媒体平台 (与现有 nginx 共存; 证书由 acme.sh 管理)
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    client_max_body_size 2m;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        # X-Forwarded-For 必须透传: 后端的按 IP 限流靠它识别真实访客
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # 视频直连播走 206 分片: 关缓冲让数据实时流出, 超时放宽到 2 分钟
        proxy_buffering off;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
EOF
  echo "检测到证书, 已配置 443。"
else
  cat > "$NGINX_CONF" <<EOF
# CSMP 畅搜媒体平台 (与现有 nginx 共存; 证书由 acme.sh 管理)
# 注: 当前只有 80 端口。用 acme.sh 拿到 $DOMAIN 证书后,
# 可重新跑本脚本并加 SSL_CERT/SSL_KEY 参数自动配好 443。
server {
    listen 80;
    server_name $DOMAIN;
    client_max_body_size 2m;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        # X-Forwarded-For 必须透传: 后端的按 IP 限流靠它识别真实访客
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # 视频直连播走 206 分片: 关缓冲让数据实时流出, 超时放宽到 2 分钟
        proxy_buffering off;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
EOF
  echo "未提供证书, 先只配置 80 端口。"
fi
nginx -t
systemctl reload nginx

echo "== 5/5 收尾 =="
echo ""
echo "部署完成!"
if [ -n "$SSL_CERT" ] && [ -f "$SSL_CERT" ]; then
  echo "访问 https://$DOMAIN"
else
  echo "访问 http://$DOMAIN (先用 HTTP 验证功能正常)"
  echo ""
  echo "证书 (acme.sh, 证书不走 Caddy, 继续用你现有的):"
  echo "  1) 申请: acme.sh --issue -d $DOMAIN -w $WEBROOT"
  echo "  2) 安装: acme.sh --install-cert -d $DOMAIN \\"
  echo "             --key-file /etc/nginx/ssl/$DOMAIN.key \\"
  echo "             --fullchain-file /etc/nginx/ssl/$DOMAIN.cer \\"
  echo "             --reloadcmd \"systemctl reload nginx\""
  echo "  3) 配好 443: 重新跑本脚本, 加上证书路径:"
  echo "     curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy-nginx.sh | \\"
  echo "       sudo SSL_CERT=/etc/nginx/ssl/$DOMAIN.cer SSL_KEY=/etc/nginx/ssl/$DOMAIN.key bash"
fi
echo ""
echo "注意: 域名 $DOMAIN 必须已解析到本机 IP (云厂商安全组放行 80/443)。"
echo "acme.sh 续期后会自动重载 nginx, 证书无需手动维护。"
