#!/bin/bash
# CSMP 畅搜媒体平台一键部署 (Ubuntu/Debian)
# 功能: 安装依赖 -> systemd 常驻服务 -> Caddy 反代 + 自动申请 Let's Encrypt 证书
#
# 用法: sudo DOMAIN=dl.csmp.si bash deploy.sh
#   (域名需已解析到本机; 如用根域名 csmp.si, 则 DOMAIN=csmp.si)
set -e

DOMAIN="${DOMAIN:-dl.csmp.si}"
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_USER="${SUDO_USER:-$USER}"

echo "== 域名: $DOMAIN =="

echo "== 1/5 安装依赖 =="
apt-get update -qq
apt-get install -y -qq python3 python3-pip ffmpeg curl debian-keyring debian-archive-keyring apt-transport-https > /dev/null
pip3 install --break-system-packages -q -r "$APP_DIR/requirements.txt"

echo "== 2/5 systemd 服务 =="
cat > /etc/systemd/system/csmp.service <<EOF
[Unit]
Description=CSMP 畅搜媒体平台
After=network.target

[Service]
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/gunicorn -w 2 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now csmp
sleep 3
systemctl is-active csmp

echo "== 3/5 安装 Caddy =="
if ! command -v caddy > /dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
  apt-get update -qq && apt-get install -y -qq caddy > /dev/null
fi

echo "== 4/5 配置自动证书 =="
sed "s/{\$DOMAIN:dl.csmp.si}/$DOMAIN/" "$APP_DIR/Caddyfile" > /etc/caddy/Caddyfile
caddy fmt --overwrite /etc/caddy/Caddyfile
systemctl reload caddy

echo "== 5/5 放行端口 =="
ufw allow 80/tcp 2>/dev/null || true
ufw allow 443/tcp 2>/dev/null || true

echo ""
echo "部署完成! 访问 https://$DOMAIN"
echo "证书由 Caddy 自动向 Let's Encrypt 申请并续期, 无需手动操作。"
echo "注意: 域名 $DOMAIN 必须已解析到本机 IP, 且 80/443 端口对外可达 (云厂商安全组也要放行)。"
