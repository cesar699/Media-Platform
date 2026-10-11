#!/bin/bash
# CSMP 畅搜媒体平台一键部署 (Ubuntu/Debian)
# 功能: 拉取代码 -> 安装依赖 -> systemd 常驻服务 -> Caddy 反代 + 自动申请 Let's Encrypt 证书
#
# VPS 上一行搞定:
#   curl -fsSL https://raw.githubusercontent.com/cesar699/Media-Platform/main/deploy.sh | sudo bash
#
# (默认用根域名 csmp.si, 需已解析到本机; 换别的域名则加 DOMAIN=xxx, 如
#  curl -fsSL https://raw.githubusercontent.com/cesar699/Media-Platform/main/deploy.sh | sudo DOMAIN=dl.csmp.si bash)
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
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/downloads"
cp "$SRC_DIR/app.py" "$SRC_DIR/requirements.txt" "$INSTALL_DIR/"
cp -r "$SRC_DIR/templates" "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
APP_DIR="$INSTALL_DIR"

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
cat > /etc/caddy/Caddyfile <<EOF
# CSMP 畅搜媒体平台 (Caddy 自动申请/续期 Let's Encrypt 证书)
$DOMAIN {
	reverse_proxy 127.0.0.1:5000
}
EOF
caddy fmt --overwrite /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl enable --now caddy
systemctl reload caddy

echo "== 5/5 放行端口 =="
ufw allow 80/tcp 2>/dev/null || true
ufw allow 443/tcp 2>/dev/null || true

echo ""
echo "部署完成! 访问 https://$DOMAIN"
echo "证书由 Caddy 自动向 Let's Encrypt 申请并续期, 无需手动操作。"
echo "注意: 域名 $DOMAIN 必须已解析到本机 IP, 且 80/443 端口对外可达 (云厂商安全组也要放行)。"
