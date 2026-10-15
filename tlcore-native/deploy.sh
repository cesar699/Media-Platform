#!/usr/bin/env bash
# TLCore-Native 一键部署脚本
#
# 在你的 VPS 上以 root 身份运行（一行搞定）：
#   curl -fsSL https://raw.githubusercontent.com/cesar699/tlcore-native/main/deploy.sh | sudo bash
#
# 可选环境变量：
#   PANEL_PORT=8080        面板监听端口（默认 8080）
#   ADMIN_USER=admin       管理员用户名（默认 admin）
#   ADMIN_PASSWORD=...     管理员密码；不填则自动生成随机密码并打印出来
#   REPO=...               仓库地址（默认 github.com/cesar699/tlcore-native）
#
# 重复运行 = 更新：拉最新代码、重新编译、重启服务，/var/lib/tlcore-native 下的数据不动。
set -euo pipefail

REPO="${REPO:-https://github.com/cesar699/tlcore-native.git}"
INSTALL_DIR="/opt/tlcore-native"
DATA_DIR="/var/lib/tlcore-native"
BIN="/usr/local/bin/tlcore-native"
SERVICE="/etc/systemd/system/tlcore-native.service"
GO_VERSION="1.26.0"
PANEL_PORT="${PANEL_PORT:-8080}"
ADMIN_USER="${ADMIN_USER:-admin}"

log() { echo -e "\033[1;32m[tlcore]\033[0m $*"; }
warn() { echo -e "\033[1;33m[tlcore]\033[0m $*" >&2; }
die() { echo -e "\033[1;31m[tlcore]\033[0m $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "请用 root 运行（前面加 sudo）"

# ---------- 基础依赖 ----------
if command -v apt-get >/dev/null 2>&1; then
    log "安装依赖 (apt)…"
    apt-get update -qq
    apt-get install -y -qq git curl ca-certificates >/dev/null
elif command -v yum >/dev/null 2>&1; then
    log "安装依赖 (yum)…"
    yum install -y -q git curl ca-certificates >/dev/null
elif command -v apk >/dev/null 2>&1; then
    log "安装依赖 (apk)…"
    apk add --no-cache git curl ca-certificates >/dev/null
else
    warn "没认出包管理器，请先手动装好 git 和 curl"
fi
command -v git >/dev/null || die "没找到 git，请先安装"

# ---------- Go 工具链（go.mod 要求 go >= 1.26） ----------
go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local v
    v="$(go version | grep -oE 'go1\.[0-9]+' | head -1 | cut -c3-)"
    local major="${v%%.*}" minor="${v##*.}"
    { [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 26 ]; }; }
}
if ! go_ok; then
    arch="$(uname -m)"
    case "$arch" in
        x86_64) goarch="amd64" ;;
        aarch64|arm64) goarch="arm64" ;;
        *) die "不支持的架构: $arch" ;;
    esac
    log "安装 Go ${GO_VERSION}（${goarch}）…"
    curl -fsSL -o /tmp/go.tgz "https://dl.google.com/go/go${GO_VERSION}.linux-${goarch}.tar.gz"
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
fi
log "Go: $(go version)"

# ---------- 拉代码、编译 ----------
if [ -d "$INSTALL_DIR/.git" ]; then
    log "更新代码…"
    git -C "$INSTALL_DIR" fetch -q origin
    git -C "$INSTALL_DIR" reset -q --hard origin/HEAD
else
    log "克隆代码…"
    rm -rf "$INSTALL_DIR"
    git clone -q "$REPO" "$INSTALL_DIR"
fi
log "编译…"
export GOTMPDIR="${GOTMPDIR:-$INSTALL_DIR/.build-tmp}"
mkdir -p "$GOTMPDIR"
(cd "$INSTALL_DIR" && CGO_ENABLED=0 go build -trimpath -o "$BIN" .)
chmod 755 "$BIN"
log "二进制: $BIN ($("$BIN" -h 2>/dev/null | head -1 || echo ok))"

# ---------- 管理员密码 ----------
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
if [ -z "${ADMIN_PASSWORD:-}" ]; then
    if [ -f "$DATA_DIR/state.json" ] && grep -q '"admin_pass_hash":"[^"]' "$DATA_DIR/state.json" 2>/dev/null; then
        log "检测到已有管理员账号，保持原密码（想改去面板设置里改）"
        ADMIN_PASSWORD="__KEEP__"
    else
        ADMIN_PASSWORD="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
        FIRST_RUN=1
    fi
fi

# ---------- systemd 服务 ----------
log "写入 systemd 服务…"
if [ "$ADMIN_PASSWORD" = "__KEEP__" ]; then
    env_line="# 管理员已存在，密码沿用面板里的"
else
    env_line="Environment=\"TLCORE_ADMIN_PASSWORD=${ADMIN_PASSWORD}\""
fi
cat > "$SERVICE" <<EOF
[Unit]
Description=TLCore-Native proxy core + panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DATA_DIR
Environment=TLCORE_ADMIN_USER=${ADMIN_USER}
${env_line}
ExecStart=$BIN -addr 0.0.0.0:${PANEL_PORT} -data $DATA_DIR
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
chmod 600 "$SERVICE"
systemctl daemon-reload
systemctl enable -q tlcore-native
systemctl restart tlcore-native
sleep 2
systemctl is-active -q tlcore-native || {
    warn "服务没起来，看日志：journalctl -u tlcore-native -n 50"
    exit 1
}

# ---------- 防火墙放行面板端口 ----------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${PANEL_PORT}/tcp" >/dev/null && log "ufw 已放行 ${PANEL_PORT}/tcp"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    firewall-cmd -q --permanent --add-port="${PANEL_PORT}/tcp" && firewall-cmd -q --reload && log "firewalld 已放行 ${PANEL_PORT}/tcp"
elif command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT
    log "iptables 已放行 ${PANEL_PORT}/tcp（重启后需自行持久化）"
fi

# ---------- 收尾 ----------
PUBIP="$(curl -fsSL --max-time 8 https://api.ipify.org 2>/dev/null || echo "<你的服务器IP>")"
echo
log "部署完成 ✅"
echo "  面板地址: http://${PUBIP}:${PANEL_PORT}"
echo "  管理员:   ${ADMIN_USER}"
if [ "${FIRST_RUN:-0}" = "1" ]; then
    echo "  初始密码: ${ADMIN_PASSWORD}   ← 只显示这一次，登录后去设置里改"
fi
echo
echo "  进面板 → 设置 → 填服务器地址（${PUBIP}），然后「+ 新建入站」建节点，"
echo "  链接/二维码一键生成，手机扫码即用。"
echo "  日志: journalctl -u tlcore-native -f"
