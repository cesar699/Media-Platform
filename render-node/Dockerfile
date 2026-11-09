# Render 免费版 VLESS + WebSocket 节点
# Render 只出 HTTP/WebSocket，裸 TCP 端口出不去，所以用 WS 传输走它自带的 443。
# UUID / WS_PATH 不进仓库，通过 Render 后台 Environment Variables 传入。

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl \
    && curl -fsSL https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz -o /tmp/sb.tgz \
    && tar -xzf /tmp/sb.tgz -C /tmp \
    && mv /tmp/sing-box-1.14.3-linux-amd64/sing-box /usr/local/bin/sing-box \
    && rm -rf /tmp/* \
    && sing-box version

COPY config.json.template /etc/sing-box/config.json.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
