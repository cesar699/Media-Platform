#!/bin/sh
# 把 Render 注入的 $PORT 和后台配置的 $UUID / $WS_PATH 填进模板，然后启动 sing-box。
set -e

PORT=${PORT:-10000}
if [ -z "$UUID" ]; then echo "missing env var: UUID" >&2; exit 1; fi
if [ -z "$WS_PATH" ]; then echo "missing env var: WS_PATH" >&2; exit 1; fi

sed -e "s/__PORT__/$PORT/g" \
    -e "s/__UUID__/$UUID/g" \
    -e "s#__WS_PATH__#$WS_PATH#g" \
    /etc/sing-box/config.json.template > /etc/sing-box/config.json

exec /usr/local/bin/sing-box run -c /etc/sing-box/config.json
