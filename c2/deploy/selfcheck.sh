#!/usr/bin/env bash
# Camty C2 部署套件本地自检（不依赖服务器）：语法/结构/路径/引用一致性。
# 用法：bash c2/deploy/selfcheck.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
fail=0

check() {  # check <描述> <命令>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  [ok] $desc"
  else
    echo "  [FAIL] $desc"
    fail=1
  fi
}

echo "== 1) 脚本语法 =="
check "deploy.sh bash 语法" bash -n "$HERE/deploy.sh"
check "selfcheck 自身" bash -n "$HERE/selfcheck.sh"

echo "== 2) 服务端/植入体语法与结构 =="
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "print(1)" >/dev/null 2>&1; then
    PY="$cand"; break
  fi
done
check "camty_c2.py 可编译" "$PY" -c "import ast,sys;ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$REPO/c2/server/camty_c2.py"
check "beacon.c 关键宏齐备" grep -q "C2_PSK_HEX" "$REPO/c2/implant/beacon.c"
check "loader.c PE 映射完整" grep -q "IMAGE_REL_BASED_DIR64" "$REPO/c2/implant/loader.c"

echo "== 3) systemd 单元结构 =="
for field in "Description=" "EnvironmentFile=/etc/camty/c2.env" "ExecStart=" "Restart=on-failure" "User=camty"; do
  check "service 含 $field" grep -q "$field" "$HERE/camty-c2.service"
done
check "service api 只绑回环(--api-bind 127.0.0.1)" grep -q "api-port 127.0.0.1" "$HERE/camty-c2.service"

echo "== 4) Caddyfile 结构 =="
check "beacon 反代路径" grep -q "/api/v1/heartbeat" "$HERE/Caddyfile"
check "result 反代路径" grep -q "/api/v1/report" "$HERE/Caddyfile"

echo "== 5) env 示例字段 =="
for var in CAMTY_TOKEN CAMTY_PSK CAMTY_BEACON_PORT CAMTY_API_PORT CAMTY_BEACON_PATH CAMTY_RESULT_PATH; do
  check "c2.env.example 含 $var" grep -q "$var" "$HERE/c2.env.example"
done

echo "== 6) 服务端 CLI 参数一致性 =="
check "camty_c2 支持 --beacon-path" grep -q "beacon-path" "$REPO/c2/server/camty_c2.py"
check "camty_c2 支持 --api-bind" grep -q "api-bind" "$REPO/c2/server/camty_c2.py"
check "beacon 使用 WinHTTP TLS" grep -q "WinHttpOpen" "$REPO/c2/implant/beacon.c"

if [ "$fail" -eq 0 ]; then
  echo "SELF CHECK PASS：套件结构完整（真机部署按 c2/deploy/README.md 执行）"
else
  echo "SELF CHECK FAIL：存在结构缺失"
  exit 1
fi
