#!/usr/bin/env bash
# 拉取 subfinder/httpx 到 E:\AI tools（本地代理 7897，带重试）；nuclei 已存在则跳过
# tag 走 git ls-remote（不受 GitHub API 匿名限额影响）；解压前校验 zip 魔数
set -uo pipefail
export https_proxy=http://127.0.0.1:7897 http_proxy=http://127.0.0.1:7897
TOOLS="/e/AI tools"
STAGE="$TOOLS/_staging"
mkdir -p "$STAGE"

latest_tag() {
  git -c http.proxy=http://127.0.0.1:7897 ls-remote --tags --refs "https://github.com/projectdiscovery/$1.git" \
    | awk '{print $2}' | sed 's|refs/tags/||; s/^v//' | sort -V | tail -1 | sed 's/^/v/'
}

zip_ok() {
  python -c "import sys; sys.exit(0 if open(r'$1','rb').read(2)==b'PK' else 1)" 2>/dev/null
}

dl() {  # dl <url> <out>：代理不稳定，重试到拿到合法 zip 为止；断流快速切断
  local url="$1" out="$2" attempt=1
  while ! zip_ok "$out"; do
    [ "$attempt" -gt 30 ] && { echo "[fail] 放弃: $url"; return 1; }
    echo "  [try $attempt] $(basename "$url")"
    curl -sL --connect-timeout 20 --max-time 900 \
      --speed-time 20 --speed-limit 2048 \
      -o "$out" "$url"
    attempt=$((attempt + 1))
    sleep 2
  done
}

fetch() {
  local repo="$1" tag ver url
  if [ -e "$TOOLS/$repo/${repo}.exe" ]; then
    echo "[skip] $TOOLS/$repo 已存在，不重复下载"
    return 0
  fi
  tag=$(latest_tag "$repo")
  ver="${tag#v}"
  url="https://github.com/projectdiscovery/${repo}/releases/download/${tag}/${repo}_${ver}_windows_amd64.zip"
  echo "[fetch] $repo $tag"
  if ! dl "$url" "$STAGE/$repo.zip"; then return 1; fi
  mkdir -p "$TOOLS/$repo"
  python -c "
import zipfile
with zipfile.ZipFile(r'E:/AI tools/_staging/$repo.zip') as z:
    z.extractall(r'E:/AI tools/$repo')
print('[extract] $repo ok')
"
  rm -f "$STAGE/$repo.zip"
}

for repo in subfinder httpx nuclei; do fetch "$repo"; done

echo "[verify] 版本检查"
"$TOOLS/subfinder/subfinder.exe" -version 2>&1 | head -1 || true
"$TOOLS/httpx/httpx.exe" -version 2>&1 | head -1 || true
"$TOOLS/nuclei/nuclei.exe" -version 2>&1 | head -1 || true

echo "[templates] nuclei 模板更新（走代理，可能较慢）"
"$TOOLS/nuclei/nuclei.exe" -update-templates 2>&1 | tail -2 || echo "[templates] 更新失败，首次运行 nuclei 时会自动重试"
echo ALL_DONE
