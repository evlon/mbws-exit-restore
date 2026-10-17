# =====================================================================
#  policy_decode.ps1 —— 密保卫士策略传输载荷解码/编码辅助工具
#
#  背景（逆向结论）：密保卫士客户端与管控服务器之间的策略传输使用
#  base64( XOR( JSON(UTF-8), 0x1F ) ) 编码；服务器 <策略服务器IP>，
#  端口 8443 / 15001 / 38443 / 26112。
#
#  用法：
#    解码（直接给字符串）：
#      .\policy_decode.ps1 -Text "<base64载荷>"
#    解码（载荷存成了文件，支持每行一条）：
#      .\policy_decode.ps1 -File .\payload.txt
#    编码（把明文 JSON 编成同格式载荷，用于验证解码器/构造测试）：
#      .\policy_decode.ps1 -Encode -Json '{"a":1}'
#
#  抓包提示（需要管理员，本工具不代抓）：
#    管理员 PowerShell:
#      netsh trace start capture=yes tracefile=C:\temp\mbws.etl
#      （触发一次客户端策略同步，或重启 itxcltserver 服务）
#      netsh trace stop
#    或用 Wireshark 过滤 host <策略服务器IP>，Follow TCP Stream
#    导出 payload 存文件后喂给本脚本。
#
#  兼容性：Windows PowerShell 5.1，无需管理员（纯文本运算）。
# =====================================================================

param(
    [string]$Text,
    [string]$File,
    [string]$Json,
    [switch]$Encode
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-MbwsPayload {
    param([string]$B64)
    $bytes = [Convert]::FromBase64String($B64.Trim())
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor 0x1F }
    # 优先 UTF-8；UTF8 解码不抛异常（替换回退），含 U+FFFD 时改用系统 ANSI(GBK) 重解
    $u8 = [Text.Encoding]::UTF8.GetString($bytes)
    if ($u8.IndexOf([char]0xFFFD) -ge 0) {
        return @([Text.Encoding]::Default.GetString($bytes), 'ANSI(GBK)')
    }
    return @($u8, 'UTF-8')
}

function ConvertTo-MbwsPayload {
    param([string]$PlainText)
    $bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor 0x1F }
    return [Convert]::ToBase64String($bytes)
}

if ($Encode) {
    if (-not $Json) { Write-Host '用法：-Encode -Json ''<明文JSON>'''; exit 1 }
    $b64 = ConvertTo-MbwsPayload -PlainText $Json
    Write-Host '── 编码结果（base64(XOR 0x1F)）──'
    Write-Host $b64
    Write-Host ''
    Write-Host '── 回环自检（编码→解码应还原原文）──'
    $back = ConvertFrom-MbwsPayload -B64 $b64
    if ($back[0] -eq $Json) { Write-Host '  [OK] 回环一致' } else { Write-Host ('  [异常] 回环不一致: ' + $back[0]) }
    exit 0
}

$inputs = @()
if ($Text) { $inputs += $Text }
if ($File) {
    if (-not (Test-Path -LiteralPath $File)) { Write-Host ('找不到文件: ' + $File); exit 1 }
    $inputs += (Get-Content -LiteralPath $File -Encoding UTF8 | Where-Object { $_.Trim() })
}
if ($inputs.Count -eq 0) {
    Write-Host '密保卫士策略载荷解码器'
    Write-Host '  解码: .\policy_decode.ps1 -Text "<base64>"   或  -File <载荷文件>'
    Write-Host '  编码: .\policy_decode.ps1 -Encode -Json "<明文JSON>"'
    exit 0
}

$n = 0
foreach ($b64 in $inputs) {
    $n++
    Write-Host ('── 载荷 #{0}（{1} 字符）──' -f $n, $b64.Trim().Length)
    try {
        $dec = ConvertFrom-MbwsPayload -B64 $b64
        $plain = $dec[0]
        Write-Host ('  编码: ' + $dec[1])
        $obj = $null
        try { $obj = $plain | ConvertFrom-Json } catch { }
        if ($obj) {
            Write-Host '  格式: JSON，Pretty 输出：'
            ($obj | ConvertTo-Json -Depth 16) -split "`n" | ForEach-Object { Write-Host ('  ' + $_.TrimEnd()) }
        } else {
            Write-Host '  格式: 纯文本，内容：'
            $plain -split "`n" | ForEach-Object { Write-Host ('  ' + $_.TrimEnd()) }
        }
    } catch {
        Write-Host ('  [失败] ' + $_.Exception.Message)
        Write-Host '  （提示：确认载荷是 base64(XOR 0x1F) 格式；或截取时混入了非载荷字节）'
    }
}
