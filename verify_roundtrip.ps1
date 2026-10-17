# =====================================================================
#  verify_roundtrip.ps1 —— mjbwctl v3「驱动开关协议 + 三阶段闭环」验证器
#
#  三阶段协议（对应实测：驱动在场时停服务/杀进程/改配置均被拒绝）：
#    Pre   阶段：运行 -ExitOneTime -Yes → 预期完成阶段1（备份+置 unload=1）
#                随后必须重启电脑（开关只在驱动启动时读取）
#    Post  阶段：重启后运行 → 阶段2 卸载驱动并真实退出 → 断言 →
#                -Restore 恢复 → 断言（用户服务被产品防篡改拦截 SCM 启动属预期：
#                允许"Running 或 Stopped 且 Start 已还原"，待重启自启）→ 报告
#    Check 阶段：再重启一次后运行 → 核对全部组件已随开机自启复原 → 闭环结论
#
#  实测机制（2026-10-17）：产品把防篡改挂钩驻留在 services.exe 进程内，本开机内
#  拒绝经 SCM start/stop 其 5 个用户服务（驱动卸载/组件被杀后仍存活）；重启后
#  消失，开机自启路径不受影响 → Post 部分恢复属预期，Check 阶段完成闭环。
#
#  用法：verify.cmd            → Pre
#        verify.cmd post       → Post（第一次重启后）
#        verify.cmd check      → Check（第二次重启后，最终核对）
#        本脚本 -Stage Pre|Post|Check [-Plan]；-Plan 只打印说明（无需管理员）
#  引擎：显式 powershell.exe（Windows PowerShell 5.1），不依赖 PATH 的 pwsh
# =====================================================================
param(
    [ValidateSet('Pre','Post','Check')][string]$Stage = 'Pre',
    [switch]$Plan
)
$ErrorActionPreference = 'Continue'
$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ctl        = Join-Path $Root 'mjbwctl.ps1'
$BackupFile = Join-Path $Root 'state_backup.json'
$DriverKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\zfprotect'
$UserServices = @('zfhookupdat','itxcltserver','zfnetchkclient','ZFICONTROL','ZFFTSSERVER')
$AllServices  = @('zfprotect','super') + $UserServices
$ProcNames    = @('zhp.exe','zfhookupdat.exe','itxsvc.exe','itxtray.exe','ZFIControl.exe',
                  'ZFIDataServer.exe','ZFIFileContent.exe','ZFIUpdateServer.exe')

if ($Plan) {
    Write-Host '===== 闭环验证器 v3 · 干跑说明 ====='
    Write-Host '  Pre：运行 -ExitOneTime -Yes（预期只做：备份+置 unload=1+提示重启），断言：备份存在、unload=1、5 个用户服务仍在运行、无 MJBW_KeepOff 任务、驱动仍在运行。'
    Write-Host '  Post（第一次重启后）：再次 -ExitOneTime -Yes（预期：fltmc/sc 卸载驱动 → SCM 停服务被拒 → 清进程兜底），断言驱动 Stopped、5 服务 Stopped、进程=0；'
    Write-Host '       随后 -Restore -Yes，断言：驱动 Running、Start 与备份一致（全部 7 项）、unload 还原、无任务、恢复结论行如实；'
    Write-Host '       5 个用户服务 Running 或（被产品防篡改拦截 SCM 启动时）Stopped 且 Start 已还原——属预期，待重启自启。'
    Write-Host '  Check（第二次重启后）：核对 5 服务 Running、驱动 Running、Start 与备份一致、unload 缺省、无任务、进程回归 → 三阶段闭环。'
    Write-Host '  三阶段均 PASS 才算协议闭环验证通过。'
    return
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-State {
    $svcs = @()
    foreach ($n in $AllServices) {
        $g   = Get-Service -Name $n -ErrorAction SilentlyContinue
        $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $n) -ErrorAction SilentlyContinue
        $svcs += [pscustomobject]@{ Name = $n; Status = "$($g.Status)"; Start = [int]$reg.Start }
    }
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ($ProcNames -contains $_.Name) -or ("{0}" -f $_.ExecutablePath) -match 'Intax|ZfHook|zfi' })
    $un   = (Get-ItemProperty -LiteralPath $DriverKey -Name 'unload' -ErrorAction SilentlyContinue).'unload'
    $task = [bool](Get-ScheduledTask -TaskName 'MJBW_KeepOff' -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Services = $svcs; ProcCount = $procs.Count; Unload = ("{0}" -f $un); Task = $task }
}

$Script:Assertions = @()
function Assert {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $Script:Assertions += [pscustomobject]@{ 断言 = $Name; 结果 = ($(if ($Ok) {'PASS'} else {'FAIL'})); 说明 = $Detail }
    $color = 'Green'; if (-not $Ok) { $color = 'Red' }
    Write-Host ("  [{0}] {1}  {2}" -f ($(if ($Ok) {'PASS'} else {'FAIL'})), $Name, $Detail) -ForegroundColor $color
    return $Ok
}

function Save-Report {
    param([string[]]$RawOutputs)
    $ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $Root ("verify_result_{0}_{1}.md" -f $ts, $Stage.ToLower())
    $pass = @($Script:Assertions | Where-Object { $_.结果 -eq 'PASS' }).Count
    $all  = @($Script:Assertions).Count
    $verdict = 'FAIL'; if ($all -gt 0 -and $pass -eq $all) { $verdict = 'PASS' }
    $L = @()
    $L += "# mjbwctl v3 闭环验证报告 · {0} 阶段" -f $Stage
    $L += ''
    $L += "- 时间：{0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $L += "- 机器：{0}" -f $env:COMPUTERNAME
    $L += "- PowerShell 引擎：Windows PowerShell {0}（显式 5.1，与交付物一致）" -f $PSVersionTable.PSVersion
    $L += "- 总结论：**{0}**（断言 {1}/{2} 通过）" -f $verdict, $pass, $all
    $L += ''
    $L += '## 断言明细'
    $L += ''
    $L += ($Script:Assertions | Format-Table -AutoSize | Out-String).TrimEnd()
    $L += ''
    $L += '## 关键状态（执行后）'
    $L += ''
    $s = Get-State
    foreach ($x in $s.Services) { $L += ("- {0,-15} 状态={1,-8} Start={2}" -f $x.Name, $x.Status, $x.Start) }
    $L += "- 目标进程数 = {0}" -f $s.ProcCount
    $L += "- unload 开关 = {0}" -f $s.Unload
    $L += "- MJBW_KeepOff 任务 = {0}" -f ($(if ($s.Task) {'存在'} else {'不存在'}))
    $L += ''
    $L += '## 控制器原始输出'
    for ($i = 0; $i -lt $RawOutputs.Count; $i++) {
        $L += ''
        $L += '### 输出 #{0}' -f ($i + 1)
        $L += '```'
        $L += "$($RawOutputs[$i])"
        $L += '```'
    }
    $L | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Host ''
    Write-Host ("报告已生成：{0}" -f $path) -ForegroundColor Cyan
    return $path
}

# ---- 提权 ----
if (-not (Test-Admin)) {
    Write-Host '需要管理员权限，正在请求 UAC 并以管理员身份重新启动…'
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File', ('"{0}"' -f $PSCommandPath), '-Stage', $Stage)
    Start-Process -FilePath 'powershell.exe' -ArgumentList $a -Verb RunAs
    return
}

switch ($Stage) {

'Pre' {
    Write-Host '===== 闭环验证 · Pre 阶段（预期只做：备份 + 置 unload=1，随后重启） =====' -ForegroundColor Cyan
    $before = Get-State
    $out = (& $Ctl -ExitOneTime -Yes 6>&1 | Out-String)
    Write-Host $out
    $after = Get-State

    Assert '备份文件存在' (Test-Path $BackupFile)
    Assert '驱动开关 unload = 1' ($after.Unload -eq '1') ("实际 = {0}" -f $after.Unload)
    Assert '输出包含「阶段 1/2 完成」' ($out -match '阶段 1/2 完成')
    $userRun = @($after.Services | Where-Object { $UserServices -contains $_.Name -and $_.Status -eq 'Running' }).Count
    Assert '5 个用户服务仍在运行（阶段1不停任何组件）' ($userRun -eq 5) ("实际 {0}/5" -f $userRun)
    $drv = ($after.Services | Where-Object { $_.Name -eq 'zfprotect' } | ForEach-Object { $_.Status })
    Assert 'zfprotect 仍在运行（卸载回调要重启后才有）' ("$drv" -eq 'Running') ("实际 = {0}" -f $drv)
    Assert '未创建 MJBW_KeepOff 任务（一次性退出不该建任务）' (-not $after.Task)

    $null = Save-Report @($out)
    Write-Host ''
    Write-Host '════════════════════════════════════════════════' -ForegroundColor Yellow
    Write-Host ' 下一步（重要）：' -ForegroundColor Yellow
    Write-Host '   1. 重启电脑（开关仅在驱动启动时生效）' -ForegroundColor Yellow
    Write-Host ('   2. 重启后运行：verify.cmd post（即 {0} -Stage Post）' -f $PSCommandPath) -ForegroundColor Yellow
    Write-Host '   3. Post 会自动完成：退出 → 断言 → 恢复 → 断言（用户服务被拦截属预期，标注待重启自启）' -ForegroundColor Yellow
    Write-Host '   4. 再重启一次电脑 → 运行 verify.cmd check 做最终核对（三阶段闭环）' -ForegroundColor Yellow
    Write-Host '════════════════════════════════════════════════' -ForegroundColor Yellow
}

'Post' {
    Write-Host '===== 闭环验证 · Post 阶段（重启后：真实退出 → 断言 → 恢复 → 断言） =====' -ForegroundColor Cyan
    $before = Get-State
    Write-Host ("前置状态：zfprotect={0}，unload={1}" -f (($before.Services | Where-Object { $_.Name -eq 'zfprotect' } | ForEach-Object { $_.Status })), $before.Unload)

    $out1 = (& $Ctl -ExitOneTime -Yes 6>&1 | Out-String)
    Write-Host $out1
    $mid = Get-State
    Write-Host '── 退出断言'
    Assert '输出包含「一次性退出完成」' ($out1 -match '一次性退出完成')
    Assert '输出不含「退出未完成」' (-not ($out1 -match '退出未完成'))
    $drv = ($mid.Services | Where-Object { $_.Name -eq 'zfprotect' } | ForEach-Object { $_.Status })
    Assert 'zfprotect 已停止（驱动已卸载）' ("$drv" -eq 'Stopped') ("实际 = {0}" -f $drv)
    $stopped = @($mid.Services | Where-Object { $UserServices -contains $_.Name -and $_.Status -eq 'Stopped' }).Count
    Assert '5 个用户服务全部 Stopped' ($stopped -eq 5) ("实际 {0}/5" -f $stopped)
    Assert '目标进程清零' ($mid.ProcCount -eq 0) ("实际 = {0}" -f $mid.ProcCount)

    Write-Host '── 恢复断言（运行 -Restore -Yes）'
    $out2 = (& $Ctl -Restore -Yes 6>&1 | Out-String)
    Write-Host $out2
    $after = Get-State
    $bk = $null
    if (Test-Path $BackupFile) { $bk = Get-Content -LiteralPath $BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json }
    Assert '备份可读（恢复断言的对照基准）' ($null -ne $bk)
    Assert '恢复输出不含「启动失败」（被拦截应标 [SCM拒绝]）' (-not ($out2 -match '启动失败'))
    Assert '恢复输出含最终结论行（✔ 恢复完成 / △ 部分恢复 / △ 恢复完成度）' ($out2 -match '(✔ 恢复完成|△ 部分恢复|△ 恢复完成度)')
    $runOk = @($after.Services | Where-Object { $UserServices -contains $_.Name -and $_.Status -eq 'Running' }).Count
    $pendOk = 0
    if ($bk) {
        foreach ($n in $UserServices) {
            $cur  = $after.Services | Where-Object { $_.Name -eq $n }
            $orig = $bk.services | Where-Object { $_.Name -eq $n }
            if ($orig -and $cur -and $cur.Status -eq 'Stopped' -and $cur.Start -eq [int]$orig.StartDword) { $pendOk++ }
        }
    }
    Assert '5 个用户服务：Running 或（被防篡改拦截）Stopped 且 Start 已还原' (($runOk + $pendOk) -eq 5) ("Running {0}/5 + 待重启自启 {1}/5" -f $runOk, $pendOk)
    $drv2 = ($after.Services | Where-Object { $_.Name -eq 'zfprotect' } | ForEach-Object { $_.Status })
    Assert 'zfprotect 恢复 Running（驱动重新加载）' ("$drv2" -eq 'Running') ("实际 = {0}" -f $drv2)
    Assert 'unload 开关已还原（缺省）' ($after.Unload -eq '' -or $after.Unload -eq '0') ("实际 = {0}" -f $after.Unload)
    Assert 'MJBW_KeepOff 任务不存在' (-not $after.Task)
    $startOk = 0
    if ($bk) { foreach ($s in $after.Services) { $orig = $bk.services | Where-Object { $_.Name -eq $s.Name }; if ($orig -and $s.Start -eq [int]$orig.StartDword) { $startOk++ } } }
    Assert '7 个服务 Start 全部与备份一致' ($startOk -eq 7) ("实际 {0}/7" -f $startOk)
    Assert '目标进程：全部回归（≥8）或待重启自启（≤1）' ($after.ProcCount -ge 8 -or $after.ProcCount -le 1) ("实际 = {0}" -f $after.ProcCount)

    $null = Save-Report @($out1, $out2)
    $pass = @($Script:Assertions | Where-Object { $_.结果 -eq 'PASS' }).Count
    $all  = @($Script:Assertions).Count
    Write-Host ''
    if ($pass -eq $all) { Write-Host '✔ Post 阶段通过：退出全链路成立 + 恢复项还原正确。用户服务若标注"待重启自启"，属产品防篡改拦截，为预期。' -ForegroundColor Green }
    else { Write-Host ('✘ Post 阶段 {0}/{1} 断言通过，未闭环。请把报告发给维护者。' -f $pass, $all) -ForegroundColor Red }
    Write-Host '════════════════════════════════════════════════' -ForegroundColor Yellow
    Write-Host ' 下一步（重要）：' -ForegroundColor Yellow
    Write-Host '   1. 再重启一次电脑（用户服务随开机自启回归）' -ForegroundColor Yellow
    Write-Host ('   2. 重启后运行：verify.cmd check（即 {0} -Stage Check）→ 三阶段闭环结论' -f $PSCommandPath) -ForegroundColor Yellow
    Write-Host '════════════════════════════════════════════════' -ForegroundColor Yellow
}

'Check' {
    Write-Host '===== 闭环验证 · Check 阶段（第二次重启后：核对全部组件已随开机自启复原） =====' -ForegroundColor Cyan
    $after = Get-State
    $bk = $null
    if (Test-Path $BackupFile) { $bk = Get-Content -LiteralPath $BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json }
    Assert '备份文件仍存在（本核对依据备份）' ($null -ne $bk)
    if ($bk) {
        $try = 0
        $runOk = 0
        $drvOk = $false
        while ($try -lt 6) {
            $after = Get-State
            $runOk = @($after.Services | Where-Object { $UserServices -contains $_.Name -and $_.Status -eq 'Running' }).Count
            $drvOk = ("$((($after.Services | Where-Object { $_.Name -eq 'zfprotect' }) | ForEach-Object { $_.Status }))" -eq 'Running')
            if ($runOk -eq 5 -and $drvOk) { break }
            $try++
            Start-Sleep -Seconds 10
        }
        Assert '5 个用户服务已随开机自启 Running' ($runOk -eq 5) ("实际 {0}/5（含最多 60 秒等待）" -f $runOk)
        Assert 'zfprotect 运行中（生产模式）' $drvOk ("实际 = {0}" -f $drvOk)
        $startOk = 0
        foreach ($s in $after.Services) { $orig = $bk.services | Where-Object { $_.Name -eq $s.Name }; if ($orig -and $s.Start -eq [int]$orig.StartDword) { $startOk++ } }
        Assert '7 个服务 Start 与备份一致' ($startOk -eq 7) ("实际 {0}/7" -f $startOk)
        Assert 'unload 开关保持缺省（生产模式）' ($after.Unload -eq '' -or $after.Unload -eq '0') ("实际 = {0}" -f $after.Unload)
        Assert 'MJBW_KeepOff 任务不存在' (-not $after.Task)
        $need = @($bk.processes).Count
        if ($need -lt 8) { $need = 8 }
        Assert '目标进程已回归（≥ 备份时数量，且 ≥8）' ($after.ProcCount -ge $need) ("实际 {0}（基准 {1}）" -f $after.ProcCount, $need)
    }
    $null = Save-Report @()
    $pass = @($Script:Assertions | Where-Object { $_.结果 -eq 'PASS' }).Count
    $all  = @($Script:Assertions).Count
    Write-Host ''
    if ($pass -eq $all) { Write-Host '✔ 三阶段闭环验证全部通过：开关→重启→卸载→退出→恢复→重启自启 全链路成立。' -ForegroundColor Green }
    else { Write-Host ('✘ Check 阶段 {0}/{1} 断言通过，未闭环。请把报告发给维护者。' -f $pass, $all) -ForegroundColor Red }
}
}
