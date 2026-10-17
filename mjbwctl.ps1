# =====================================================================
#  mjbwctl.ps1 —— 中孚密保卫士 控制器（安全退出 / 恢复 / 状态）
#
#  功能：
#    -Status         查看当前状态（只读，无需管理员）
#    -ExitOneTime    一次性安全退出（两阶段）：第1次运行置位驱动卸载开关(unload=1)并提示重启；
#                    重启后再次运行完成卸载驱动+停止全部组件（不改启动类型，
#                    再下次开机整套系统随开机自启自动恢复）
#    -ExitKeepOff    持续退出：停止全部组件 + 禁用服务自启动 + 创建开机计划任务
#                    MJBW_KeepOff，每次开机自动执行退出并保持退出
#    -ScheduleExit   仅预约：本次开机不动（仅禁 zfprotect/super 自启+置开关+建任务），
#                    下次开机自动执行退出并保持退出
#    -ReassertExit   开机重断言（由 MJBW_KeepOff 计划任务以 SYSTEM 调用，勿手动使用）
#    -Restore        恢复正常运行：按 state_backup.json 还原服务启动类型并逐个启动
#    -Interactive    中文菜单（双击 mjbwctl.cmd 进入）
#    -Yes            跳过确认提示（计划任务/命令行自动化用）
#    -Plan           干跑：只打印将要执行的动作，不做任何修改（无需管理员）
#    -ForceBackup    退出时强制重新快照现场（默认保护最早原始备份不覆盖）
#
#  安全设计：
#    * 备份优先：任何修改前先把现场快照存入 state_backup.json（保留历史副本至多 5 份）
#    * 只改服务状态（Start/停止/启动），绝不删除产品文件、绝不删除产品注册表键
#    * 驱动开关协议（逆向结论）：zfprotect64.sys 生产模式无卸载回调；在其服务键写 unload=1
#      并重启后，驱动将带卸载回调启动，可用 fltmc/sc 停止。开关仅在驱动启动时读取。
#      实测：驱动在场时停服务被拒/杀进程被拒/改服务配置被拦（procGuard/服务处理器/注册表回调）
#    * 全程日志：logs\yyyyMMdd_HHmmss_动作.log
#  兼容性：Windows PowerShell 5.1（文件为 UTF-8 BOM 编码）
# =====================================================================

param(
    [switch]$Status,
    [switch]$ExitOneTime,
    [switch]$ExitKeepOff,
    [switch]$ScheduleExit,
    [switch]$Restore,
    [switch]$ReassertExit,
    [switch]$Interactive,
    [switch]$Yes,
    [switch]$Plan,
    [switch]$ForceBackup
)

$ErrorActionPreference = 'Continue'
$Script:Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:LogDir     = Join-Path $Script:Root 'logs'
$Script:BackupFile = Join-Path $Script:Root 'state_backup.json'
$Script:LogFile    = $null

# 记录启动参数（自提权时原样重放）
$Script:ArgList = @()
foreach ($k in $PSBoundParameters.Keys) { $Script:ArgList += ('-' + $k) }

# ---------------- 常量（逆向侦察结论，详见 docs\ANALYSIS.md） ----------------
$Script:PathPattern    = 'Intax|ZfHook|zfi|patchclient'
# 受管服务：全部持久化面只有这 7 个服务（无计划任务/Run键/WMI订阅）
$Script:ManagedServices = @('zfprotect','super','zfhookupdat','itxcltserver','zfnetchkclient','ZFICONTROL','ZFFTSSERVER')
# 持续退出时需要禁用自启动的服务（super 本来就停着，不动它）
$Script:DisableOnKeepOff = @('zfprotect','zfhookupdat','itxcltserver','zfnetchkclient','ZFICONTROL','ZFFTSSERVER')
# 停止顺序：父服务先断、依赖者先停（zfnetchkclient 依赖 itxcltserver）
$Script:StopOrder   = @('zfhookupdat','ZFICONTROL','zfnetchkclient','itxcltserver','ZFFTSSERVER','zfprotect','super')
# 恢复启动顺序：驱动先行，主客户端在 netchk 之前
$Script:RestoreOrder = @('zfprotect','itxcltserver','zfnetchkclient','zfhookupdat','ZFICONTROL','ZFFTSSERVER')
# 已知进程名单
$Script:KnownProcesses = @('zhp.exe','zfhookupdat.exe','itxsvc.exe','itxtray.exe','ZFIControl.exe',
                           'ZFIDataServer.exe','ZFIFileContent.exe','ZFIUpdateServer.exe',
                           'Secpolx32.exe','Secpolx64.exe','notifyserver.exe')
$Script:KeepOffTask = 'MJBW_KeepOff'
$Script:StartWords  = @('boot','system','auto','demand','disabled')
# 驱动开关面板（逆向结论：zfprotect64.sys 仅在 DriverEntry 启动时读取自身服务键的这些值；
# 详细语义见 README「驱动开关协议」一节）
$Script:DriverKey      = 'HKLM:\SYSTEM\CurrentControlSet\Services\zfprotect'
$Script:DriverSwitches = @('unload','Monitor Registry','Process Protect','Disable Filtering',
                           'Disable FileHide','ServProtect','Build CommPort','Load Image Notify',
                           'Process Create Notify Routine','MajorFunc Mask','Concerned FileSystem')
$Script:LastScError = ''

# ---------------- 日志 ----------------
function Start-Log {
    param([string]$Action)
    if (-not (Test-Path -LiteralPath $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }
    $Script:LogFile = Join-Path $Script:LogDir ("{0}_{1}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Action)
}
function Write-Info {
    param([string]$Msg)
    Write-Host $Msg
    if ($Script:LogFile) {
        Add-Content -LiteralPath $Script:LogFile -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg) -Encoding UTF8
    }
}

# ---------------- 权限 ----------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-SelfElevate {
    # 用管理员身份重新拉起自身，保留全部启动参数
    $args2 = @('-NoProfile','-ExecutionPolicy','Bypass','-File', ('"{0}"' -f $PSCommandPath))
    $args2 += $Script:ArgList
    Start-Process -FilePath 'powershell.exe' -ArgumentList $args2 -Verb RunAs
}

# ---------------- 实体发现（动态，防企业后续策略变化新增持久化点） ----------------
function Get-TargetServices {
    $list = @()
    $cim = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { ($_.PathName -match $Script:PathPattern) -or ($Script:ManagedServices -contains $_.Name) }
    foreach ($s in $cim) {
        $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $s.Name) -ErrorAction SilentlyContinue
        $list += [pscustomobject]@{
            Name = $s.Name; Status = $s.State
            StartDword = [int]$reg.Start; Delayed = [int]$reg.DelayedAutoStart; Path = $s.PathName
        }
    }
    # 内核驱动服务 Win32_Service 可能不列，逐个补查
    foreach ($n in @('zfprotect','super')) {
        if (-not ($list | Where-Object { $_.Name -eq $n })) {
            $g = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($g) {
                $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $n) -ErrorAction SilentlyContinue
                $list += [pscustomobject]@{
                    Name = $n; Status = "$($g.Status)"
                    StartDword = [int]$reg.Start; Delayed = [int]$reg.DelayedAutoStart; Path = $reg.ImagePath
                }
            }
        }
    }
    return $list
}
function Get-TargetProcesses {
    $wp = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { ($Script:KnownProcesses -contains $_.Name) -or ($_.ExecutablePath -match $Script:PathPattern) }
    return ($wp | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Id = $_.ProcessId; Path = $_.ExecutablePath; Cmd = $_.CommandLine }
    })
}
function Get-TargetTasks {
    return (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        ($_.Actions | Where-Object { $_.Execute -match $Script:PathPattern })
    } | ForEach-Object { [pscustomobject]@{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State } })
}
function Get-TargetRunKeys {
    $out = @()
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $p = Get-ItemProperty $k
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS' -and ("{0}" -f $prop.Value) -match $Script:PathPattern) {
                    $out += [pscustomobject]@{ Key = $k; Name = $prop.Name; Value = "{0}" -f $prop.Value }
                }
            }
        }
    }
    return $out
}

# ---------------- 备份 ----------------
function New-Snapshot {
    return [pscustomobject]@{
        timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        computer  = $env:COMPUTERNAME
        services  = @(Get-TargetServices)
        processes = @(Get-TargetProcesses)
        tasks     = @(Get-TargetTasks)
        runKeys   = @(Get-TargetRunKeys)
        driverSwitches = @(Get-DriverSwitches)
    }
}
function Save-Backup {
    param($Snap)
    if (Test-Path -LiteralPath $Script:BackupFile) {
        $hist = Join-Path $Script:Root ('state_backup_{0}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Copy-Item -LiteralPath $Script:BackupFile -Destination $hist -Force
        Get-ChildItem -Path (Join-Path $Script:Root 'state_backup_*.json') -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    $Snap | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Script:BackupFile -Encoding UTF8
    Write-Info ("已保存现场快照 → {0}" -f $Script:BackupFile)
}
function Load-Backup {
    if (Test-Path -LiteralPath $Script:BackupFile) {
        return (Get-Content -LiteralPath $Script:BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    return $null
}

# ---------------- 确认 ----------------
function Confirm-Action {
    param([string]$Title, [string]$Detail)
    if ($Script:Yes) { return $true }
    Write-Host ''
    Write-Host ('== ' + $Title) -ForegroundColor Yellow
    Write-Host $Detail
    $a = Read-Host '输入 Y 确认执行，其他任意键取消'
    return ($a -eq 'Y' -or $a -eq 'y')
}

# ---------------- 服务 Start 修改（sc.exe，支持 0-4 全部类型；捕获错误文本） ----------------
function Set-ServiceStartDword {
    param([string]$Name, [int]$Dword)
    $word = $Script:StartWords[$Dword]
    if (-not $word) { return $false }
    $Script:LastScError = ''
    $out = (& sc.exe config $Name start= $word 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { $Script:LastScError = $out; return $false }
    return $true
}

# ---------------- 驱动开关面板（逆向结论：仅驱动启动时读取） ----------------
function Get-DriverSwitchValue {
    param([string]$Name)
    $v = (Get-ItemProperty -LiteralPath $Script:DriverKey -Name $Name -ErrorAction SilentlyContinue).$Name
    return $v
}
function Get-DriverSwitches {
    $out = @()
    foreach ($n in $Script:DriverSwitches) {
        $v = Get-DriverSwitchValue $n
        $out += [pscustomobject]@{ Name = $n; Present = ($null -ne $v); Value = [int]$v }
    }
    return $out
}
function Set-DriverSwitch {
    param([string]$Name, [int]$Value)
    try {
        New-ItemProperty -Path $Script:DriverKey -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Info ("  [失败] 写入开关 {0}={1}：{2}" -f $Name, $Value, $_.Exception.Message)
        return $false
    }
    $chk = Get-DriverSwitchValue $Name
    if ("$chk" -eq "$Value") { return $true }
    Write-Info ("  [失败] 开关 {0} 写入后读回不一致（读到 {1}）" -f $Name, $chk)
    return $false
}
function Stop-ZfProtect {
    # 前提：unload=1（驱动带卸载回调）。fltmc 卸载过滤 + sc 停服务（ZwUnloadDriver）双保险
    $txt = @()
    $out1 = (& fltmc.exe unload zfprotect 2>&1 | Out-String).Trim()
    $txt += $out1
    Start-Sleep -Seconds 2
    $out2 = (& sc.exe stop zfprotect 2>&1 | Out-String).Trim()
    $txt += $out2
    Start-Sleep -Seconds 2
    $st = (Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue).Status
    if ("$st" -eq 'Stopped') { Write-Info '  [OK] zfprotect 已停止（驱动已卸载）'; return $true }
    $errText = ($txt -join ' | ')
    Write-Info ("  [失败] 驱动卸载后状态仍为 {0}" -f $st)
    Write-Info ("         原始输出：{0}" -f $errText)
    return $false
}
function Invoke-DriverPhase {
    # 返回 'stopped'（驱动已停/不存在，可继续阶段2）| 'armed'（开关已置位，需重启）
    # | 'aborted'（失败，须中止）
    $drv = Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue
    if (-not $drv) { Write-Info '  [驱动] zfprotect 服务不存在'; return 'stopped' }
    if ($drv.Status -ne 'Running') { Write-Info ("  [驱动] zfprotect 当前 {0}（未在运行）" -f $drv.Status); return 'stopped' }
    $un = Get-DriverSwitchValue 'unload'
    if ("$un" -eq '1') {
        Write-Info '  [驱动] 卸载开关已置位（unload=1），尝试卸载…'
        if (Stop-ZfProtect) { return 'stopped' }
        return 'aborted'
    }
    Write-Info '  [驱动] 生产模式（无卸载回调）。实测：驱动在场时停服务被拒/杀进程被拒/改服务配置被拦。'
    if (Set-DriverSwitch -Name 'unload' -Value 1) {
        Write-Info '  [OK] 已置位卸载开关（重启后驱动将带卸载回调启动）'
        return 'armed'
    }
    return 'aborted'
}

# ---------------- 诚实化辅助：停止动作必须验证真实结果 ----------------
function Stop-ServiceVerified {
    param([string]$Name)
    $err = $null
    try { Stop-Service -Name $Name -Force -ErrorAction Stop } catch { $err = ("{0}" -f $_.Exception.Message) }
    Start-Sleep -Milliseconds 500
    $st = "$((Get-Service -Name $Name -ErrorAction SilentlyContinue).Status)"
    if ($st -eq 'Stopped') {
        Write-Info ("  [停止服务] {0} → 已停止" -f $Name)
        return $true
    }
    if ($err -match 'Cannot open .* service on computer') {
        Write-Info ("  [SCM拒绝] {0}：产品防篡改拦截 SCM 停止（驻留 services.exe，本开机内持续），将由清进程兜底" -f $Name)
        return $false
    }
    Write-Info ("  [失败] {0} 停止后仍为 {1}" -f $Name, $st)
    if ($err) { Write-Info ("         原因：{0}" -f $err) }
    return $false
}
function Start-ServiceVerified {
    param([string]$Name)
    $err = $null
    try { Start-Service -Name $Name -ErrorAction Stop } catch { $err = ("{0}" -f $_.Exception.Message) }
    Start-Sleep -Milliseconds 800
    $st = "$((Get-Service -Name $Name -ErrorAction SilentlyContinue).Status)"
    if ($st -eq 'Running') {
        Write-Info ("  [启动服务] {0} → 运行中" -f $Name)
        return $true
    }
    if ($err -match 'Cannot open .* service on computer') {
        Write-Info ("  [SCM拒绝] {0}：产品防篡改拦截 SCM 启动（驻留 services.exe，本开机内持续，重启后自愈）" -f $Name)
    } else {
        Write-Info ("  [启动失败] {0}：调用后仍为 {1}" -f $Name, $st)
        if ($err) { Write-Info ("         原因：{0}" -f $err) }
    }
    return $false
}
function Stop-ProcessVerified {
    param([int]$Id, [string]$Name)
    $err = $null
    try { Stop-Process -Id $Id -Force -ErrorAction Stop } catch { $err = ("{0}" -f $_.Exception.Message) }
    Start-Sleep -Milliseconds 300
    if ($err -and (Get-Process -Id $Id -ErrorAction SilentlyContinue)) {
        Write-Info ("  [失败] {0} (pid={1}) 终止被拒绝：{2}" -f $Name, $Id, $err)
    }
    return $null -eq $err
}
function Test-ExitSuccess {
    $leftProc = @(Get-TargetProcesses)
    $leftSvc  = @(Get-TargetServices | Where-Object {
        ($Script:ManagedServices -contains $_.Name) -and $_.Name -ne 'zfprotect' -and $_.Name -ne 'super' -and $_.Status -eq 'Running' })
    $drv = "$((Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue).Status)"
    return [pscustomobject]@{ Procs = $leftProc.Count; Svc = $leftSvc.Count; Driver = $drv }
}

# ---------------- MJBW_KeepOff 计划任务 ----------------
function New-KeepOffTask {
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -ReassertExit -Yes' -f $PSCommandPath)
    $trg = New-ScheduledTaskTrigger -AtStartup
    $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $Script:KeepOffTask -Action $act -Trigger $trg -Principal $prn -Force -ErrorAction Stop | Out-Null
}
function Test-KeepOffTask {
    return [bool](Get-ScheduledTask -TaskName $Script:KeepOffTask -ErrorAction SilentlyContinue)
}
function Remove-KeepOffTask {
    if (Test-KeepOffTask) {
        Unregister-ScheduledTask -TaskName $Script:KeepOffTask -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Merge-BackupRuntimeItems {
    # KeepOff 专用：把"备份之后新出现"的计划任务/Run 键并入原始快照，
    # 保证 Restore 有据可还原；服务字段保持最早原始值不动。
    $b = Load-Backup
    if (-not $b) { return }
    $b.tasks   = @($b.tasks)
    $b.runKeys = @($b.runKeys)
    $dirty = $false
    foreach ($t in (Get-TargetTasks)) {
        $hit = @($b.tasks | Where-Object { ("{0}" -f $_.TaskPath) -eq ("{0}" -f $t.TaskPath) -and ("{0}" -f $_.TaskName) -eq ("{0}" -f $t.TaskName) })
        if ($hit.Count -eq 0) { $b.tasks += $t; $dirty = $true }
    }
    foreach ($rk in (Get-TargetRunKeys)) {
        $hit = @($b.runKeys | Where-Object { ("{0}" -f $_.Key) -eq ("{0}" -f $rk.Key) -and ("{0}" -f $_.Name) -eq ("{0}" -f $rk.Name) })
        if ($hit.Count -eq 0) { $b.runKeys += $rk; $dirty = $true }
    }
    if ($dirty) {
        $b | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Script:BackupFile -Encoding UTF8
        Write-Info '  [备份合并] 新增的计划任务/Run 键已并入原始快照（服务状态保持原值）'
    }
}

# ---------------- 停止序列（退出/重断言共用；需管理员；前置条件：驱动已停止） ----------------
function Invoke-StopSequence {
    Write-Info '── [1/3] 按依赖与父子顺序停止服务'
    foreach ($n in $Script:StopOrder) {
        if ($n -eq 'zfprotect') { continue }   # 驱动由 Invoke-DriverPhase 处理
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($svc.Status -ne 'Running') { Write-Info ("  [跳过] {0}（未在运行）" -f $n); continue }
        $null = Stop-ServiceVerified -Name $n
    }
    Write-Info '── [2/3] 清理残留进程（注入宿主/托盘/检查组件）'
    $procs = Get-TargetProcesses
    foreach ($p in $procs) {
        Write-Info ("  [结束进程] {0} (pid={1})" -f $p.Name, $p.Id)
        $null = Stop-ProcessVerified -Id $p.Id -Name $p.Name
    }
    Write-Info '── [3/3] 复查（防看门狗拉起，最多3轮×5秒）'
    for ($i = 1; $i -le 3; $i++) {
        Start-Sleep -Seconds 5
        $again = Get-TargetProcesses
        $dirty = $false
        foreach ($p in $again) {
            $dirty = $true
            Write-Info ("  [复查-结束] {0} (pid={1})" -f $p.Name, $p.Id)
            $null = Stop-ProcessVerified -Id $p.Id -Name $p.Name
        }
        foreach ($n in $Script:StopOrder) {
            if ($n -eq 'zfprotect') { continue }
            $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $dirty = $true
                $null = Stop-ServiceVerified -Name $n
            }
        }
        if (-not $dirty) { Write-Info ('  [复查] 第 {0} 轮：已无残留' -f $i); break }
    }
    $leftProc = @(Get-TargetProcesses)
    $leftSvc  = @(Get-TargetServices | Where-Object {
        ($Script:ManagedServices -contains $_.Name) -and $_.Name -ne 'zfprotect' -and $_.Name -ne 'super' -and $_.Status -eq 'Running' })
    if ($leftProc.Count -eq 0 -and $leftSvc.Count -eq 0) { return $true }
    Write-Info ("  [终态] 仍有 {0} 个服务运行 / {1} 个进程存活 → 退出未完成" -f $leftSvc.Count, $leftProc.Count)
    return $false
}

# ---------------- 目标校验 ----------------
function Test-TargetsExist {
    $svc = Get-TargetServices
    $prc = Get-TargetProcesses
    if (-not $svc -and -not $prc) {
        Write-Info '未在本机发现任何密保卫士组件（服务/进程），拒绝执行。'
        return $false
    }
    return $true
}

# ---------------- 退出（两种模式；两阶段：开关→重启→卸载驱动后真实退出） ----------------
function Invoke-Exit {
    param([bool]$KeepOff)
    if (-not (Test-TargetsExist)) { return }
    $modeName = '一次性安全退出（两阶段：置开关→重启→完成退出）'
    if ($KeepOff) { $modeName = '持续退出（两阶段：置开关/禁驱自启→重启→开机任务保持退出）' }
    $detail = @"
即将执行：$modeName
  · 【实测结论】驱动在场时：停服务被拒、杀进程被拒、改服务配置被拦（三层防护）
  · 阶段1（本次运行）：备份现场 + 在驱动服务键写入 unload=1 卸载开关
  · 重启一次（开关只在驱动启动时生效）
  · 阶段2（重启后再次运行本命令）：卸载驱动 → 停止服务与进程（此时全部可行）
  · 现场快照存入 state_backup.json，随时 -Restore 一键恢复
"@
    if ($KeepOff) {
        $detail += "  · 另加：禁用 zfprotect/super 自启（写入实测可行）+ 创建开机任务 $Script:KeepOffTask`n    （重启后由任务自动完成剩余 5 个服务自启禁用与退出，保持退出状态）"
    } else {
        $detail += "  · 不修改任何启动类型 → 再下次开机整套系统自动恢复"
    }
    if (-not (Confirm-Action $modeName $detail)) { Write-Info '已取消。'; return }

    # 备份：默认保护最早原始快照不被覆盖
    if ($ForceBackup -or -not (Test-Path -LiteralPath $Script:BackupFile)) {
        Save-Backup (New-Snapshot)
    } else {
        Write-Info ('已存在原始快照（{0}），继续沿用；需要重拍请加 -ForceBackup' -f $Script:BackupFile)
    }

    Write-Info '── [驱动阶段]'
    $ph = Invoke-DriverPhase
    if ($ph -eq 'aborted') {
        Write-Info ''
        Write-Info '✘ 驱动阶段失败，已中止（以上为真实原因，未做任何美化）。可先运行 -Status 查看。'
        return
    }
    if ($ph -eq 'armed') {
        Write-Info ''
        Write-Info '✔ 阶段 1/2 完成：卸载开关已置位（unload=1）。'
        Write-Info ("  下一步：重启电脑 → 重新运行：{0} -ExitOneTime 完成阶段 2" -f $PSCommandPath)
        Write-Info '  说明：驱动生产模式无卸载回调，本会话内退出实测不可行；开关重启后才生效。'
        if ($KeepOff) {
            Write-Info '── 持续退出阶段1附加项（均为实测可行操作）'
            foreach ($n in @('zfprotect','super')) {
                if (Set-ServiceStartDword -Name $n -Dword 4) { Write-Info ("  [禁用自启] {0} → Start=4" -f $n) }
                else { Write-Info ("  [失败] 禁用 {0}：{1}" -f $n, $Script:LastScError) }
            }
            Merge-BackupRuntimeItems
            try {
                New-KeepOffTask
                Write-Info ("  [OK] 开机任务 {0} 已创建（重启后自动完成剩余退出并保持）" -f $Script:KeepOffTask)
            } catch {
                Write-Info ('  [失败] 计划任务创建失败：{0}' -f $_.Exception.Message)
            }
            Write-Info ('  重启后无需手动操作；手动运行 {0} -Restore 可撤销。' -f $PSCommandPath)
        }
        return
    }

    # ph == 'stopped'：驱动已停止/未运行 → 阶段2，真实的退出
    Write-Info '── [阶段 2/2] 驱动已就绪（已停止），执行真实退出'
    $clear = Invoke-StopSequence
    if ($KeepOff) {
        Write-Info '── 禁用受管服务自启动（Start → 4 Disabled）'
        foreach ($n in $Script:DisableOnKeepOff) {
            if (Get-Service -Name $n -ErrorAction SilentlyContinue) {
                if (Set-ServiceStartDword -Name $n -Dword 4) { Write-Info ("  [禁用自启] {0}" -f $n) }
                else { Write-Info ("  [失败] 禁用 {0}：{1}" -f $n, $Script:LastScError) }
            }
        }
        Merge-BackupRuntimeItems
        foreach ($t in (Get-TargetTasks)) {
            try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null; Write-Info ("  [禁用任务] {0}{1}" -f $t.TaskPath, $t.TaskName) } catch { }
        }
        foreach ($rk in (Get-TargetRunKeys)) {
            Remove-ItemProperty -Path $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue
            Write-Info ("  [移除启动项] {0}\{1}（内容已存备份）" -f $rk.Key, $rk.Name)
        }
        if (-not (Test-KeepOffTask)) {
            Write-Info ("── 创建开机计划任务 {0}（ONSTART / SYSTEM / 最高权限）" -f $Script:KeepOffTask)
            try { New-KeepOffTask; Write-Info ("  [OK] 下次开机将以 SYSTEM 身份自动保持退出（-ReassertExit）") }
            catch { Write-Info ('  [失败] 计划任务创建失败：{0}' -f $_.Exception.Message) }
        } else {
            Write-Info ("── 开机计划任务 {0} 已存在" -f $Script:KeepOffTask)
        }
    }
    $st = Test-ExitSuccess
    Write-Info ''
    if ($st.Procs -eq 0 -and $st.Svc -eq 0 -and $st.Driver -ne 'Running') {
        if ($KeepOff) { Write-Info ("✔ 持续退出完成（驱动已卸载、服务已停止、自启已禁用）。恢复：{0} -Restore" -f $PSCommandPath) }
        else { Write-Info ("✔ 一次性退出完成（驱动已卸载、服务已停止）。下次开机自动恢复；立即恢复驱动与开关：{0} -Restore（用户服务若被产品防篡改拦截 SCM 启动，重启后随开机自启回归）" -f $PSCommandPath) }
    } else {
        Write-Info ("✘ 退出未完成：服务运行 {0} 个 / 进程存活 {1} 个 / 驱动状态 {2}。请保留日志（logs\）供分析。" -f $st.Svc, $st.Procs, $st.Driver)
    }
}

# ---------------- 仅预约（本次不动，下次开机自动执行退出） ----------------
function Invoke-ScheduleExit {
    if (-not (Test-TargetsExist)) { return }
    $detail = @"
即将执行：仅预约下次开机自动执行退出（本次开机不做任何停止）
  · 本次会话所有组件继续正常运行（不停止任何服务/进程）
  · 禁用 zfprotect/super 自启（Start=4，实测此二键写入可行）
  · 写入驱动卸载开关 unload=1（开机任务兜底用）
  · 创建开机计划任务 $Script:KeepOffTask：下次开机（驱动缺席，写入全部可行）
    自动完成其余 5 个服务自启禁用 + 停止服务 + 清理进程并保持退出
  · 用户态 5 个服务键的禁用推迟到开机任务执行（驱动在场时写入被注册表保护拦截，实测）
  · 想撤销随时 -Restore
"@
    if (-not (Confirm-Action '预约下次开机自动执行退出' $detail)) { Write-Info '已取消。'; return }
    if ($ForceBackup -or -not (Test-Path -LiteralPath $Script:BackupFile)) {
        Save-Backup (New-Snapshot)
    } else {
        Write-Info ('已存在原始快照（{0}），继续沿用；需要重拍请加 -ForceBackup' -f $Script:BackupFile)
    }
    Write-Info '── 禁用驱动自启（zfprotect/super → Start=4，此二键写入实测可行）'
    foreach ($n in @('zfprotect','super')) {
        if (Set-ServiceStartDword -Name $n -Dword 4) { Write-Info ("  [禁用自启] {0} → Start=4" -f $n) }
        else { Write-Info ("  [失败] 禁用 {0}：{1}" -f $n, $Script:LastScError) }
    }
    if (Set-DriverSwitch -Name 'unload' -Value 1) { Write-Info '  [OK] 已写入驱动卸载开关 unload=1' }
    Merge-BackupRuntimeItems
    Write-Info ("── 创建开机计划任务 {0}（ONSTART / SYSTEM / 最高权限）" -f $Script:KeepOffTask)
    try {
        New-KeepOffTask
        Write-Info '  [OK] 下次开机将以 SYSTEM 身份自动执行退出并保持（-ReassertExit）'
    } catch {
        Write-Info ('  [失败] 计划任务创建失败：{0}' -f $_.Exception.Message)
    }
    Write-Info ''
    Write-Info ('✔ 预约完成。本次开机组件继续运行；下次开机起自动保持退出。随时可用 -Restore 撤销预约并恢复正常。')
}

# ---------------- 重断言（开机计划任务用，幂等；驱动 Start=4 时不会加载，以下含兜底） ----------------
function Invoke-ReassertExit {
    if (-not (Test-TargetsExist)) { return }
    for ($r = 1; $r -le 3; $r++) {
        Write-Info ("── 开机重断言 第 {0}/3 轮" -f $r)
        # 1) 驱动兜底：若被拉起且有卸载开关 → 先卸载（Start=4 后正常不会加载）
        $drv = Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue
        if ($drv -and $drv.Status -eq 'Running') {
            if ("$(Get-DriverSwitchValue 'unload')" -eq '1') {
                Write-Info '  [驱动] zfprotect 在运行，尝试卸载…'
                $null = Stop-ZfProtect
            } else {
                Write-Info '  [驱动] zfprotect 在运行且无卸载开关（异常，记录日志待查）'
            }
        }
        # 2) 禁自启（驱动缺席时 5 个用户服务键写入可行）
        foreach ($n in $Script:DisableOnKeepOff) {
            if (Get-Service -Name $n -ErrorAction SilentlyContinue) {
                if (-not (Set-ServiceStartDword -Name $n -Dword 4)) {
                    Write-Info ("  [失败] 禁用 {0}：{1}" -f $n, $Script:LastScError)
                }
            }
        }
        # 3) 停止服务 + 清理进程（诚实验证）
        $null = Invoke-StopSequence
        Merge-BackupRuntimeItems
        foreach ($t in (Get-TargetTasks)) {
            try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null; Write-Info ("  [禁用任务] {0}{1}" -f $t.TaskPath, $t.TaskName) } catch { }
        }
        foreach ($rk in (Get-TargetRunKeys)) {
            Remove-ItemProperty -Path $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue
            Write-Info ("  [移除启动项] {0}\{1}（内容已并入备份）" -f $rk.Key, $rk.Name)
        }
        $st = Test-ExitSuccess
        if ($st.Procs -eq 0 -and $st.Svc -eq 0 -and $st.Driver -ne 'Running') {
            Write-Info '── 重断言完成：无残留。'
            return
        }
        Start-Sleep -Seconds 5
    }
    $st = Test-ExitSuccess
    Write-Info ("── 重断言结束：仍有残留（服务 {0} / 进程 {1} / 驱动 {2}），已记录日志。" -f $st.Svc, $st.Procs, $st.Driver)
}

# ---------------- 恢复 ----------------
function Invoke-Restore {
    if (-not (Test-TargetsExist)) { return }
    $b = Load-Backup
    if (-not $b) {
        Write-Info ('没有找到备份文件 {0}，当前状态即默认状态，无需恢复。' -f $Script:BackupFile)
        return
    }
    if (-not (Confirm-Action '恢复正常运行' @"
将按备份还原：
  · 还原 7 个服务的启动类型（Start 原值，含 zfprotect=3）
  · 按顺序重新启动：zfprotect → itxcltserver → zfnetchkclient → zfhookupdat → ZFICONTROL → ZFFTSSERVER
  · 托盘 itxtray 若未被服务拉起将按备份路径补启
  · 重新启用备份中的计划任务、还原 Run 启动项（如有）
  · 删除开机计划任务 $Script:KeepOffTask
  · 最后输出核对表
"@)) { Write-Info '已取消。'; return }

    Write-Info '── [1/4] 还原服务启动类型（当前值即原值的跳过，避免无谓写入）'
    $drvRun = ("$((Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue).Status)" -eq 'Running')
    foreach ($s in $b.services) {
        if (-not (Get-Service -Name $s.Name -ErrorAction SilentlyContinue)) {
            Write-Info ("  [跳过] {0}（服务已不存在）" -f $s.Name)
            continue
        }
        $cur = (Get-TargetServices | Where-Object { $_.Name -eq $s.Name } | Select-Object -First 1)
        if ($cur -and ([int]$cur.StartDword -eq [int]$s.StartDword)) {
            Write-Info ("  [无需] {0} Start={1}（当前值即原值）" -f $s.Name, $s.StartDword)
        } else {
            $ok = Set-ServiceStartDword -Name $s.Name -Dword ([int]$s.StartDword)
            if ($ok) {
                Write-Info ("  [OK] {0} → Start={1} {2}" -f $s.Name, $s.StartDword, $Script:StartWords[[int]$s.StartDword])
            } elseif ($drvRun) {
                Write-Info ("  [失败] {0} → Start={1}：{2}" -f $s.Name, $s.StartDword, $Script:LastScError)
                Write-Info '         （驱动在场时改写用户服务键被注册表保护拦截属预期；重启后或卸载驱动后再执行即可）'
            } else {
                Write-Info ("  [失败] {0} → Start={1}：{2}" -f $s.Name, $s.StartDword, $Script:LastScError)
            }
        }
        if ($s.Delayed -eq 1) {
            Set-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $s.Name) -Name DelayedAutoStart -Value 1 -ErrorAction SilentlyContinue
        }
    }
    Write-Info '── [1.5/4] 还原驱动开关面板（按备份；先于服务启动，驱动实例按原配置加载）'
    $didSwitch = $false
    if ($b.driverSwitches) {
        foreach ($sw in @($b.driverSwitches)) {
            $nowVal = Get-DriverSwitchValue $sw.Name
            if ($sw.Present) {
                Set-ItemProperty -LiteralPath $Script:DriverKey -Name $sw.Name -Value ([int]$sw.Value) -ErrorAction SilentlyContinue
                Write-Info ("  [还原开关] {0} = {1}" -f $sw.Name, $sw.Value)
                $didSwitch = $true
            } elseif ($null -ne $nowVal) {
                Remove-ItemProperty -LiteralPath $Script:DriverKey -Name $sw.Name -ErrorAction SilentlyContinue
                Write-Info ("  [还原开关] {0} 已删除（恢复缺省）" -f $sw.Name)
                $didSwitch = $true
            }
        }
    }
    if (-not $didSwitch) {
        # 老备份无开关记录：只清卸载开关
        Remove-ItemProperty -LiteralPath $Script:DriverKey -Name 'unload' -ErrorAction SilentlyContinue
        Write-Info '  [还原开关] unload 已删除（恢复缺省生产模式）'
    }
    Write-Info '── [2/4] 按顺序启动服务（仅备份时在运行的；产品防篡改可能拒绝 SCM 启动，重启后自愈）'
    $startDenied = @()
    foreach ($n in $Script:RestoreOrder) {
        $orig = $b.services | Where-Object { $_.Name -eq $n }
        if ($orig -and $orig.Status -eq 'Running') {
            if (Start-ServiceVerified -Name $n) { continue }
            if (Get-Service -Name $n -ErrorAction SilentlyContinue) { $startDenied += $n }
        } elseif ($orig) {
            Write-Info ("  [跳过] {0}（备份时未运行，保持停止）" -f $n)
        }
    }
    Write-Info '── [2.5/4] 还原计划任务与 Run 启动项（按备份）'
    foreach ($t in @($b.tasks)) {
        if (("{0}" -f $t.State) -eq 'Disabled') {
            Write-Info ("  [跳过] 任务 {0}{1}（备份时即为禁用，保持原状）" -f $t.TaskPath, $t.TaskName)
            continue
        }
        if (Get-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction SilentlyContinue) {
            try {
                Enable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null
                Write-Info ("  [启用任务] {0}{1}" -f $t.TaskPath, $t.TaskName)
            } catch { Write-Info ("  [失败] 启用任务 {0}{1}" -f $t.TaskPath, $t.TaskName) }
        } else {
            Write-Info ("  [跳过] 任务 {0}{1} 已不存在" -f $t.TaskPath, $t.TaskName)
        }
    }
    foreach ($rk in @($b.runKeys)) {
        if (Test-Path -LiteralPath $rk.Key) {
            $exists = $null -ne (Get-ItemProperty -Path $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue)
            try {
                if ($exists) {
                    Set-ItemProperty -Path $rk.Key -Name $rk.Name -Value $rk.Value
                } else {
                    New-ItemProperty -Path $rk.Key -Name $rk.Name -Value $rk.Value -PropertyType String -Force | Out-Null
                }
                Write-Info ("  [还原启动项] {0}\{1}" -f $rk.Key, $rk.Name)
            } catch { Write-Info ("  [失败] 启动项 {0}\{1} 还原失败" -f $rk.Key, $rk.Name) }
        } else {
            Write-Info ("  [跳过] Run 键 {0} 已不存在" -f $rk.Key)
        }
    }
    Write-Info '── [3/4] 等待组件自愈（8秒）并补启托盘'
    Start-Sleep -Seconds 8
    $tray = $b.processes | Where-Object { $_.Name -eq 'itxtray.exe' } | Select-Object -First 1
    if ($tray -and $tray.Path -and -not (Get-Process -Name 'itxtray' -ErrorAction SilentlyContinue)) {
        try {
            Start-Process -FilePath ($tray.Path.Trim('"'))
            Write-Info '  [补启] itxtray 已按备份路径启动'
        } catch { Write-Info ('  [提示] itxtray 补启失败（{0}），注销重登即可' -f $_.Exception.Message) }
    }
    Remove-KeepOffTask
    Write-Info ("  [清理] 已删除计划任务 {0}（若存在）" -f $Script:KeepOffTask)
    Write-Info '── [4/4] 核对表'
    $rows = @()
    foreach ($s in $b.services) {
        $cur = Get-TargetServices | Where-Object { $_.Name -eq $s.Name }
        $curStatus = '-'
        $curStart  = '-'
        if ($cur) { $curStatus = "$($cur.Status)"; $curStart = "$($cur.StartDword)" }
        $match = '注意'
        if ($curStatus -eq "$($s.Status)" -and $curStart -eq "$([int]$s.StartDword)") { $match = '一致' }
        $rows += [pscustomobject]@{
            服务 = $s.Name; 备份状态 = $s.Status; 现状态 = $curStatus
            备份Start = [int]$s.StartDword; 现Start = $curStart; 结果 = $match
        }
    }
    $tableText = $rows | Format-Table -AutoSize | Out-String
    Write-Host $tableText.TrimEnd()
    $now = Get-TargetProcesses
    $okRows = @($rows | Where-Object { $_.结果 -eq '一致' })
    $noteRows = @($rows | Where-Object { $_.结果 -eq '注意' })
    Write-Info ("  当前目标进程数：{0}（备份时：{1}）；核对表一致 {2}/{3}" -f @($now).Count, @($b.processes).Count, $okRows.Count, @($rows).Count)
    Write-Info ''
    $deniedPending = @()
    foreach ($r in $noteRows) {
        if ($startDenied -notcontains $r.服务) { continue }
        $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $r.服务) -ErrorAction SilentlyContinue
        $cur = "$((Get-Service -Name $r.服务 -ErrorAction SilentlyContinue).Status)"
        if ($cur -eq 'Stopped' -and "$($reg.Start)" -eq "$([int]$r.备份Start)") { $deniedPending += $r.服务 }
    }
    if ($okRows.Count -eq @($rows).Count) { Write-Info '✔ 恢复完成（核对表全部一致）。' }
    elseif ($deniedPending.Count -gt 0 -and $deniedPending.Count -eq $noteRows.Count) {
        Write-Info ('△ 部分恢复（{0}/{1} 一致）：{2} 个用户服务被产品防篡改拦截，本开机内无法经 SCM 启动。' -f $okRows.Count, @($rows).Count, $deniedPending.Count)
        Write-Info '  其 Start 值已全部还原为备份值：重启一次系统后由开机自启完全复原，无需其他操作。'
    }
    else { Write-Info ('△ 恢复完成度 {0}/{1}：核对表有"注意"项，请核对上方各行；如个别组件未起来，重启一次系统即可完全复原。' -f $okRows.Count, @($rows).Count) }
}

# ---------------- 状态 ----------------
function Get-Mode {
    $b = Load-Backup
    if (-not $b) { return 'normal' }
    $svc = Get-TargetServices
    $managed = @($svc | Where-Object { $Script:DisableOnKeepOff -contains $_.Name })
    if ($managed.Count -eq 0) { return 'normal' }
    $task = Test-KeepOffTask
    if ($task) {
        # 有开机任务 → 预约/持续退出路径
        $drv = ($managed | Where-Object { $_.Name -eq 'zfprotect' } | Select-Object -First 1)
        if ($drv -and [int]$drv.StartDword -eq 4) {
            $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            if ($b.timestamp -and ([datetime]$b.timestamp) -gt $boot) { return 'scheduled' }
            return 'keepoff'
        }
        return 'scheduled'
    }
    $drvRun = ("$((Get-Service -Name 'zfprotect' -ErrorAction SilentlyContinue).Status)" -eq 'Running')
    $un = Get-DriverSwitchValue 'unload'
    if ($drvRun -and "$un" -eq '1') { return 'armed' }
    $allRunning = (@($managed | Where-Object { $_.Status -ne 'Running' }).Count -eq 0)
    if ($allRunning) { return 'restored' }
    $userStopped = (@($managed | Where-Object { $_.Status -eq 'Running' -and $_.Name -ne 'zfprotect' }).Count -eq 0)
    if ($userStopped) { return 'onetime' }
    return 'partial'
}
function Show-Status {
    Write-Info ('===== 密保卫士控制器 · 当前状态（{0}） =====' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $mode = Get-Mode
    switch ($mode) {
        'normal'   { Write-Info '运行模式：正常运行（从未执行过退出）' }
        'keepoff'  { Write-Info '运行模式：持续退出中（开机计划任务保持退出）' }
        'restored' { Write-Info '运行模式：正常运行（曾退出过，已恢复）' }
        'scheduled' { Write-Info '运行模式：已预约下次开机自动执行退出（本次开机组件仍在运行）' }
        'onetime'  { Write-Info '运行模式：一次性退出中（下次开机自动恢复）' }
        'armed'    { Write-Info '运行模式：退出开关已置位（unload=1），重启后运行 -ExitOneTime 完成阶段2' }
        'partial'  { Write-Info '运行模式：部分组件已停止（介于正常与退出之间）' }
    }
    if (Test-KeepOffTask) { Write-Info ("开机计划任务 {0}：存在" -f $Script:KeepOffTask) }
    else { Write-Info ("开机计划任务 {0}：不存在" -f $Script:KeepOffTask) }
    $un = Get-DriverSwitchValue 'unload'
    if ($null -eq $un) { Write-Info '驱动卸载开关 unload：缺省（生产模式，重启后驱动不可卸载）' }
    else { Write-Info ("驱动卸载开关 unload = {0}（1=重启后驱动带卸载回调，可用 -ExitOneTime 阶段2 卸载）" -f $un) }
    $b = Load-Backup
    if ($b) { Write-Info ('原始快照：{0}（{1}）' -f $Script:BackupFile, $b.timestamp) }
    else    { Write-Info '原始快照：无' }
    Write-Info '── 服务'
    foreach ($s in (Get-TargetServices)) {
        Write-Info ("  {0,-15} 状态={1,-9} Start={2}({3}) 路径={4}" -f $s.Name, $s.Status, $s.StartDword, $Script:StartWords[$s.StartDword], $s.Path)
    }
    $procs = Get-TargetProcesses
    Write-Info ('── 进程（{0} 个）' -f @($procs).Count)
    foreach ($p in $procs) { Write-Info ("  {0} (pid={1})" -f $p.Name, $p.Id) }
    $tasks = Get-TargetTasks
    Write-Info ('── 相关计划任务（{0} 个）' -f @($tasks).Count)
    foreach ($t in $tasks) { Write-Info ("  {0}{1} [{2}]" -f $t.TaskPath, $t.TaskName, $t.State) }
    $rks = Get-TargetRunKeys
    Write-Info ('── 相关 Run 启动项（{0} 个）' -f @($rks).Count)
    foreach ($rk in $rks) { Write-Info ("  [{0}] {1} = {2}" -f $rk.Key, $rk.Name, $rk.Value) }
}

# ---------------- 干跑 ----------------
function Show-Plan {
    $svc = Get-TargetServices
    $procs = Get-TargetProcesses
    Write-Info '===== 干跑（-Plan）：以下为将要执行的动作，不会修改任何状态 ====='
    Write-Info ('发现服务 {0} 个 / 进程 {1} 个：' -f @($svc).Count, @($procs).Count)
    foreach ($s in $svc) { Write-Info ("  服务 {0} 状态={1} Start={2}({3})" -f $s.Name, $s.Status, $s.StartDword, $Script:StartWords[$s.StartDword]) }
    foreach ($p in $procs) { Write-Info ("  进程 {0} (pid={1})" -f $p.Name, $p.Id) }
    if (-not $svc -and -not $procs) { Write-Info '  未发现密保卫士组件：任何修改动作都会被拒绝。'; return }
    if ($ExitOneTime) {
        Write-Info '── -ExitOneTime 将执行（两阶段）：'
        Write-Info '   第1次运行：备份 + 驱动服务键写 unload=1（开关仅驱动重启后生效），提示重启；'
        Write-Info '   重启后再次运行：fltmc/sc 卸载 zfprotect → 停止 5 个用户服务+super → 清理进程（此时均可行）→ 复查3轮；'
        Write-Info '   【不修改任何启动类型】→ 再下次开机整套系统自动恢复。'
    }
    if ($ExitKeepOff) {
        Write-Info '── -ExitKeepOff 将执行（两阶段）：'
        Write-Info '   第1次：备份 + unload=1 + 禁用 zfprotect/super 自启（此二键写入实测可行）+ 创建开机任务 MJBW_KeepOff；'
        Write-Info '   重启后：开机任务（SYSTEM）完成其余 5 个服务自启禁用（此时驱动缺席，写入可行）+ 停止服务 + 清理进程并保持退出。'
    }
    if ($ScheduleExit) {
        Write-Info '── -ScheduleExit 将执行：【本次不停任何组件】禁 zfprotect/super 自启 + 写 unload=1 + 创建开机任务 MJBW_KeepOff；'
        Write-Info '   下次开机任务自动完成剩余禁用与退出并保持。'
    }
    if ($Restore) {
        $b = Load-Backup
        if (-not $b) { Write-Info '── -Restore：没有备份文件，无动作。' }
        else {
            Write-Info ('── -Restore 将执行：按备份({0})还原各服务 Start（当前值即原值的跳过）→ 还原驱动开关面板（先于驱动启动）→ 按顺序启动 zfprotect→itxcltserver→zfnetchkclient→zfhookupdat→ZFICONTROL→ZFFTSSERVER →' -f $b.timestamp)
            Write-Info '   还原计划任务/Run 启动项（如有）→ 补启 itxtray → 删除 MJBW_KeepOff → 输出核对表与诚实结论（被产品防篡改拦截的服务将如实标注 [SCM拒绝]，其 Start 值已还原，重启后随自启回归）。'
        }
    }
    if (-not ($ExitOneTime -or $ExitKeepOff -or $ScheduleExit -or $Restore)) {
        Write-Info '（提示：-Plan 配合 -ExitOneTime / -ExitKeepOff / -ScheduleExit / -Restore 之一使用可查看该模式的具体动作清单）'
    }
}

# ---------------- 交互菜单 ----------------
function Show-Menu {
    do {
        Write-Host ''
        Write-Host '================ 密保卫士控制器 ================' -ForegroundColor Cyan
        $mode = Get-Mode
        switch ($mode) {
            'normal'   { Write-Host ' 当前：正常运行（从未退出过）' }
            'keepoff'  { Write-Host ' 当前：持续退出中' -ForegroundColor Yellow }
            'restored' { Write-Host ' 当前：正常运行（已恢复）' }
            'scheduled' { Write-Host ' 当前：已预约下次开机自动退出（组件仍在运行）' -ForegroundColor Yellow }
            'onetime'  { Write-Host ' 当前：一次性退出中（下次开机自动恢复）' -ForegroundColor Yellow }
            'armed'    { Write-Host ' 当前：退出开关已置位，重启后完成阶段2' -ForegroundColor Yellow }
            'partial'  { Write-Host ' 当前：部分组件已停止' -ForegroundColor Yellow }
        }
        Write-Host '-------------------------------------------------'
        Write-Host '  1) 查看详细状态'
        Write-Host '  2) 一次性安全退出（两阶段：本次置开关→重启→再运行完成退出）'
        Write-Host '  3) 持续退出（本次置开关+禁驱自启→重启后开机任务保持退出）'
        Write-Host '  4) 预约下次开机自动执行退出（本次开机不动任何运行组件）'
        Write-Host '  5) 恢复正常运行（按备份一键还原）'
        Write-Host '  0) 退出程序'
        $c = Read-Host '请选择'
        switch ($c) {
            '1' { Show-Status }
            '2' { Invoke-Exit -KeepOff $false }
            '3' { Invoke-Exit -KeepOff $true }
            '4' { Invoke-ScheduleExit }
            '5' { Invoke-Restore }
            '0' { }
            default { }
        }
    } while ($c -ne '0')
    if (-not $Script:Yes) { $null = Read-Host '菜单已退出，按回车键关闭窗口...' }
}

# ---------------- 主分发 ----------------
$action = 'status'
if ($Status)        { $action = 'status' }
elseif ($ExitOneTime)  { $action = 'exit-once' }
elseif ($ExitKeepOff)   { $action = 'exit-keepoff' }
elseif ($ScheduleExit)   { $action = 'schedule-exit' }
elseif ($Restore)       { $action = 'restore' }
elseif ($ReassertExit)  { $action = 'reassert' }
elseif ($Interactive)   { $action = 'interactive' }

if ($Plan) {
    Start-Log 'plan'
    Show-Plan
    return
}

# 需要管理员的动作：自提权
$needAdmin = @('exit-once','exit-keepoff','schedule-exit','restore','reassert','interactive')
if (($needAdmin -contains $action) -and -not (Test-Admin)) {
    Write-Host ('[{0}] 需要管理员权限，正在请求 UAC 并以管理员身份重新启动...' -f $action)
    Invoke-SelfElevate
    return
}

Start-Log $action
switch ($action) {
    'status'      { Show-Status }
    'exit-once'   { Invoke-Exit -KeepOff $false }
    'exit-keepoff'{ Invoke-Exit -KeepOff $true }
    'schedule-exit'{ Invoke-ScheduleExit }
    'restore'     { Invoke-Restore }
    'reassert'    { Invoke-ReassertExit }
    'interactive' { Show-Menu }
}
