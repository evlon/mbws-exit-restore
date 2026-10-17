# mjbwctl 设计说明（DESIGN.md）

> 密保卫士控制器：两阶段安全退出（可选开机自动执行）/ 一键恢复正常状态。
> 核心机制是**驱动卸载开关 `unload`**（见 §2）；逆向分析依据见 [ANALYSIS.md](ANALYSIS.md)（脱敏版）；用法见 [USAGE.md](USAGE.md)。

## 1. 模式语义（v2：全部两阶段）

密保卫士的过滤驱动 `zfprotect64.sys` 在**本次开机内无法卸载**（生产模式下未注册卸载回调），因此「停服务/杀进程」只有在驱动退出后才真正生效。工具据此把所有退出模式改成两阶段。

| 模式 | 阶段 1（本次运行） | 阶段 2（重启后） | 下次开机 | 典型场景 |
|---|---|---|---|---|
| **一次性安全退出** `-ExitOneTime` | 备份现场 + 写 `unload`=1；提示重启 | 再运行同命令：`fltmc unload`/`sc stop zfprotect` → 停 5 个用户服务 → 清进程 → 复查 | 整套系统自动恢复 | 临时退出（做实验、开某软件），重启即回原状 |
| **持续退出** `-ExitKeepOff` | 备份 + 写 `unload`=1 + 置 `zfprotect`/`super` Start=4 + 建开机任务 `MJBW_KeepOff` | 开机任务自动断言：驱动不加载 → 停服务/清进程并保持 | 自动执行退出并保持退出 | 长期保持退出，直到手动 `-Restore` |
| **仅预约** `-ScheduleExit` | **本次不停任何组件**；备份 + 写 `unload`=1 + 置两个驱动 Start=4 + 建开机任务 | 同持续退出 | 自动执行退出并保持退出 | 本次继续工作，下次开机起退出 |
| **恢复** `-Restore` | 按备份还原 Start → **还原 `unload`**（原值或删除，先于驱动启动，实例按原配置加载）→ 启动服务与驱动（逐项验证；被 services.exe 防篡改拦截的服务如实标 `[SCM拒绝]`，Start 已还原、待重启自启）→ 还原任务/Run 键 → 删任务 → 核对表与诚实结论 | — | 正常加载 | 任何时候想回到出厂管控状态 |

`-ReassertExit` 是开机任务 `MJBW_KeepOff`（ONSTART/SYSTEM/最高权限）以 `-Yes` 调用的内部动作，幂等，勿手动使用。

## 2. 驱动开关协议（v2 核心机制）

逆向结论（`zfprotect64.sys` 全量反编译）：

- DriverEntry（`FUN_00023160`）从**自己的服务键** `HKLM\SYSTEM\CurrentControlSet\Services\zfprotect` 读取约 11 个明文 UTF-16 配置值；当前全部**不存在** = 生产缺省（防护全开）。
- 其中 **`unload` (DWORD) ≠ 0** → 置 flags0 的 bit3 → 注册 `FilterUnloadCallback`（`FUN_00013560`）与 `DriverUnload` 路径 → `fltmc unload zfprotect` / `sc stop zfprotect` 才可能成功。缺省 0 = 拒绝卸载。Windows XP（major 5 / minor 1）会强制打开该位，现代 Windows 完全由 `unload` 决定。
- **该值只在驱动启动时读取一次** → 写完后必须重启，驱动才会带卸载回调启动。
- zfprotect 的服务键**自身不受保护**（实测可写；regProtect 策略只覆盖 `zfhookupdat` 键 vs `regedit.exe`），所以管理员可以直接写 `unload`=1。
- 其他开关（`Monitor Registry` / `Process Protect`（缺省 1，正是杀进程失败的根因）/ `Disable Filtering` / `Disable FileHide` / `Build CommPort` / `MajorFunc Mask` / `Concerned FileSystem` …）驱动停下后即无意义，工具**不写**，保持最小干预。
- 服务键里的 `DebugFlags = 0` 是 INF 残留，**不是**开关，勿混淆。

**为什么不能只靠停服务**：实测中 1 秒间隔连发 5 个 `sc stop` + 杀 12 个进程后，3 轮复查仍找到同名进程（PID 都没变），`sc config start=` 对 5 个用户服务也被拒绝 —— 驱动把权限回调、进程保护、服务自拒全部挡住，而旧版工具把这些静默失败误报为成功（见 §5）。

**实测补充（2026-10-17 真机 Post 阶段）——services.exe 防篡改拦截**：产品把一层与驱动独立的防篡改挂钩驻留在 services.exe 进程内：本开机内对其 5 个用户服务的 SCM start/stop 一律拒绝（提升令牌同样；`sc.exe start` 报 `OpenService FAILED 5`、.NET 报 "Cannot open … service"；驱动已卸载、组件已杀后依然存活；System 日志无 7000/7009 → 请求未达 SCM 内部；`sc sdshow` 显示的默认 SDDL 与实际执行脱钩；无 LaunchProtected、无存储 Security 值）。重启后消失，开机自启不受影响。结论：① 退出相位「停服务」由清进程兜底完成（`[SCM拒绝]` 为预期路径）；② 同一开机内 `-Restore` 无法拉起这 5 个服务，「部分恢复」是平台约束下的正确终态——Start 已还原，重启一次即完全复原；③ KeepOff/ScheduleExit 开机任务运行时该挂钩从未植入，SCM 停止可用。

**实测补充 2（2026-10-17 第二轮真机）——看门狗驱动回拉竞态**：驱动卸载、清进程完成后数秒内，产品组件可能未经 SCM 直接复活（本轮实测：zfhookupdat.exe + 4×zhp.exe），再经 SCM 重启 zfprotect 驱动——驱动服务不在防篡改拦截名单内，StartService 放行；重载的驱动重读 unload=1，仍带卸载回调、可再次卸载。竞态取决于维护节拍是否落进清理窗口（同日两轮真机：09:45 零复活、11:09 一轮复活）。v3.1 对策：① 复查循环每轮清复活进程/服务后核驱动，发现 Running 即自动再次卸载，下一轮复测；② 终态判定纳入驱动三态；③ SCM 拒绝签名双语识别（.NET 英文 "Cannot open … service on computer" 与本地化中文 "无法打开计算机…上的…服务"——同日两轮真机分别出现，旧匹配器只认英文导致中文报告掉进通用 [失败] 分支）。

## 3. 停止/启动顺序及其理由

- **停止顺序**：`zfhookupdat → ZFICONTROL → zfnetchkclient → itxcltserver → ZFFTSSERVER → zfprotect(fltmc/sc) → 杀残留进程 → 3×5s 复查`
  - zfhookupdat 先停：它是注入宿主 `zhp.exe` 的父进程（看门狗源头），断根
  - ZFICONTROL 先停：它是 ZFIUpdateServer→ZFIFileContent 的父进程
  - zfnetchkclient 先于 itxcltserver：前者 SCM 依赖后者，反序会被 SCM 拒绝
  - zfprotect 走 `Invoke-DriverPhase`：先读 `unload`，未置位则明确告知「需先写开关 + 重启」，置位后用 `fltmc unload` 与 `sc stop` 双保险并**验证真的停了**（不再假装成功）
  - 复查 3 轮：防看门狗拉活；每轮都重新枚举并用新 PID 判定；每轮核驱动，被拉回即再次卸载（v3.1）
- **恢复顺序**：`zfprotect → itxcltserver → zfnetchkclient → zfhookupdat → ZFICONTROL → ZFFTSSERVER`
  - 驱动先行；主客户端先于其依赖者
  - 仅启动备份时在运行的服务（`super` 原本停止 → 保持停止）
  - 8 秒后 `itxtray` 未被服务拉起则按备份路径补启

## 4. 持久化面（为什么只处理服务 + 启动项）

侦察证实本机密保卫士的持久化**主体是 7 个服务**：无计划任务、无 Run 键、无 WMI 订阅、SCM 失败恢复均未配置。工具仍保留运行时自动发现（路径模式 `Intax|ZfHook|zfi|patchclient` + 核心名单），并在写入前把发现的计划任务/Run 键一并备份；`-Restore` 时按备份还原（含「备份时即为 Disabled」的状态守卫，避免还原失真）。

## 5. 关键设计决策与诚实化

1. **备份优先，永不覆盖原始快照**：`state_backup.json` 只在首次退出时创建（`-ForceBackup` 强制重拍）；历史副本至多 5 份。**v2 起备份额外快照驱动开关值**（`driverSwitches`），`-Restore` 据此还原 `unload`。
2. **绝不破坏**：只改服务状态与 `unload` 值，不删产品文件、不删产品注册表键；Run 键移除前必入备份。
3. **诚实化（针对真实 FAIL 报告）**：
   - `Set-ServiceStartDword` 不再用 `| Out-Null` 吞掉 `sc.exe` 的错误文本，改为捕获并回显；
   - 每个停止/杀进程动作都**单独验证**，失败即如实标记；
   - 最终判定用**独立的实时查询**（`Get-Service`/`Get-Process`）而非控制器自己的文案；未达标时输出醒目的失败横幅，绝不再打印假的 `✔`。
4. **两阶段退出**：驱动开关 + 重启是唯一能真正卸载 `zfprotect64.sys` 的路径；`-ExitKeepOff`/`-ScheduleExit` 通过「重启前就置 Start=4」保证驱动在下次开机根本不加载，因此不需要在本次会话里强行卸载。
5. **开机自动执行 = ONSTART/SYSTEM 计划任务**（用户选择"持续退出/仅预约"时创建，`-Restore` 删除）：防止服务器策略同步/管理员远程重新启用后组件复活。
6. **自提权**：修改类动作检测非管理员时用 UAC 重启自身并保留全部参数；`-Status`/`-Plan` 只读不提权。

## 6. 已知残留与风险（诚实清单）

- **阶段 1 之后到重启之前**：`unload` 已置位但驱动仍是旧实例，防护照旧生效；此时退出**不会**成功——工具会明确提示重启，不再做无用的停服务。
- **阶段 2 之后**：`zfprotect64.sys` 已真正卸载，文件写保护/目录隐藏/注册表拦截随之失效；用户态组件全部停止。
- **服务器可见性**：客户端停止后服务器会看到终端离线（心跳/策略同步中断），管理员端有感知；服务器可远程下发策略或安排重装。开机计划任务（持续退出/仅预约模式）会再次断言，但若管理员重装到新目录/新服务名，需重新侦察后更新名单。
- **企业合规**：在受管企业设备上停用安全软件请遵守公司制度，后果自负；本工具为技术验证用途设计。

## 附：一键闭环自检器（verify_roundtrip.ps1 / verify.cmd）

v3 自检器为**三阶段**（两阶段退出协议 + services.exe 拦截的现实）：

- **Pre 阶段（重启前）**：双击 `verify.cmd` → 采集状态 → `-ExitOneTime -Yes`（预期只做：备份 + 置 `unload`=1 + 提示重启）→ 断言：备份存在、`unload`=1、5 个用户服务与 zfprotect 均仍在运行（阶段 1 不停任何组件）、**无** MJBW_KeepOff 任务 → 生成 `verify_result_<时间戳>_pre.md`，提示重启。
- **Post 阶段（第一次重启后）**：`verify.cmd post` → 再次 `-ExitOneTime -Yes`（驱动已带卸载回调，阶段 2 可干净卸载）→ 断言：zfprotect Stopped（驱动已卸载）、5 个用户态服务 Stopped、目标进程清零 → 真实 `-Restore -Yes` → 断言：zfprotect 回 Running、`unload` 已还原（缺省）、任务移除、7 个服务 Start 全部与备份一致、恢复结论行如实、输出无「启动失败」；5 个用户服务"Running 或（被防篡改拦截）Stopped 且 Start 已还原"均算 PASS（预期，待重启自启）→ 生成 `verify_result_<时间戳>_post.md`。
- **Check 阶段（第二次重启后）**：`verify.cmd check` → 核对 5 个用户服务已随开机自启 Running、zfprotect Running、7 个 Start 与备份一致、`unload` 缺省、无任务、目标进程回归（含最多 60 秒等待窗口）→ 生成 `verify_result_<时间戳>_check.md` 与三阶段闭环结论。
- 设计决策：断言用独立查询（`Get-Service` / `Get-Process` / 注册表直读）而非解析控制器输出；控制器原始输出全文收录进报告作为证据链。
- `-Plan` 干跑无需管理员；真实运行需要管理员（UAC 一次）；自检器内部以 `-Yes` 无人值守调用控制器，引擎显式使用 `powershell.exe`（不依赖 PATH 上的 pwsh）。