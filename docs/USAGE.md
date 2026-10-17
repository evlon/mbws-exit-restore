# 密保卫士控制器（mjbwctl）使用说明

> 适用对象：安装了中孚「密保卫士」企业保密终端（Intax 平台，7 个服务、12 个相关进程）的 Windows 机器。
> 本工具只做四件事：**查状态、安全退出、预约下次开机退出、一键恢复**。
> 设计细节见 [DESIGN.md](DESIGN.md)，防护原理逆向分析见 [ANALYSIS.md](ANALYSIS.md)（脱敏版）。

## 一、功能简介

- **查看状态**（`-Status`）：列出 7 个受管服务（含 zfprotect/super 两个内核驱动服务）、12 个相关进程、开机计划任务 MJBW_KeepOff 的有无、以及相关 Run 启动项，并判定当前处于哪种运行模式。只读，无需管理员。
- **安全退出/预约**（三种模式，均遵循「驱动开关协议」两阶段执行，见第四节）：
  - `-ExitOneTime` 一次性退出（两阶段）：第1次运行置位驱动卸载开关并提示重启；重启后再次运行完成"卸载驱动→停止全部组件"（**不修改任何启动类型**，再下次开机整套系统随自启动自动恢复）；
  - `-ExitKeepOff` 持续退出（两阶段）：第1次运行置开关 + 禁用 zfprotect/super 自启（实测此二键可写）+ 创建开机任务 MJBW_KeepOff；重启后开机任务自动完成剩余禁用与退出并**每次开机保持**。
- **仅预约下次开机退出**（`-ScheduleExit`）：本次开机**不做任何停止**（仅置开关 + 禁 zfprotect/super 自启 + 建任务），**下次开机自动执行退出并保持**。
- **一键恢复**（`-Restore`）：按退出前的现场快照 `state_backup.json` 还原服务启动类型、按依赖顺序重启服务、补启托盘、删除 MJBW_KeepOff，最后输出核对表。

工具**绝不删除产品文件**、**绝不删除产品注册表键**；任何修改前自动把现场快照存入备份文件（原始快照默认永不覆盖），全程留日志。

## 二、三种用法

### 1. 双击进菜单（日常推荐）

双击 `mjbwctl.cmd`，弹出 UAC 时点"是"，随后出现中文菜单：

```
1) 查看详细状态
2) 一次性安全退出（两阶段：本次置开关，重启后第二次运行完成退出）
3) 持续退出（本次置开关+禁驱自启，重启后开机任务保持退出）
4) 预约下次开机自动执行退出（本次开机不动任何运行组件）
5) 恢复正常运行（按备份一键还原）
0) 退出程序
```

输入数字并回车即可。修改类操作会再要求输入 `Y` 确认。

### 2. 命令行

在 PowerShell 中运行（路径按实际位置调整）：

```powershell
# 查看当前状态（只读，无需管理员）
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -Status

# 干跑预览：只打印将要执行的动作，不做任何修改（无需管理员）
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ExitOneTime -Plan
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ExitKeepOff -Plan
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -Restore -Plan
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ScheduleExit -Plan

# 真实执行（非管理员时脚本会自动弹 UAC 并以管理员身份重跑自身，参数原样保留；-Yes 为跳过确认）
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ExitOneTime -Yes
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ExitKeepOff -Yes
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -Restore -Yes
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -ScheduleExit -Yes
```

### 3. 参数表

| 参数 | 作用 | 需要管理员 |
|---|---|---|
| `-Status` | 查看当前状态（只读；会在 logs\ 留一份运行日志） | 否 |
| `-ExitOneTime` | 一次性安全退出（两阶段，见第三/四节） | 是，自动弹 UAC |
| `-ExitKeepOff` | 持续退出（两阶段，见第三/四节） | 是，自动弹 UAC |
| `-ScheduleExit` | 仅预约：本次不动（置开关+禁驱自启+建任务） | 是，自动弹 UAC |
| `-Restore` | 按备份恢复正常运行 | 是，自动弹 UAC |
| `-Plan` | 干跑：只打印将执行的动作，零修改 | 否 |
| `-Yes` | 跳过 Y/N 确认提示（自动化场景用） | — |
| `-ForceBackup` | 退出时强制重新拍现场快照（默认沿用最早的原始快照） | — |
| `-Interactive` | 进入中文菜单（双击 mjbwctl.cmd 即此入口） | 是 |
| `-ReassertExit` | 开机计划任务内部使用（勿手动运行） | SYSTEM |

### 4. 一键闭环自检（三阶段，真实验证用）

验证器已适配「驱动开关协议」与「services.exe 防篡改拦截」，分三步走：

1. **Pre 阶段**：双击 `verify.cmd`（不带参数）→ 自动执行 `-ExitOneTime -Yes` → 断言：备份存在、`unload=1` 已置位、组件未被停止、无任务被误建 → 生成 `verify_result_<时间戳>_pre.md` → **随后重启电脑**（开关只在驱动启动时生效）；
2. **Post 阶段**：第一次重启后运行 `verify.cmd post` → 自动执行阶段2退出 → 断言：驱动 Stopped、5 个用户服务 Stopped、目标进程清零 → 自动执行 `-Restore -Yes` → 断言：驱动回 Running、Start 与备份一致（全部 7 项）、`unload` 开关已还原、无任务、恢复结论如实；5 个用户服务"Running 或（被产品防篡改拦截）Stopped 且 Start 已还原"均算 PASS（属预期，待重启自启）→ 生成 `verify_result_<时间戳>_post.md`；
3. **Check 阶段**：再重启一次后运行 `verify.cmd check` → 核对全部组件已随开机自启复原（5 服务 Running、驱动 Running、Start 与备份一致、`unload` 缺省、无任务、进程回归）→ 生成 `verify_result_<时间戳>_check.md` 与三阶段闭环结论。

三阶段均 PASS 即闭环验证通过。每步需要管理员（自动弹 UAC）；只预览不执行：`powershell -ExecutionPolicy Bypass -File <工具目录>\verify_roundtrip.ps1 -Plan`。引擎显式使用 `powershell.exe`（5.1），不依赖 PATH 上的 pwsh 版本。

## 三、三种模式的区别（一次性退出 / 持续退出 / 仅预约）

| | 一次性安全退出 `-ExitOneTime` | 持续退出 `-ExitKeepOff` | 仅预约 `-ScheduleExit` |
|---|---|---|---|
| 第1次运行（阶段1） | 备份 + 置 `unload=1` + 提示重启；**不停任何组件** | 同左 + 禁用 zfprotect/super 自启（实测可写）+ 创建 MJBW_KeepOff | 同左（不停任何组件） |
| 重启 | 驱动带卸载回调启动 | 驱动**不再加载**（自启已禁） | 同左 |
| 阶段2 / 开机任务 | 重启后再次运行本命令：卸载驱动→停服务→清进程（此时全部可行，逐项验证） | 开机任务自动：禁用其余 5 个服务自启→停服务→清进程→保持 | 同左 |
| 服务启动类型 | **不改**（下次开机整套自动恢复） | 6 个服务自启禁用 | 同左 |
| 下次开机 | **整套系统自动恢复运行** | **自动执行退出并保持退出**（重启也不复活） | **自动执行退出并保持退出** |
| 如何恢复 | `-Restore`：开关+驱动立即恢复，5 个用户服务因防篡改拦截需重启一次回归（或直接重启，整机自动恢复） | 只能 `-Restore`（或手动删任务 + 改回服务启动类型） | `-Restore` 撤销预约并恢复正常 |
| 适合场景 | 临时退出（装某软件、做实验） | 长期保持退出 | 现在还要用，只想下次开机起退出 |

> **MJBW_KeepOff 说明**：这是工具自建的开机计划任务（触发器"系统启动时"、以 SYSTEM 身份、最高权限运行），每次开机自动执行一遍退出序列并复查 3 轮，防止组件开机复活或被策略重新拉起；复查同时监测驱动，被看门狗拉回即自动再次卸载。`-Restore` 会自动删除它；`-Status` 会显示它是否存在。持续退出（-ExitKeepOff）与仅预约（-ScheduleExit）两种模式都会创建它。

## 四、驱动开关协议（v2 核心机制）

**为什么必须"先置开关、再重启"？** 本机实测（2026-10-17）：zfprotect64.sys 驱动在场时，用户态三类操作会被静默或显式拒绝——① `Stop-Service` 被服务处理器拒绝；② `Stop-Process` 被 procGuard 规则拒绝（进程原地不动）；③ `sc config` 改 5 个用户服务键被驱动注册表回调拦截（改 zfprotect/super 自身键不拦）。因此"本次开机内直接退出"在本机不可能成立，v1 工具当时的"✔ 完成"是误报，v2 已全部改为逐项真实验证。

**实测补充（2026-10-17，Post 阶段真机运行发现）——services.exe 防篡改拦截**：产品还有一层与驱动无关的防篡改，挂钩驻留在 services.exe 进程内：**本开机内**拒绝经 SCM start/stop 其 5 个用户服务（提升的管理员令牌同样被拒；驱动已卸载、组件已被杀后依然存活；`sc.exe start` 直接报 `OpenService FAILED 5`，System 日志无 7000/7009 → 请求未到达 SCM 内部）。重启后该挂钩消失，开机自启路径不受影响。影响与对策：① 退出相位"停服务"实际由清进程兜底完成（工具把 SCM 拒绝如实标注为 `[SCM拒绝]`）；② 同一开机内 `-Restore` 拉不起这 5 个服务（如实标注，Start 值已还原）——**重启一次即由开机自启完全复原**；③ KeepOff/ScheduleExit 的开机任务运行时（驱动未加载、组件未运行）该挂钩从未植入，SCM 停止可用。

**逆向结论**（Ghidra 分析 `C:\Windows\System32\drivers\zfprotect64.sys`，v2025.1.23.9；已做字节级身份核验：分析副本=实盘文件，全盘唯一，服务 ImagePath 即指向它）：驱动在 `DriverEntry` 启动时用 `ZwOpenKey` 读取**自身服务键** `HKLM\SYSTEM\CurrentControlSet\Services\zfprotect` 的一组开关值（明文 UTF-16 值名），据此决定是否注册卸载回调、开启哪些防护。生产装机这些值**全部缺省**（= 全防护 ON、驱动不可卸载）。

| 值名（DWORD） | 缺省行为 | 置位/清零效果 |
|---|---|---|
| **`unload`** | **缺省 0=不注册 FilterUnloadCallback → `sc stop`/`fltmc unload` 必败** | **=1 → 驱动启动时注册真实卸载回调 → 可用 `fltmc unload zfprotect`（或 `sc stop`）干净卸载** |
| `Monitor Registry` | 1=注册表回调防护 ON（改服务键被拦的来源） | 0=关闭 |
| `Process Protect` | 1=进程保护 ON（杀不掉的来源） | 0=关闭 |
| `Disable Filtering` | 0=minifilter 正常 | 1=整个文件过滤跳过 |
| `Disable FileHide` | 0=目录隐藏 ON | 1=关闭隐藏 |
| `ServProtect` | 0 | 1=服务自保护 |
| `Build CommPort` | 1=与用户态建通信口 | 0=不建 |
| `Load Image Notify` / `Process Create Notify Routine` | 注册（注入与监控的根基） | 0=不注册 |
| `MajorFunc Mask` | 0xFFFFFFFF（IRP 全拦截） | 位掩码 |
| `Concerned FileSystem` | 0x20001E | 关注的文件系统 |

**两阶段协议**（工具已内置，自动引导）：

1. **阶段 1**（`-ExitOneTime`/`-ExitKeepOff` 首次运行）：备份现场 → 写 `unload=1`（该键本身不受注册表回调保护，实测可写）→ 提示重启；
2. **重启**：驱动带着卸载回调启动（开关**只在启动时读取一次**，运行中改值无效）；
3. **阶段 2**（重启后再次运行）：`fltmc unload zfprotect`（过滤卸载）+ `sc stop`（服务停）→ 此时停服务/杀进程/改配置**全部可行** → 真实退出并逐项验证，最终结论诚实（成功/未完成都会明说）；
4. **恢复**（`-Restore`）：按备份还原 `unload`（原为缺省则删除该值）、重启驱动与服务、输出核对表。

**设计取舍**：只写 `unload` 一个值——驱动一旦卸载，procGuard/注册表回调/文件过滤等其余防护全部随之失效，无需多动；最小干预、可完整还原。`-ExitKeepOff`/`-ScheduleExit` 另加禁用 zfprotect/super 自启（Start=4，此二键实测可写），重启后驱动**根本不加载**，开机任务完成剩余退出并保持。

> 升级提示：若日后驱动升级，请先复核开关面板是否仍在（在 `zfprotect64.sys` 内搜索这些值名字符串即可初判）再沿用本协议。

## 五、恢复方法与核对表

任一模式退出后，想回到正常运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File <工具目录>\mjbwctl.ps1 -Restore
```

`-Restore` 会自动完成：

1. 按备份 `state_backup.json` 还原 7 个服务的启动类型（Start 原值，含 zfprotect=3 按需启动；当前值即原值的自动跳过——驱动在场时改 5 个用户服务键会被注册表回调拦截，工具会如实报告原因）；
2. **还原驱动开关面板**（按备份记录：`unload` 等值原为缺省则删除，恢复生产模式。**先于驱动启动执行**：本次加载的驱动实例即按原配置运行——生产模式实例无卸载回调，`sc stop`/`fltmc unload` 会被驱动拒绝，与出厂状态一致）；
3. 按依赖顺序重启**备份时在运行**的服务（zfprotect → itxcltserver → zfnetchkclient → zfhookupdat → ZFICONTROL → ZFFTSSERVER；super 备份时就是停止的，保持停止）。每个启动逐项验证并输出真实结果；被产品防篡改拦截（services.exe 内驻留挂钩，本开机内拒绝 SCM 启动）的服务如实标注 `[SCM拒绝]`——其 Start 值已还原，重启一次后随开机自启回归；
4. 重新启用备份中的相关计划任务、还原 Run 启动项（如有；本机当前没有这类项）；
5. 等待 8 秒组件自愈，托盘 itxtray 若未被服务拉起则按备份路径补启一次；
6. 删除开机计划任务 MJBW_KeepOff；
7. 输出**核对表**与诚实结论：逐项比对每个服务的"备份状态 vs 当前状态、备份 Start vs 当前 Start"，标注"一致/注意"；全部一致报"✔ 恢复完成"；仅由被拦截服务构成的"注意"项如实分类为"△ 部分恢复（N 个用户服务被产品防篡改拦截，Start 已还原，重启后由自启完全复原）"；其余异常如实报"△ 完成度 x/y"。

核对表全部"一致"即恢复成功；存在被拦截的"注意"项属"部分恢复"（预期行为，重启一次即完全复原）；其他个别组件未起来时，重启一次系统同样即可完全复原。

## 六、注意事项（重要）

1. **需要管理员**：退出/恢复/菜单会自动弹 UAC；`-Status` 与 `-Plan` 不需要管理员且零修改（仅留运行日志）。
2. **驱动卸载遵循「驱动开关协议」（见第四节）**：首次运行只置开关、不停任何组件（实测驱动在场时停服务/杀进程/改配置均被拒，v1 强行执行只会产生假成功）；重启后阶段 2 才能干净卸载驱动并真实退出。置开关后、重启前，防护照旧运行，属预期现象。
3. **服务器可感知/重装**：客户端停止后心跳与策略同步中断，管理端会看到本机离线；服务器也可能远程下发策略重新拉起组件，甚至安排重新安装。持续退出/仅预约模式的开机计划任务会在每次开机重新断言退出，但若管理员以新目录/新服务名重装，需重新侦察后再更新本工具名单。
4. **企业设备请遵守公司制度**：本工具为技术验证与设备管理用途设计。在受管企业设备上停用保密软件前，请确认符合公司规定并自行承担后果。
5. **文件与日志位置**（均在 `<工具目录>\` 下）：
   - `state_backup.json` —— **最早一次退出前的原始现场快照**（默认永不覆盖，恢复以此为准）；
   - `state_backup_时间戳.json` —— 每次重新拍备份前留下的历史副本，**至多保留 5 份**；
   - `logs\` —— 全程操作日志，每次运行一个 `时间戳_动作.log`（含 `-Status`/`-Plan` 运行记录，便于审计）。

## 七、常见问题

- **退出后托盘图标（itxtray）没起来？** 恢复时已按备份路径补启一次；若仍未出现，**注销再登录**即可。
- **想重新拍一份备份？** 默认沿用最早的原始快照以防丢失"出厂状态"；确认要重拍时加 `-ForceBackup`（会先把旧备份存为历史副本再拍新的）。
- **担心执行后果？** 先加 `-Plan` 干跑预览，输出会列出该模式将执行的每一步，零修改。
- **想确认当前处于哪种模式？** 运行 `-Status`，第一部分"运行模式"会显示：正常运行（从未退出）/ 一次性退出中（下次开机自动恢复）/ **退出开关已置位（重启后运行 -ExitOneTime 完成阶段2）** / 持续退出中 / 已预约下次开机自动退出（本次仍在运行）/ 正常运行（已恢复）/ 部分组件已停止。`-Status` 还会显示驱动开关面板当前值与"可退出性"预测。
- **预约后到重启前，服务若异常停止会自动复活吗？** 不会（自启已禁用、服务无失败自恢复）；如需立即恢复可 -Restore，或等下次开机按预约进入退出。
- **-Restore 提示"没有找到备份文件"？** 说明从未执行过退出，当前即默认状态，无需恢复。
- **备份文件误删？** 用 `state_backup_*.json` 历史副本（至多 5 份）中合适的一份，重命名为 `state_backup.json` 即可继续 `-Restore`。
- **为什么 `-Restore` 后 5 个用户服务仍是 Stopped？** 产品防篡改挂钩驻留在 services.exe 进程内，本开机内拒绝经 SCM 启动其用户服务（管理员也一样，且与驱动是否在场无关）。`-Restore` 已把它们的 Start 值还原为原值——**重启一次电脑**即由开机自启全部拉起；要闭环证明已复原，重启后运行 `verify.cmd check`。

- **退出最后报「✘ … 驱动状态 Running」？** 产品看门狗竞态——清进程后数秒内组件（如 zfhookupdat）可能复活并经 SCM 重启驱动（驱动服务不在防篡改名单内，放行；且重载时读到 unload=1，仍可再次卸载）。v3.1 起复查环节会自动再次卸载并复测；若旧版本遇到，直接再运行一次同命令即可完成退出。

## 八、附：策略流量解码辅助工具（可选）

`policy_decode.ps1`（与主程序同目录）用于解读密保卫士客户端与管控服务器之间的**策略传输载荷**（格式：`base64(XOR(JSON, 0x1F))`；服务器 <策略服务器IP>，端口 8443/15001/38443/26112）：

```powershell
# 解码：直接给 base64 字符串，或给"每行一条载荷"的文件
powershell -ExecutionPolicy Bypass -File <工具目录>\policy_decode.ps1 -Text "<base64载荷>"
powershell -ExecutionPolicy Bypass -File <工具目录>\policy_decode.ps1 -File .\payload.txt

# 编码（构造测试载荷/验证解码器，自带回环自检）
powershell -ExecutionPolicy Bypass -File <工具目录>\policy_decode.ps1 -Encode -Json '{"a":1}'
```

抓取载荷的方法（需要管理员，属研究性质，非本工具必需）：

1. 安装 Wireshark，捕获过滤器填 `host <策略服务器IP>`；
2. 触发一次策略同步（如重启 itxcltserver 服务，或等客户端定时同步）；
3. 对 15001 等端口的 TCP 流右键 **Follow TCP Stream**，把 body 中的 base64 文本（每行一条）存成 `payload.txt`；
4. 用上面的 `-File` 解码，即可看到服务器下发给本机的明文策略 JSON。

> 提示：解码出的策略仅代表抓包时刻的配置内容，请遵守公司数据保密制度，勿外传。
