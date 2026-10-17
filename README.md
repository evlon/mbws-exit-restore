# mbws-exit-restore

> **密保卫士可逆退出与恢复工具** · Reversible exit & restore toolkit for Zhongfu "MiBaoWeiShi" (MBWS / Intax DLP) on Windows.

给装了中孚「密保卫士」终端管控（Intax 平台）的 Windows 机器装一个**可逆开关**：想退干净就退干净（临时或长期），想回原样就一键回原样——全程逐项验证、日志留痕、零假成功，且**不删任何产品文件、不删任何产品注册表键**。

## 为什么需要它

「密保卫士」是国产企业 DLP/终端保密系统（内核驱动 `zfprotect64.sys` + 7 个服务 + 12 个相关进程）。驱动在场时：

- 停服务被拒（SCM 一律拒绝）；
- 杀进程原地不动（procGuard 进程保护）；
- 直接改服务注册表键被拦（注册表回调）。

常规手段退不掉；硬删/野卸载是破坏性操作且不可逆。本工具利用从驱动**逆向出的官方内置卸载开关**（`zfprotect` 服务键的 `unload` DWORD，驱动启动时读取）实现协议化、可完全还原的退出：

```
置 unload=1 ─► 重启（驱动本次带卸载回调启动）─► fltmc unload 干净卸载驱动
─► 停服务（被 SCM 拒绝的由清进程兜底并如实标注）─► 清理目标进程 ─► 复查无残留

恢复：-Restore 按原始快照一键还原；一次性退出模式甚至只需再重启一次——
启动类型从未被改动，整套系统随开机自启自动复原。
```

深入阅读：[docs/ANALYSIS.md](docs/ANALYSIS.md)（防护原理逆向分析·脱敏版）· [docs/DESIGN.md](docs/DESIGN.md)（设计说明）· [docs/USAGE.md](docs/USAGE.md)（完整操作手册）。

## 快速开始

前置：Windows 10/11 x64 · PowerShell 5.1（系统自带）· 修改类操作需要管理员（自动弹 UAC）· 退出协议包含重启电脑。

**方式一（推荐）**：双击 `mjbwctl.cmd` → UAC 点「是」→ 出现中文菜单，按数字选择即可。

**方式二（命令行）**：

```powershell
# 1) 只读看当前状态（无需管理员）
powershell -NoProfile -ExecutionPolicy Bypass -File .\mjbwctl.ps1 -Status

# 2) 干跑预览：只打印将要执行的动作，零修改
powershell -NoProfile -ExecutionPolicy Bypass -File .\mjbwctl.ps1 -ExitOneTime -Plan

# 3) 真实执行（示例：一次性退出）
powershell -NoProfile -ExecutionPolicy Bypass -File .\mjbwctl.ps1 -ExitOneTime -Yes
#    第 1 次运行只置开关 → 按提示重启 → 重启后再跑一次同命令完成退出
#    想恢复：再重启一次即自动复原；或 -Restore 立即还原开关与驱动
```

## 四种模式

| 你想要的效果 | 入口 | 说明 |
|---|---|---|
| **临时退出**（装软件/做实验） | `-ExitOneTime` | 两阶段退出；不改任何启动类型，**再下次开机整套系统自动恢复** |
| **长期保持退出** | `-ExitKeepOff` | 禁两个驱动服务自启 + 建开机任务 `MJBW_KeepOff`，每次开机自动断言退出，重启也不复活 |
| **这次还要用，下次开机起再退** | `-ScheduleExit` | 本次零动作；下次开机自动进入持续退出 |
| **恢复 / 回厂** | `-Restore` | 按退出前原始快照 `state_backup.json` 还原全部改动，输出逐项核对表 |

配套**三阶段闭环验证器**（可选，用于证明全链路真的成立）：

```
verify.cmd          # Pre：置开关 + 断言
（重启）
verify.cmd post     # Post：真实退出 → 断言 → 恢复 → 断言
（重启）
verify.cmd check    # Check：核对全部组件随开机自启复原 → 生成报告
```

本项目已在一台真实受管机完成全链路实测：**Pre 6/6 · Post 退出 5/5 · Check 7/7**。

## 它有多"诚实"

- 每个停止/启动/杀进程动作**单独验证真实结果**，绝不吞错；
- 平台预期内拒绝如实标注（`[SCM拒绝]`），既不粉饰也不假装成功；
- 恢复核对表三分类：✔ 恢复完成 / △ 部分恢复（平台防篡改拦截，重启自启复原）/ △ 完成度 x/y；
- 全程日志（`logs\`）；原始快照默认永不覆盖，恢复永远以最早一次退出前的状态为准。

## 环境与版本

- 实测产品版本：`zfprotect64.sys` v2025.1.23.9（中孚密保卫士 / Intax 平台）· Windows 10/11 x64；
- 驱动升级后请先复核开关面板仍在（在驱动文件内搜 `unload` 等值名字符串初判）再沿用；
- PowerShell 引擎显式使用系统自带 5.1，不依赖 PATH。

## 诚实边界与合规声明

1. **管理端可见**：退出期间本机心跳/策略同步中断，管理端会看到离线；服务器可能远程下发策略或安排重装；产品若重装到新目录/新服务名，需重新侦察；
2. **合规**：本仓库面向**技术研究与自有设备管理**场景。在受管企业设备上停用保密软件前，请确认符合你所在单位的制度并自行承担后果；
3. **恢复的物理上限**：产品驻留 services.exe 的防篡改拦截（本开机内拒绝经 SCM 启停其 5 个用户服务）是平台行为——同一开机内 `-Restore` 会还原开关/驱动/启动类型，5 个用户服务待下次开机随自启归位（Check 阶段核对的正是这件事）。

## 目录结构

```
mbws-exit-restore/
├── mjbwctl.ps1            # 主控制器（菜单/命令行/干跑/恢复/自动提权）
├── mjbwctl.cmd            # 双击入口（弹 UAC → 中文菜单）
├── verify.cmd             # 三阶段验证器入口
├── verify_roundtrip.ps1   # Pre/Post/Check 三阶段断言引擎
├── policy_decode.ps1      # 策略传输载荷解码辅助（base64(XOR(JSON,0x1F))）
├── docs/
│   ├── USAGE.md           # 完整操作手册（参数表/模式对照/FAQ）
│   ├── DESIGN.md          # 设计说明（开关协议/顺序/持久化面/诚实化）
│   └── ANALYSIS.md        # 防护原理逆向分析（脱敏副本）
├── .gitignore
└── LICENSE                # MIT
```

运行时自动生成、不入库：`state_backup.json`（原始快照）、`logs\`、`verify_result_*.md`。

## 许可

MIT —— 见 [LICENSE](LICENSE)。

---

**关键词**：密保卫士 · mibaoweishi · MBWS · 中孚 · Zhongfu · Intax · DLP · zfprotect · Windows · PowerShell · reversible exit · restore
