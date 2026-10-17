# 密保卫士（中孚信息）防护原理逆向分析报告

> 本文为脱敏副本：策略服务器 IP、本机客户端 UUID、策略节点 ID、安装实例 GUID 已替换为占位符，不影响机制分析本身。


- **分析对象**：本机安装的中孚信息"密保卫士系统"终端客户端（内部代号 **MBWS**，平台名 **Intax**，源码工程代号 **nhqdpt**）
- **分析方式**：纯静态逆向（Ghidra 12.1.4 + 自研 PE/IAT 交叉引用扫描器）+ 注册表/日志/数据库取证 + 行为实验，**未执行任何破坏性操作**
- **证据强度标注**：🟢 = 直接观察到的证据；🟡 = 由代码逻辑推断；⚪ = 尚未证实
- **样本信息**：内核驱动 `zfprotect64.sys` 141,960 字节（版本 2025.1.23.9，PDB: `d:\workspace\nhqdpt_develop\trunk\src\driver\zfprotect\drv\entry.c`）；Hook 组件 `ZfHookWinHook.dll` x64 588,592 字节（PDB: `D:\WorkSpace\nhqdpt\branch\V3.2.1\src\hook\HookPlat\@Output\Release_x64\zfhookwinhook.pdb`）；均为 Win7 WDK 7600 工具链编译
- **服务器**：`<策略服务器IP>`（8443 Web / 15001 策略 RPC / 38443 / 26112 升级下载）；本机客户端 UUID `<本机客户端UUID>`，策略节点 `<策略节点ID>`

---

## 一、结论摘要（TL;DR）

这台电脑上安装的"密保卫士"是一套**企业保密合规终端管控系统**，不是杀毒软件，也不是透明加密软件。它的防护原理由四层组成：

| 层 | 组件 | 作用 | 本机状态 |
|---|---|---|---|
| **内核过滤层** | `zfprotect64.sys`（minifilter + 旧式控制设备） | 文件防篡改、**目录隐身**、进程/模块监控、注册表保护 | 🟢 运行中 |
| **注入探针层** | `zfhookupdat.exe` 服务 + `zhp.exe` 注入宿主 + `ZfHookWinHook.dll` | 把"间谍 DLL"注入目标进程（本机策略=微信）做进程内监控 | 🟢 运行中（4 个 zhp 宿主待命） |
| **内容审查层** | `ZFIControl / ZFIDataServer / ZFIFileContent`（zf.chksdk） | 全盘文件索引 + 涉密标识/个人信息正则扫描，本地加密留存 | 🟢 运行中 |
| **策略通道层** | `itxclient`（itxsvc/itxtray/core.logic/trans） | 与服务器同步策略/配置/升级，通道编码已破解 | 🟢 运行中 |

**它不监控文件内容加密**——全部分析中未发现任何密码学加密文件的能力（驱动无任何 AES/SM4/CNG 导入，无 IRP_MJ_READ 改写逻辑）。“密保”指的是**保密防护**（涉密检查+行为管控），而非透明加解密。

---

## 二、安装形态与组件清单

### 2.1 安装位置 🟢

| 路径 | 内容 |
|---|---|
| `C:\Windows\System32\drivers\zfprotect64.sys` | 内核防护驱动（WoSign 签名，**该 CA 已被吊销**） |
| `C:\Windows\System32\drivers\super64.sys` | 辅助驱动（服务名 `super`，中孚自签，当前**停止**） |
| `C:\Program Files\ZfHookProject-<安装实例GUID>\HookEx\` | 注入平台（**隐藏目录**）：`x86/x64\zhp.exe`（注入宿主）、`KernelStubDll.dll`（管道服务桩）、`ZfHookWinHook.dll`（间谍 DLL）、`zfhookupdat.exe`（策略服务）、`policy\hookproject_defalut.zfpy`（SQLite 策略库） |
| `C:\Program Files (x86)\Intax\` | `itxclient`（策略客户端/托盘）、`zf.chksdk.winclient`（保密检查）、`netchkforjavaclient`（含 `Secpolx32/64.exe`、`super64.sys`）、`patchclient` |
| `C:\ProgramData\Intax\` | `comcfg\cfgsec`（**明文敏感词规则库**）、`zfchksdk\file_index\filesonindex\FileIndex.db`（40MB 加密内容索引）、`log\`（RPC 明文+编码日志） |

### 2.2 服务与进程 🟢

```
zfprotect        Running  （内核服务）
zfhookupdat      Running  （注入策略引擎，自启动）
zhp.exe ×4       运行中   （x86+x64 注入宿主，等待注入目标）
itxsvc ×2 / itxtray / ZFIControl / ZFIDataServer / ZFIFileContent / ZFIUpdateServer  运行中
super            Stopped  （Secpol 用的辅助驱动，当前未启用）
```

注册表自画像：`HKLM\SOFTWARE\WOW6432Node\zfhookproject\zfprotect\procinfo\<路径MD5>` 已积累 **913 个**进程条目（procPath、`singSet` 完整证书链、`isZhognfuSign`、peCompanyName）——其中包括 `Weixin.exe`、`WeChatAppEx.exe`、`crashpad_handler.exe` 全家族 🟢，证明微信运行时被驱动逐一画像过（见 §3.5）。

### 2.3 目录隐身（实证） 🟢

- `dir /a`、PowerShell `Get-ChildItem -Force`、.NET `Directory.GetFiles` 列举 `ZfHookProject-<实例GUID>...\` 均返回 **0 个文件**
- 但按**精确路径**直接读文件全部成功（我读出了其中每个文件）
- 原理见 §3.3——不是 ACL，而是内核在目录枚举结果里**删条目**

---

## 三、内核层防护原理（zfprotect64.sys）

> 逆向方法说明：Ghidra 对该驱动的字符串/IAT 交叉引用全部失效（字符串区混排在 .text 尾部+8 字节标记混淆），故用自研扫描器重建了全部 `call/jmp/lea` 引用图，还原出完整调用结构。下述函数地址均为 Ghidra 加载基址 0x10000 下的 VA。

### 3.1 双通道接口 🟢

- **minifilter**：`FltRegisterFilter`（@0x140E5）注册，高度 400052（FSFilter Top 组），依赖 FltMgr；流句柄上下文 0x404 字节（池标签 `zfpf`）
- **旧式控制设备**：`\Device\zfprotect` + 符号链接 `\??\zfprotect`（用户态 `\\.\zfprotect`），IRP_MJ_DEVICE_CONTROL 分发器 @0x16630，**50+ 个 IOCTL**（0x222588–0x222718 区间）
- **过滤管理器通信端口**：`\zfprotect_notify_port`（`FltCreateCommunicationPort` @0x18123），供用户态服务接收内核事件/下发指令

### 3.2 动态构建的过滤回调表 🟢

`FltRegisterFilter` 使用的操作表**不是静态数据**，而是运行时按开关位动态组装（`FUN_00013b20`）：

| IRP_MJ | Pre 回调 | Post 回调 | 用途 |
|---|---|---|---|
| 0x00 CREATE | `FUN_00012800` | `FUN_00012b60` | 文件打开执法（见 3.4） |
| 0x03 READ | `FUN_00012f00` | `FUN_00012ed0` | 读监控/审计 |
| 0x04 WRITE | `FUN_00012e10` | `FUN_00012ed0` | 写监控/审计 |
| 0x06 SET_INFORMATION | `FUN_00012f30` | `FUN_00013170` | 重命名/删除管控 |
| **0x0C DIRECTORY_CONTROL** | `FUN_00011ad0` | `FUN_000125b0` | **目录隐身（见 3.3）** |
| 0x12 CLEANUP | `FUN_000132e0` | `FUN_00013420` | 关闭处理 |

日志格式串（.text 尾部 0x2C2xx 区）：`FileOpPreCreate/PostCreate/PreRename("FileOpPreRename, oldName:%wz, newName:%wz")/PostRename/PreClose/PostClose` 🟢

### 3.3 目录隐身的实现（本产品最有代表性的自保护技术）

**Pre 回调**（`_OnPreDirectoryControl`，源码路径串 `filter.c:0x60`）🟢：
1. 仅处理 `IRP_MN_QUERY_DIRECTORY`；
2. 取目录名 + 请求进程 PID，调用 `GetSpecFileAccess`（@0x1DCD0）查策略；
3. 命中 `fileAccess=2` → 直接 `STATUS_ACCESS_DENIED` 拒绝整个列举，日志打印 `"_OnPreDirectoryControl Denied, pid:%d, file:%wz"`。

**Post 回调**（@0x125B0）🟢：
1. **先排除自己人**：若请求 PID == 自家受信进程（@0x19FB0 取自）则放行——所以中孚自己的组件能正常看到全部文件；
2. 判断被列目录是否受保护路径（@0x16F30）；
3. 调 `FUN_00012360` 遍历 `FILE_DIRECTORY_INFORMATION` 单向链表：逐条目用 `FUN_00012010` 匹配（查询类支持 1/2/3/0x25/0x26/0xC 等 8 种目录信息类）；
4. 命中的条目被**从链表中剔除**，然后二选一：
   - 缓冲区场景：把过滤后的缓冲拷回 + `FltSetCallbackDataDirty`；
   - MDL 场景：`MmMapLockedPagesSpecifyCache` 映射后改写，再 `FltSetCallbackDataDirty` + **`FltReissueSynchronousIo` 重发 IRP**（经典的"重发缩小结果"手法）。

**效果**：列举 `ZfHookProject-...` 目录时，每个条目的完整路径都命中 `*\ZfHookProject-<实例GUID>...*` 规则 → 全部条目被删 → 看到空目录；而按精确路径打开不走枚举 → 照常成功。这正是实测观察到的行为。🟢

### 3.4 文件保护规则引擎（fileprotect） 🟢

策略以链表存在内核（锁 `0x30790`，链头 `0x307F8`），由注册表灌入：

```
HKLM\SYSTEM\CurrentControlSet\Services\zfprotect\fileprotect\drvPolicy\0000000x
  matchMode  fileAccess  procSet  pathSet
```

本机实时规则（注册表取证）：

| # | matchMode | fileAccess | procSet | pathSet | 语义 |
|---|---|---|---|---|---|
| 00000000 | 1 | **2** | 微信五进程组 | `*\ZfHookWinHook.dll` | **微信被拒绝打开间谍 DLL 文件**（防 DLL 劫持/防二次装载，见 §4.4） |
| 00000001 | 0 | 1 | （空） | `*\ZfHookProject-<实例GUID>...*` | 所有进程禁止写自身安装目录 |
| 00000002 | 0 | 1 | （空） | `*\intax\itxclient\*` | 禁改策略客户端 |
| 00000003 | 0 | 1 | （空） | `*\Intax\zf.chksdk.winclient\*` | 禁改保密检查组件 |
| 00000004 | 0 | 1 | （空） | `*\Intax\netchkforjavaclient\*` | 禁改网络检查组件 |

字段语义（由 `GetSpecFileAccess` @0x1DCD0 + PreCreate @0x12800 逻辑还原）🟡：
- `matchMode=1`：规则作用于 **procSet 命中**的进程；`matchMode=0`：作用于 **procSet 未命中**的进程（procSet 为空 = 作用于全部进程）
- `fileAccess=2` → 一切打开全部 **ACCESS_DENIED**（PreCreate 直接置 `0xC0000022` 并完成 IRP）
- `fileAccess=1` → 仅拒绝**写意图**打开（DesiredAccess 命中 `0x40010006` = DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|…），读放行 → 即"防篡改、可查看"

PreCreate 还叠加了两个规则源：**filemon**（审计，@0x1C520→0x189C0，带共享/属性/Disposition 全量记录后交 `FUN_00024B30` 上报）和 **ijtprotect**（注入保护规则，@0x21530，链表 `0x30998`，同样 procSet+pathSet 结构）🟢。

### 3.5 进程与模块监控 🟢

- `PsSetCreateProcessNotifyRoutine(FUN_00017110)` + `PsSetLoadImageNotifyRoutine(FUN_00017310)`
- 进程创建回调里有一个**分发数组（0x30D00 函数表 / 0x30D80 名字表）**——zfprotect 是"平台驱动"，**其他中孚内核模块可向它注册回调**🟡
- 若新建进程映像位于受保护路径，驱动会先做**路径重写**（@0x16F30 判断 + @0x18580 变换）再分发/记录——与目录隐身配套
- 模块加载回调盯着间谍 DLL 的映像名（编码串 @0x2C370），一旦某进程装载它，立即记录 PID/TID/基址（@0x18830）→ 注入事件入账
- 进程退出走 `FUN_000182C0` 清理；所有事件进环形缓冲（`KeSetEvent` 唤醒刷新，`drveventcollect.c`），经 `\zfprotect_notify_port` 或 `drvEvent` 注册表键（`...\zfprotect\drvEvent`）供用户态消费

### 3.6 注册表保护 🟢

- Vista+ 用 `MmGetSystemRoutineAddress("CmRegisterCallbackEx")` 动态注册（XP 退回 `CmRegisterCallback`），回调 `FUN_0001E860` 跳过 PID 0/4 与自家进程后，按 RegNt 类别分派到 5 个处理函数（`FUN_0001E220/E350/E4D0/E610/E750`）
- 本机实际规则来自 `.zfpy` 策略库 type 26 JSON：🟢
```json
{"pathPolicy":[{"key":"*\\SYSTEM\\*\\services\\zfhookupdat",
  "procSet":"*\\regedit.exe","protectLevel":1,"protectMode":1,"value":"*"}]}
```
即：**regedit.exe 修改 zfhookupdat 服务键会被拦截**。

### 3.7 内核层自保护与反分析 🟢

| 手法 | 证据 |
|---|---|
| **生产环境拒绝卸载** | `FLT_REGISTRATION` 的 FilterUnloadCallback（@0x13560）**仅在调试开关位 3 置位时才填**，平时为 NULL → `FltUnregisterFilter` 不可达 |
| 通信端口按开关位创建 | `FltCreateCommunicationPort` 仅当标志位 5 开启才执行（@0x14110–0x14128） |
| 全局变量 XOR 混淆 | `DAT_00030100/00030108`，栈保护指针用 `key ^ rbp` 校验（@0x17110 可见），运行时 `FUN_00023AA0` 解码 |
| 字符串运行时解密 | UTF-16 明文与 8 字节标记块（`DB 8F 0B 7A…`）+ `0C FF/1A FF` 尾巴混排，由解码函数取用 |
| 反调试 | DriverEntry 前置 `func_0x00036008` 读 `KdDebuggerEnabled`（0xFFFFF78000003020） |
| 假象/威慑 | 导入了 `KeBugCheckEx`，但**全驱动无一处调用**（纯摆设，不会蓝屏）🟢 |
| 策略完整性 | `superproc` 策略带 `policyInCfgCRC32/policyInPolicyCRC32`（本机=249582017），篡改注册表策略会校验失败 |
| 信任进程缓存 | procinfo 913 条（含完整证书链 `singSet`、`isZhognfuSign`），"中孚签名的进程"享受豁免 |

### 3.8 附加：filemon 全局策略与"层"概念 🟡

驱动还从 `...\zfprotect\filemon\global` 读取 `globalPassPath` / `globalPassProcSet` / `globalUsbDeviceSet` 三个名单（U 盘设备名单 `globalUsbDeviceSet` 证明其具备**外设管控**的策略接口；本机该键当前不存在，即未下发）。日志串 `"layer"`/`"load layer name failed"` 表明规则可分"层"。

---

## 四、注入探针层（HookEx 平台）——防护原理中最"侵入"的部分

### 4.1 策略来源 🟢

`policy\hookproject_defalut.zfpy`（SQLite，124 行，t_policy_info: policytype/matchtype/matchstr）：

| policytype | 含义 | 本机内容 |
|---|---|---|
| 0 | 豁免名单 | ~116 条系统/自家进程（svchost、python.exe、zhp.exe、itxsvc.exe…） |
| 1 | 自身目录保护 | `*\zhp.exe`、`*\ZfHookProject-*\*` |
| 2 | **目录隐藏** | `*\ZfHookProject-<实例GUID>...*` |
| 4 | 服务保护 | `zfhookupdat` |
| 26 | 注册表保护 | 上文 JSON |
| **27** | **DLL 注入** | `{"policyNode":[{"fileAccess":2,"pathSet":"*\\ZfHookWinHook.dll","procSet":"*\\weixin.exe;*\\wechat.exe;*\\wechatappex.exe;*\\tencent\\wechat\\*.exe;*\\tencent\\weixin\\*.exe"}]}` |

zfhookupdat.exe 把 type-27 规则翻译成驱动的 `fileprotect\drvPolicy\00000000`（§3.4 表中第一条）——**策略库 → 注册表 → 内核执法**闭环。🟢

### 4.2 注入架构 🟢

```
.zfpy 策略 ──→ zfhookupdat.exe(服务) ──→ zhp.exe x86/x64（注入宿主，本机4个常驻）
                                           │
                        ┌──────────────────┼─────────────────────┐
                        ▼                  ▼                     ▼
              驱动辅助注入            SetWindowsHookEx 全局钩子     KernelStubDll.dll
          （drv\inject64.dll，        （失败时打印                 （宿主内的命名管道服务桩，
            "noDrvInject"=无驱动回退    "SetWindowsHookEx Failed"）  Zf_HookNamedPipe /
            模式字符串 🟢）                                          ZFHK{GUID}_PC%05u）
```

`zhp.exe`（ZfHookEngSrv，PDB 串 `CUIDialog::InjectHookModule / RunAsInjector / _InitInjectPlugin`）装载注入 DLL 后 `GetProcAddress("InjectInit")` 启动。注入完成后**目标进程从未以常规方式打开过间谍 DLL 文件**——该文件被驱动按 procSet=微信 规则封锁（fileAccess=2），既防止用户用木马化的同名 DLL 在微信 DLL 搜索路径里抢先装载（**反 DLL 劫持**），也保证进程内只有受控的一份手工映射实例。🟡

### 4.3 间谍 DLL 的工作流（ZfHookWinHook.dll，微信内） 🟢

PDB 符号与字符串完整还原了类 `InjectedProcess` 的生命周期：

1. `InjectInit/DrvInjectInit`（导出）→ 创建每 PID 命名事件 → `CreateSpyThread`
2. **`InjectedProcess::SpyThreadFunc`**（间谍线程）：`SpyDelayConnectForShellWindow` 延迟连接目标窗口 → 连命名管道 → 发 `register` 命令（字段：`pid_method`、`image`、`create_capture_time`、`inject_method`）
3. 接收指令集（明文命令名，全部在二进制里）：
   `perm_block`（权限阻断）、`tmp_block`、`ae_registerproxy`、`get_cache`/`syncCache`、`setcaps_task`/`CapControl`（能力开关协商，失败打印 `"setcaps" failed`）、`check_ssl`、`removeFile`/`UpdatFile`/`Updat_x_Msgsvrs`（更新消息服务表=注册表 `.Msgsvrs` 键）、`:Update`、`RenewPlugin`、`subscribe`/`unsubscribe`、`Nnt notify`（Mnnt 系列导出）
4. `IssueReadHeaderReq / IssueReadPayloadReq / OnReceiveCompleted` —— **拉取策略与回传数据**
5. 通信层导出：`CommGetClients`、**`CommAllocChatContentRequest`**（聊天内容请求）、`CommAllocJsonRequest`、`CommTransact/CommPost`、`TpipSendRequest`、`MnntPostNotify`、`MnntIsAudienceExists`（**校验接收对象/群是否存在**——受众判定）
6. 策略层导出：`PlcHitTest/PlcHitTestEx/PlcTypeExist`、`GetPermBlockFlags`——命中即按策略阻断/上报
7. hook 引擎：PE 里存在 **`.detourc`/`.detourd` 节（Microsoft Detours）** 🟢；动态解析 `NtCreateFile/NtReadFile/NtWriteFile`（延迟导入）、`SetWindowsHookExW/CallNextHookEx/UnhookWindowsHookEx`、`SetThreadContext/GetThreadContext/VirtualProtectEx`（线程劫持辅助）、`RtlCaptureStackBackTrace`（调用栈取证）

### 4.4 插件家族（平台能力上限） 🟢

`ZfHookWinHook.dll` 内置 `PluginManager`，可装载以下插件（本机**均未部署**，仅平台在位）：

```
ZfHookEng.dll                    引擎
ZfHookFilemmPlugin.dll           文件监控
ZfHookSendFilePlugin.dll         发送文件拦截（IM 外发管控）
ZfHookExeCtrlPlugin.dll          可执行程序管控
ZfHookPrintCtrlPlugin.dll        打印管控
ZfHookDirReadPlugin.dll          目录读取监控
ZfHookScreenPlugin.dll           截屏/屏幕管控
ZfHookWaterMarkInjectPlugin.dll  屏幕水印
ZfHookSFDlpPlugin.dll            结构化文件 DLP
ZfHookUiaPlugin.dll              UI 自动化监控
ZfHookUnitedPlugin.dll           联合插件
ZFNotifyMsg.exe / ZfHookConsole.exe  用户提示/控制台
SSLPC64.dll                      SSL 检查组件
*mjbz.hook*.dll                  产品自定义 hook DLL 命名模式
```

另有 Chrome 专门决策串：`"WinHook: chrome network proc, need inject"` / `"chrome ui proc, need inject"` / `"chrome no need inject child proc"` ——**平台具备对浏览器按进程角色选择性注入的能力**（本机策略未启用）。🟢

### 4.5 本机实际部署评估 🟢

- 注入规则（type 27 + drvPolicy 00000000）**只指向微信**
- procinfo 里有微信全家族记录 → 微信曾在本机运行并被驱动记录
- 插件 DLL 不在盘上 → 当前部署 = "平台就位 + 微信注入策略待命"，未见发送文件/截屏/打印等具体拦截插件的落地
- 微信当前未运行，4 个 zhp 宿主待命 —— 一旦微信启动，注入链路具备全部条件 🟡

---

## 五、内容审查层（zf.chksdk / ZFI 四件套） 🟢

运行中的 `ZFIControl.exe`、`ZFIDataServer.exe`、`ZFIFileContent.exe`、`ZFIUpdateServer.exe` 构成本地"保密检查"引擎：

1. **敏感规则库（明文！）** `C:\ProgramData\Intax\comcfg\cfgsec`：
   ```json
   {"ver":"10","name":"self_define_sec_level","data":[32 条正则]}
   ```
   - **type 2 = 涉密文件标识**：`国发/中办发/明电/工作秘密/内部文件/会议资料/特此公告/非公开文件` 等
   - **type 3 = 个人信息**：`身份证/手机号/银行卡/邮箱/家庭住址/护照号/车牌号/统一社会信用代码/港澳/台湾通行证/出生年月/营业执照号码/军官证号/车辆识别码/组织机构代码` 等
   - 每条规则带 `hitCounts` 字段 —— **本地扫描正在计数命中** 🟢
2. **本地文件索引**：`FileIndex.db` 40MB + `FileIndexReq.db`，头部 `CE CB EC 84 14 3E 89 52` = **sqlite3mc（SQLite Multiple Ciphers）加密库**；插件目录里有 `sqlite3mc_dll-Win32.dll` 实锤加密器、`libzfd7z.dll`（7-Zip 改）负责**压缩包内容解包扫描**
3. `judgeAgent\agent.db` 与 `registry\sdkregistry.db`：自定义加密（魔数 `B6 74 BF 62 06 DC E4 57…`），内容未破解 ⚪
4. 网络 检查组件 `netchkforjavaclient`（`Secpolx32/64.exe` + `super64.sys`）当前停止（`super` 服务 Stopped）🟢

> 说明：这一层是**检查/发现**（DLP 式扫描+索引+命中统计），不是加密。哪个目录会被扫描、命中结果何时回传服务器，取决于未截获的完整主机策略（见 §7）。

---

## 六、策略通道层（itxclient）与传输编码破解

### 6.1 通道架构 🟢

- 主策略 RPC：`<策略服务器IP>:15001`（`TransNodeMgr::NetConnectEx`）
- 升级下载：`https://<策略服务器IP>:26112/share/Clients/Windows/Windows/single/MBWS_..._.exe` + `.sign` 签名文件
- 客户端组件升级清单（解码自日志）：`itxclient 9.4.0.67565`、`zf.chksdk.winclient 2.4.0.67565`、`patchclient 1.0.9.67662`、`netchkforjavaclient 2.4.0.67567`

### 6.2 编码方案（已破解） 🟢

日志中的策略串（如 `ZD1vbXBrcD0l...`）既非标准 Base64 明文也非 TLS 密文——分析 `cpp.trans.ext\transinfo.ext.dll`、`trans.ext.dll`、`core.logic.dll` 均内嵌**标准 Base64 字母表**，最终确认：

```
payload = base64( XOR(明文JSON, 0x1F) )
```

单字节异或 0x1F，`ZD1vbXBr` → `{"prot`。全部日志 token 解密后均为合法 JSON 🟢。示例：

```json
{"host_id":"<本机客户端UUID>...","proto":"2","config_list":{"ignore_path":"30","self_define_sec_level":"10","itx":"441"}}
{"proto":"0","id":"<本机客户端UUID>...","node_id":"<策略节点ID>...","host_version":"3","policy_version":""}
```

> 这是**编码**（obfuscation）不是加密——无密钥、无完整性校验，只用于规避肉眼/普通抓包工具的直接阅读。服务器侧为"配置版本号 + 增量同步"模式（`CfgMgr.Sync / PolicyMgr.Sync / hostsynor.SyncHostPolicy`），日志中最近一次主机策略响应为 `host policy not changed`，因此**完整主机策略报文未在日志中出现** ⚪（只能看到本机注册表/zfpy 落地结果）。

---

## 七、观察 vs 推断 vs 未知

### 已证实（观察） 🟢
- 目录隐身机制及其完整内核实现路径
- fileprotect 规则语义（fileAccess 1/2、matchMode 0/1、procSet/pathSet）
- 微信专属注入策略与 50+ IOCTL 的控制面存在
- 注册表保护规则（regedit.exe vs zfhookupdat 服务键）
- 驱动平台化（第三方内核模块回调注册表）、913 条进程证书画像缓存
- 生产环境不可卸载（无 Unload 回调）、字符串/全局混淆、KeBugCheckEx 摆设
- 敏感词规则库明文在盘 + 命中计数；本地加密文件索引（sqlite3mc）与压缩包扫描能力
- 传输编码 = base64(XOR 0x1F)，并解出实况 RPC
- 插件家族名单（发送文件/截屏/打印/水印/DLP/UIA 等）与 Chrome 选择性注入决策串

### 推断（高置信） 🟡
- 间谍 DLL 采用"宿主读文件 + 手工映射（驱动/线程劫持辅助）"方式注入，目标进程自身不打开 DLL 文件；`fileAccess=2` 规则同时充当反 DLL 劫持
- `filemon\global` 的 `globalUsbDeviceSet` 是外设（U 盘）管控的策略接口
- ijtprotect 规则链（0x30998）服务于注入文件保护场景

### 未知（诚实声明） ⚪
- `FileIndex.db / agent.db / sdkregistry.db` 的内容（密钥在运行进程内存内）
- 完整主机策略报文（服务器回复 "not changed"，日志无全文）；截获需在策略变更时抓包或高权限复制内存
- 各插件（SendFile/Screen 等）的具体拦截逻辑——本机未部署插件二进制，无法逆向
- `matchtype` 257（=1|0x100）中 0x100 标志的精确含义
- 服务器 38443/8443 端口的具体业务分工

---

## 八、给使用者的防护原理总结（通俗版）

1. **藏**：内核在目录枚举结果里删掉自家文件的条目——你"看不见"它，但它都在。
2. **锁**：谁都不能改它的安装目录和服务键（改了注册表有 CRC 校验兜底），驱动本身生产模式不给卸载入口。
3. **盯**：每个新进程出生都被记录路径+数字证书链（913 条），加载的每个模块被核对——为"信任中孚签名=放行、非信任=按策略"提供依据。
4. **钻**：向微信（以及策略指定的任何 IM/浏览器）进程里注入"间谍线程"，在进程内部做策略命中测试，经命名管道回传宿主，宿主再走 15001 端口回服务器；受众校验（MnntIsAudienceExists）说明其能按**聊天对象**做差异化管控。
5. **翻**：全盘文件被正则扫描（涉密标识 16 类 + 个人信息 16 类），命中计数、索引入加密库，压缩包也要解开看。
6. **报**：一切结果通过"伪 Base64"（XOR 0x1F）编码回传 <策略服务器IP>，策略也是从那里同步下来的——这台终端是服务端的眼睛和手，而非一台独立的杀毒工具。

## 附录 A：主要 IOC 速查

```
驱动/服务   zfprotect64.sys / super64.sys / 服务 zfprotect, super, zfhookupdat
设备/端口   \Device\zfprotect  \\.\zfprotect  \zfprotect_notify_port
进程        zhp.exe, zfhookupdat.exe, itxsvc.exe, itxtray.exe, ZFIControl.exe,
            ZFIDataServer.exe, ZFIFileContent.exe, ZFIUpdateServer.exe
目录        C:\Program Files\ZfHookProject-<安装实例GUID>\
            C:\Program Files (x86)\Intax\{itxclient,zf.chksdk.winclient,netchkforjavaclient,patchclient}
            C:\ProgramData\Intax\
注册表      HKLM\SYSTEM\CurrentControlSet\Services\zfprotect\{fileprotect\drvPolicy,superproc,filemon,ijtprotect}
            HKLM\SOFTWARE\WOW6432Node\zfhookproject\{zfprotect\procinfo,.Msgsvrs}
管道        \\.\Pipe\Zf_HookNamedPipe  \\.\pipe\ZFHK{40A3952A-...}_PC%05u
全局对象    Global\ZFInject.Cache.INJECTFLAG.%u  Global\ZFInject.Cache.ShareName.FF15
策略库      policy\hookproject_defalut.zfpy (SQLite)  comcfg\cfgsec (明文JSON)
服务器      <策略服务器IP>:8443/15001/38443/26112
编码        base64( XOR(json, 0x1F) )
```

## 附录 B：关键函数地址索引（zfprotect64.sys，基址 0x10000）

```
DriverEntry            0x36064          主初始化           0x11070
FltRegisterFilter      0x140E5          操作表构建         0x13B20
Pre/Post 目录枚举      0x11AD0/0x125B0  条目过滤           0x12360
PreCreate              0x12800          GetSpecFileAccess  0x1DCD0
进程创建/模块回调      0x17110/0x17310  注册表回调          0x1E860
IOCTL 分发             0x16630          通信端口建立       0x18030→0x18123
filemon 策略装载       0x1B3B4 区       superproc 装载      0x1A319 区
```

