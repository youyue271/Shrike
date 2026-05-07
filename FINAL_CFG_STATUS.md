# CFG 提取最终状态报告

## 工作总结

经过完整的诊断和多次修复尝试，成功完成了以下工作：

### ✅ 已完成
1. **成功运行沙箱并捕获 CFG 数据**
   - DynamoRIO 成功捕获了 49,200 行原始 trace 数据
   - 包含 23,211 个基本块、9,556 次调用、10,924 次分支
   - Sysmon 捕获了 14,123 个行为事件

2. **诊断根本问题**
   - 样本检测到 DynamoRIO 并拒绝执行恶意代码
   - 只执行系统 DLL 的清理代码，样本自身代码从未执行

3. **尝试的修复方案**
   - ✅ 下载 DynamoRIO (313MB)
   - ✅ 修改源代码添加所有 DLL 变体到隐藏列表
   - ✅ 调整 PEB unlinking 执行时机（从早期移到 DR 初始化之后）
   - ✅ 重新编译 DLL (3次)
   - ✅ 更新 guest runtime (3次)
   - ✅ 刷新快照 (3次)

### ❌ 核心问题

**PEB Unlinking 无法工作的根本原因**：

DynamoRIO 模块（`dynamorio.dll`, `drmgr.dll`, `drwrap.dll`, `shrike_drcov_nudge.dll`）**不在 PEB 的 `InLoadOrderModuleList` 链表中**。

证据：
```
PEB 模块列表（从 trace 数据）：
- 样本 EXE
- ntdll.dll
- KERNEL32.DLL
- KERNELBASE.dll
- ADVAPI32.dll
- ... (其他系统 DLL)
- ❌ 没有任何 DynamoRIO 模块
```

但 `module_load` 事件显示这些模块确实被加载了：
```
{"event":"module_load","path":"dynamorio.dll","base":"0x74ab0000"}
{"event":"module_load","path":"drmgr.dll","base":"0x74ad0000"}
{"event":"module_load","path":"drwrap.dll","base":"0x74ab0000"}
{"event":"module_load","path":"shrike_drcov_nudge.dll","base":"0x74ae0000"}
```

**结论**：DynamoRIO 使用了特殊的加载机制（可能是手动映射或私有加载），绕过了标准的 Windows 加载器，因此这些模块不会出现在 PEB 链表中。PEB unlinking 方法对 DynamoRIO 无效。

## 当前数据

虽然样本没有执行恶意代码，但已获得：

### 原始 Trace 数据
```
reports/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2_20260426_115652/raw/
├── trace.06016.ndjson          # 49,200 行 CFG 事件
├── sysmon_process_events.json  # 99 个进程事件
├── sysmon_file_events.json     # 156 个文件事件
├── sysmon_registry_events.json # 10,363 个注册表事件
├── sysmon_injection_events.json # 3,269 个注入事件
└── 其他行为数据
```

### CFG 统计
- **基本块**：23,211 个（全部在系统 DLL 中）
- **调用**：9,556 次
- **分支**：10,924 次
- **样本执行**：0 个基本块

## 替代方案

由于 PEB unlinking 对 DynamoRIO 无效，建议考虑以下替代方案：

### 方案 1：Intel PT (Processor Trace)
- **优点**：硬件级别 trace，完全透明，无软件痕迹
- **缺点**：需要硬件支持，数据量巨大，解析复杂
- **状态**：README 提到正在探索

### 方案 2：修改样本
- **方法**：Patch 掉样本中的反调试/反虚拟化检测代码
- **优点**：可以获得完整 CFG
- **缺点**：需要逆向分析，可能破坏样本行为

### 方案 3：使用其他 trace 工具
- **Pin**：Intel 的动态插桩工具（可能有类似问题）
- **Frida**：动态插桩框架（更容易被检测）
- **QEMU**：全系统模拟（性能较差但更隐蔽）

### 方案 4：API Hook 方法
当前实现已经有 API hook（4个函数），但样本可能：
- 直接读取 PEB 结构（绕过 API）
- 使用其他检测方法（CPUID, RDTSC, 时序分析等）

可以尝试：
- Hook 更多 API
- Hook ntdll 的底层函数
- 使用内核驱动级别的 hook

### 方案 5：接受部分 CFG
- 当前已获得系统 DLL 的 CFG
- 可以分析样本的静态 CFG（IDA/Ghidra）
- 结合 Sysmon 行为数据进行分析

## 技术细节

### 修改的文件
1. `windows_host/drio_client/src/shrike_drcov_nudge.c`
   - 添加了所有 DLL 变体到隐藏列表
   - 将 PEB unlinking 移到 DR 初始化之后

2. `windows_host/drio_client/bin32/release/shrike_drcov_nudge.dll`
   - 最新编译：2026-04-27 07:29:23
   - SHA256: 4605A55A9E17AC336227A924989AFD25FA8E946607E44AFCF1909F0E39371A49

3. `windows_host/drio_client/bin64/release/shrike_drcov_nudge.dll`
   - 最新编译：2026-04-27 07:29:24
   - SHA256: 43F7B712D2ABE62C53781302C3708CD6EE72132A38BC014F91BF3825A3501508

### 编译记录
- Build ID: FF0F78BA_20260427072853
- Source SHA256: FF0F78BA91530D900B72A1393092F8B7F18B623D949FCE39F3279B7F0B196F64

## 下一步建议

1. **短期**：分析现有的系统 DLL CFG 和 Sysmon 数据
2. **中期**：研究 Intel PT 或其他硬件级 trace 方案
3. **长期**：考虑使用内核驱动级别的隐藏技术

## 相关文档
- `README.md` - 沙箱文档
- `FIX_PEB_UNLINKING.md` - PEB unlinking 修复尝试
- `CFG_EXTRACTION_STATUS.md` - 之前的状态报告
- `PROBLEM_DIAGNOSIS.md` - 问题诊断（如果存在）

## 时间线
- **2026-04-26 11:51** - 首次运行样本分析
- **2026-04-26 12:01** - 诊断问题并首次修复
- **2026-04-27 00:19** - 下载 DynamoRIO 并重新编译
- **2026-04-27 07:29** - 调整 PEB unlinking 时机并再次编译
- **2026-04-27 07:40** - 最终测试，确认 PEB unlinking 对 DynamoRIO 无效

## 结论

PEB unlinking 方法无法隐藏 DynamoRIO，因为 DynamoRIO 的模块不在标准的 PEB 链表中。这是 DynamoRIO 设计的一部分，用于提高性能和减少对目标进程的影响。

要获得完整的恶意样本 CFG，需要使用硬件级 trace（Intel PT）或修改样本本身。当前的软件插桩方法（DynamoRIO, Pin, Frida）都容易被检测。
