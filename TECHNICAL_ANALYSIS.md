# DynamoRIO 反检测技术分析 - 最终报告

## 执行日期
2026-04-25

## 问题诊断

### 样本行为
样本 `8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2` 检测到 DynamoRIO 并拒绝执行加密代码。

### 证据
- ✅ DynamoRIO 成功捕获 245,980+ 控制流事件
- ✅ PEB BeingDebugged 标志已修补
- ❌ 所有执行都在系统 DLL 中（0x77..., 0x76...）
- ❌ 样本代码（base: 0x00c40000）完全没有执行

## 解决方案尝试

### 方法 1: PEB 模块链表解链

#### 理论基础
Windows 进程的 PEB (Process Environment Block) 维护了三个模块链表：
- InLoadOrderModuleList
- InMemoryOrderModuleList  
- InInitializationOrderModuleList

恶意软件可以通过遍历这些链表来检测调试器和分析工具。

#### 实施步骤

1. **代码修改**
   - 修改 `shrike_drcov_nudge.c`，将 PEB 操作移到 `dr_client_main` 最开始
   - 在任何 DynamoRIO 模块初始化之前执行解链

2. **编译**
   - 第一次：使用 `/MD`（动态链接 CRT），生成 26KB DLL
     - 问题：依赖 VCRUNTIME140.dll，guest VM 中不存在
   - 第二次：使用 `/MT`（静态链接 CRT），生成 100KB DLL
     - ✅ 成功编译，无额外依赖
     - Build ID: `STEALTH_20260425_FINAL`

3. **部署**
   - ✅ 使用 `06_install_guest_runtime.ps1` 成功部署
   - ✅ 验证 guest VM 中的 DLL（MD5: 434BCFA58475B182A925B42B9C5A8124）
   - ✅ 刷新快照并验证快照中的 DLL

4. **测试结果**
   - ✅ 新 DLL 被成功加载（PID 5552）
   - ❌ PEB 解链失败：`unlinked_count:0`
   - ❌ 样本代码仍然没有执行

### 根本原因分析

#### 关键发现

通过对比 `module_load` 事件和 `peb_module` 事件，发现：

**module_load 事件（DynamoRIO 报告的加载模块）：**
```json
{"event":"module_load","path":"dynamorio.dll","base":"0x753c0000","size":1581056}
{"event":"module_load","path":"drmgr.dll","base":"0x75300000","size":49152}
{"event":"module_load","path":"drwrap.dll","base":"0x752e0000","size":45056}
{"event":"module_load","path":"shrike_drcov_nudge_final.dll","base":"0x75310000","size":118784}
```

**peb_module 事件（PEB 链表中的模块）：**
```json
{"event":"peb_module","name":"8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2","base":"0x002f0000"}
{"event":"peb_module","name":"ntdll.dll","base":"0x777a0000"}
{"event":"peb_module","name":"KERNEL32.DLL","base":"0x76f30000"}
... (共 17 个模块，全部是系统 DLL)
```

**结论：DynamoRIO 模块完全不在 PEB 链表中！**

#### 技术解释

DynamoRIO 使用了以下技术之一来加载模块：

1. **手动映射 (Manual Mapping)**
   - 直接读取 PE 文件并映射到内存
   - 手动处理重定位和导入表
   - 绕过 Windows 加载器（LoadLibrary）
   - 模块不会被添加到 PEB 链表

2. **私有加载器**
   - DynamoRIO 有自己的模块加载机制
   - 不通过 ntdll.dll 的 LdrLoadDll
   - 避免触发加载器通知回调

3. **内存注入**
   - 将 DLL 代码直接注入到进程内存
   - 不创建标准的 LDR_DATA_TABLE_ENTRY 结构

#### 为什么 PEB 解链无法工作

```
PEB 链表中的模块（17 个）:
├─ 样本.exe
├─ ntdll.dll
├─ KERNEL32.DLL
├─ KERNELBASE.dll
└─ ... (其他系统 DLL)

DynamoRIO 模块（不在 PEB 中）:
├─ dynamorio.dll      ← 手动映射，不在 PEB
├─ drmgr.dll          ← 手动映射，不在 PEB
├─ drwrap.dll         ← 手动映射，不在 PEB
└─ shrike_drcov_nudge.dll ← 手动映射，不在 PEB
```

由于 DynamoRIO 模块从未被添加到 PEB 链表，我们的解链代码无法找到它们，因此 `unlinked_count` 始终为 0。

## 样本的检测机制

基于以上分析，样本可能使用以下方法检测 DynamoRIO：

### 方法 1: 内存扫描
扫描进程内存空间，查找 DynamoRIO 的特征签名：
- "DynamoRIO" 字符串
- 特定的代码模式
- 已知的函数签名

### 方法 2: 模块枚举（非 PEB）
使用其他 API 枚举模块：
- `EnumProcessModules` (PSAPI)
- `CreateToolhelp32Snapshot` + `Module32First/Next`
- `NtQuerySystemInformation` (SystemModuleInformation)

这些 API 可以检测到手动映射的模块。

### 方法 3: 行为检测
检测 DynamoRIO 的运行时行为：
- 异常的内存保护属性
- 大量的代码缓存区域
- 异常的执行流程（代码缓存跳转）

## 替代解决方案

### 方案 A: API Hooking（推荐）

Hook 模块枚举 API，过滤掉 DynamoRIO 模块：

```c
// Hook EnumProcessModules
BOOL WINAPI Hook_EnumProcessModules(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
) {
    BOOL result = Real_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
    
    // 过滤掉 DynamoRIO 模块
    filter_dynamorio_modules(lphModule, lpcbNeeded);
    
    return result;
}

// Hook CreateToolhelp32Snapshot
HANDLE WINAPI Hook_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
) {
    HANDLE hSnapshot = Real_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    
    // 标记快照，在 Module32First/Next 中过滤
    mark_snapshot_for_filtering(hSnapshot);
    
    return hSnapshot;
}
```

**优点**：
- 可以拦截所有模块枚举方法
- 不依赖 PEB 链表
- 可以处理手动映射的模块

**缺点**：
- 需要 hook 多个 API
- 可能被反 hook 技术检测

### 方案 B: 内存隐藏

修改 DynamoRIO 模块的内存属性，使其难以被扫描：

```c
// 将 DynamoRIO 代码区域标记为 PAGE_NOACCESS
VirtualProtect(dynamorio_base, dynamorio_size, PAGE_NOACCESS, &old_protect);

// 在需要执行时临时恢复
VirtualProtect(dynamorio_base, dynamorio_size, PAGE_EXECUTE_READ, &old_protect);
```

**优点**：
- 可以对抗内存扫描
- 实现相对简单

**缺点**：
- 性能开销大
- 可能导致访问违例
- 无法对抗 API 枚举

### 方案 C: Intel PT（最佳方案）

使用 Intel Processor Trace 进行硬件级追踪：

**优点**：
- 完全无软件痕迹
- 无法被检测
- 性能开销小

**缺点**：
- 需要硬件支持（Intel CPU）
- 实现复杂
- trace 数据量大

### 方案 D: 模块重命名

将 DynamoRIO DLL 重命名为系统 DLL 名称：

```
dynamorio.dll  → msvcr120.dll
drmgr.dll      → msvcp120.dll
drwrap.dll     → vcruntime140.dll
```

**优点**：
- 简单易实现
- 可以绕过简单的名称检查

**缺点**：
- 容易被签名验证检测
- 无法对抗深度检查

## 部署问题排查

在实施过程中遇到的部署问题及解决方案：

### 问题 1: VCRUNTIME140.dll 依赖

**现象**：第一次编译的 DLL（26KB）无法加载

**原因**：使用 `/MD` 编译，依赖 VCRUNTIME140.dll，guest VM 中不存在

**解决**：使用 `/MT` 静态链接 CRT

### 问题 2: 快照状态不一致

**现象**：多次部署后 trace 仍显示旧 DLL

**原因**：
- 快照刷新时机不对
- VM 状态缓存
- 多个 DLL 位置（bin32/bin64）

**解决**：
1. 恢复到 maintenance-base 快照
2. 部署新 DLL
3. 验证 DLL（MD5）
4. 停止 VM
5. 刷新快照
6. 验证快照中的 DLL
7. 运行测试

### 问题 3: 多个进程使用不同 DLL

**现象**：5 个进程中，4 个使用旧 DLL，1 个使用新 DLL

**原因**：
- bin64 目录中的 DLL 未更新
- 某些进程可能从缓存加载

**解决**：确保 bin32 和 bin64 都更新

## 文件清单

### 已修改
- ✅ `README.md` - 添加了详细的问题诊断
- ✅ `windows_host/drio_client/src/shrike_drcov_nudge.c` - 修改了 PEB 操作时机
- ✅ `windows_host/drio_client/build_client.ps1` - 创建了编译脚本

### 已生成
- ✅ `windows_host/drio_client/bin32/release/shrike_drcov_nudge_final.dll` - 新 DLL（100KB，/MT）
- ✅ `guest/runtime/drio/bin32/shrike_drcov_nudge.dll` - 已更新为新 DLL
- ✅ `FINAL_SUMMARY.md` - 工作总结
- ✅ `TECHNICAL_ANALYSIS.md` - 本技术分析报告

### 验证数据
- 新 DLL MD5: `434BCFA58475B182A925B42B9C5A8124`
- 新 DLL 大小: 101888 字节
- Build ID: `STEALTH_20260425_FINAL`
- 测试报告: `reports/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2_20260425_124349/`

## 结论

1. **PEB 解链方法从根本上无法工作**
   - DynamoRIO 使用手动映射，模块不在 PEB 链表中
   - 代码实现正确，但目标不存在

2. **样本的检测机制更复杂**
   - 不仅仅依赖 PEB 链表
   - 可能使用内存扫描或其他 API

3. **推荐的解决方案**
   - 短期：API Hooking（EnumProcessModules, CreateToolhelp32Snapshot）
   - 长期：Intel PT 硬件追踪

4. **技术收获**
   - 深入理解了 Windows 模块加载机制
   - 掌握了 PEB 结构和链表操作
   - 了解了 DynamoRIO 的内部实现

## 下一步行动

### 立即可行
1. 实施 API Hooking 方案
2. Hook `EnumProcessModules` 和 `CreateToolhelp32Snapshot`
3. 过滤掉 DynamoRIO 相关模块

### 中期目标
1. 研究样本的具体检测代码
2. 使用 IDA Pro 静态分析样本
3. 确定样本使用的检测方法

### 长期目标
1. 评估 Intel PT 的可行性
2. 构建完整的反检测框架
3. 支持多种追踪技术

## 参考资料

### Windows 内部机制
- PEB 结构定义：https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
- LDR_DATA_TABLE_ENTRY：https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm

### DynamoRIO
- 官方文档：https://dynamorio.org/
- 源代码：https://github.com/DynamoRIO/dynamorio

### 反检测技术
- Manual Mapping：https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
- API Hooking：https://www.codeproject.com/Articles/2082/API-hooking-revealed
