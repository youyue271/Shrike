# API Hook 反检测方案 - 实施报告

## 执行日期
2026-04-25

## 方案概述

在发现 PEB 解链方法无法工作后（DynamoRIO 使用手动映射，模块不在 PEB 链表中），我们实施了 API Hooking 方案来拦截模块枚举 API。

## 实施细节

### Hook 的 API

1. **K32EnumProcessModules** (PSAPI)
   - 拦截模块枚举
   - 过滤掉 DynamoRIO 相关模块

2. **CreateToolhelp32Snapshot** (Toolhelp32)
   - 拦截快照创建
   - 标记需要过滤的快照

3. **Module32First** (Toolhelp32)
   - 拦截第一个模块枚举
   - 跳过 DynamoRIO 模块

4. **Module32Next** (Toolhelp32)
   - 拦截后续模块枚举
   - 跳过 DynamoRIO 模块

### 代码实现

```c
/* Helper function to check if a module should be hidden */
static bool
should_hide_module(const char *module_name)
{
    const char *hide_list[] = {
        "dynamorio.dll",
        "drmgr.dll",
        "drwrap.dll",
        "drutil.dll",
        "shrike_drcov_nudge.dll",
        "shrike_drcov_nudge_final.dll",
        "shrike_drcov_nudge_new.dll",
        NULL
    };

    if (module_name == NULL)
        return false;

    for (int i = 0; hide_list[i] != NULL; i++) {
        if (_stricmp(module_name, hide_list[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Hook for K32EnumProcessModules */
static void
wrap_K32EnumProcessModules_post(void *wrapcxt, void *user_data)
{
    HMODULE *lphModule = (HMODULE *)drwrap_get_arg(wrapcxt, 1);
    DWORD cb = (DWORD)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpcbNeeded = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    BOOL result = (BOOL)(ptr_uint_t)drwrap_get_retval(wrapcxt);

    if (!result || lphModule == NULL || lpcbNeeded == NULL)
        return;

    /* Filter out DynamoRIO modules */
    DWORD module_count = cb / sizeof(HMODULE);
    DWORD filtered_count = 0;

    for (DWORD i = 0; i < module_count; i++) {
        if (lphModule[i] == NULL)
            continue;

        char module_name[MAX_PATH];
        if (GetModuleBaseNameA(GetCurrentProcess(), lphModule[i], module_name, sizeof(module_name)) > 0) {
            if (!should_hide_module(module_name)) {
                if (filtered_count != i) {
                    lphModule[filtered_count] = lphModule[i];
                }
                filtered_count++;
            }
        }
    }

    /* Update the count */
    *lpcbNeeded = filtered_count * sizeof(HMODULE);
}
```

### 编译

```batch
cl.exe /LD /O2 /MT /DWINDOWS /DX86_32 /DBUILD_ID="APIHOOK_20260425_V1" ^
    /I"D:\Temp\DynamoRIO\include\" ^
    /I"D:\Temp\DynamoRIO\ext\include\" ^
    shrike_drcov_nudge.c ^
    /link /OUT:shrike_drcov_nudge_apihook.dll ^
    D:\Temp\DynamoRIO\lib32\release\dynamorio.lib ^
    D:\Temp\DynamoRIO\ext\lib32\release\drmgr.lib ^
    D:\Temp\DynamoRIO\ext\lib32\release\drutil.lib ^
    D:\Temp\DynamoRIO\ext\lib32\release\drwrap.lib ^
    ws2_32.lib psapi.lib
```

### 部署

- ✅ 编译成功：102KB DLL
- ✅ Build ID: `APIHOOK_20260425_V1`
- ✅ 部署到 guest VM
- ✅ 快照已刷新
- ✅ MD5: `312858DAAF249657ECEAD04CB542C2BA`

## 测试结果

### ✅ 成功的部分

1. **API Hook 注册成功**
```json
{"event":"api_hook","function":"K32EnumProcessModules","status":"hooked"}
{"event":"api_hook","function":"CreateToolhelp32Snapshot","status":"hooked"}
{"event":"api_hook","function":"Module32First","status":"hooked"}
{"event":"api_hook","function":"Module32Next","status":"hooked"}
```

2. **DLL 正确加载**
```json
{"event":"client_metadata","build_id":"APIHOOK_20260425_V1","bypass_antidebug":true,"pid":2580}
```

3. **PEB 链表正常**
   - 17 个模块，全部是系统 DLL
   - 没有 DynamoRIO 模块

### ❌ 失败的部分

1. **样本代码完全没有执行**
   - 样本加载到 `0x00e70000`
   - 入口点从未被调用
   - 0 个样本代码执行事件

2. **API Hook 从未被触发**
   - 没有模块被过滤
   - 样本没有调用我们 hook 的 API

## 根本原因分析

### 样本的检测机制

样本在初始化阶段就检测到了 DynamoRIO，可能使用了以下方法之一：

#### 1. 内存扫描
扫描进程内存空间，查找 DynamoRIO 的特征签名：
- "DynamoRIO" 字符串
- "dynamorio.dll" 路径
- 特定的代码模式
- 已知的函数签名

#### 2. 代码缓存检测
DynamoRIO 会创建大量的代码缓存区域：
- 检测异常的内存保护属性（RWX）
- 检测大量的 VirtualAlloc 分配
- 检测代码缓存的特征模式

#### 3. 执行流程异常
DynamoRIO 会修改执行流程：
- 所有代码通过代码缓存执行
- 间接跳转被重定向
- 异常处理被拦截

#### 4. 时序检测
DynamoRIO 会引入性能开销：
- RDTSC 指令检测
- QueryPerformanceCounter 检测
- 执行时间异常

#### 5. 直接读取 PEB
不通过 API，直接使用汇编读取 PEB：
```asm
mov eax, fs:[0x30]  ; 获取 PEB
mov eax, [eax+0x0C] ; 获取 Ldr
; 遍历模块链表
```

虽然 DynamoRIO 模块不在 PEB 链表中，但样本可能检测到：
- PEB 结构的异常
- 模块数量不匹配
- 内存布局异常

## 为什么 API Hook 无效

### 问题 1: 样本不调用这些 API

样本可能使用了更底层的检测方法：
- 直接读取 PEB（不通过 API）
- 内存扫描（不需要枚举模块）
- 代码缓存检测（不需要模块信息）

### 问题 2: 检测发生在初始化阶段

样本在入口点执行之前就检测到了 DynamoRIO：
- 可能在 DLL 加载时（DllMain）
- 可能在 TLS 回调中
- 可能在 CRT 初始化时

### 问题 3: DynamoRIO 的痕迹太明显

即使隐藏了模块列表，DynamoRIO 仍然有很多痕迹：
- 大量的代码缓存内存
- 修改的执行流程
- 性能开销
- 异常的内存布局

## 证据

### Trace 数据分析

```
样本加载: 0x00e70000 - 0x00ffb000 (1617920 字节)
入口点执行: 0 次
样本代码执行: 0 个事件
系统 DLL 执行: 49200 个事件
```

### 执行流程

```
1. DynamoRIO 初始化
2. 加载样本到 0x00e70000
3. API Hook 注册成功
4. 系统 DLL 初始化（ntdll, kernel32, etc.）
5. 样本检测到 DynamoRIO
6. 样本拒绝执行，直接退出
7. 入口点从未被调用
```

## 结论

### API Hook 方案的局限性

1. **只能拦截 API 调用**
   - 无法防御直接内存访问
   - 无法防御汇编级别的检测

2. **无法隐藏 DynamoRIO 的运行时痕迹**
   - 代码缓存区域
   - 执行流程修改
   - 性能开销

3. **检测发生在 Hook 生效之前**
   - 样本在初始化阶段就检测到了
   - Hook 从未被触发

### 为什么所有方法都失败了

| 方法 | 状态 | 失败原因 |
|------|------|----------|
| PEB 解链 | ❌ | DynamoRIO 模块不在 PEB 中 |
| API Hook | ❌ | 样本不调用这些 API |
| PEB 修补 | ✅ | 但样本不检查 BeingDebugged |

**根本问题**：样本使用了更底层的检测方法，不依赖 PEB 链表或 API 调用。

## 推荐方案

### 方案 A: Intel PT（强烈推荐）

**优点**：
- 硬件级追踪，完全无软件痕迹
- 无法被检测
- 性能开销小（~5%）
- 不修改进程内存

**缺点**：
- 需要硬件支持（Intel CPU with PT）
- 实现复杂
- Trace 数据量大

**实施步骤**：
1. 检查 CPU 是否支持 Intel PT
2. 使用 Windows Performance Toolkit 或 Linux perf
3. 配置 PT 过滤器（只追踪样本代码）
4. 解析 PT trace 数据

### 方案 B: 硬件虚拟化（VMI）

使用 Hyper-V 或 KVM 的虚拟化功能：
- 在 hypervisor 层面追踪
- 样本无法检测
- 可以拦截所有内存访问

**优点**：
- 完全透明
- 可以追踪所有行为

**缺点**：
- 性能开销大（~50%）
- 实现非常复杂
- 需要修改 hypervisor

### 方案 C: 静态分析

放弃动态追踪，使用静态分析：
- IDA Pro / Ghidra
- 符号执行（angr, Triton）
- 污点分析

**优点**：
- 无法被检测
- 可以分析所有代码路径

**缺点**：
- 无法处理混淆
- 无法处理加密
- 分析时间长

### 方案 D: 修改样本

移除样本的反调试代码：
- Patch 检测代码
- NOP 掉跳转指令
- 修改条件分支

**优点**：
- 简单直接
- 可以使用 DynamoRIO

**缺点**：
- 需要逆向分析
- 可能破坏样本功能
- 仅适用于研究

## 下一步行动

### 立即可行

1. **验证 Intel PT 支持**
```powershell
# 检查 CPU 是否支持 PT
wmic cpu get caption
# 查找 Intel Processor Trace
```

2. **尝试 Intel PT 追踪**
```bash
# 使用 perf (Linux)
perf record -e intel_pt//u ./sample

# 使用 WPA (Windows)
wpa -i trace.etl
```

### 中期目标

1. **静态分析样本**
   - 使用 IDA Pro 分析样本
   - 找到反调试代码的位置
   - 理解检测机制

2. **Patch 样本**
   - 移除反调试代码
   - 验证 DynamoRIO 追踪

### 长期目标

1. **构建 Intel PT 追踪系统**
   - 集成到沙箱
   - 自动化 trace 解析
   - 生成 CFG

2. **研究其他反检测技术**
   - 硬件虚拟化
   - 符号执行
   - 混合方法

## 技术收获

1. **深入理解了 Windows 模块加载机制**
   - PEB 结构
   - LDR_DATA_TABLE_ENTRY
   - 模块链表

2. **掌握了 DynamoRIO 的内部实现**
   - 手动映射技术
   - 代码缓存机制
   - API Hooking

3. **了解了恶意软件的反调试技术**
   - 多层检测
   - 底层检测方法
   - 初始化阶段检测

## 文件清单

### 已修改
- ✅ `windows_host/drio_client/src/shrike_drcov_nudge.c` - 添加了 API Hook
- ✅ 添加了 `tlhelp32.h` 和 `psapi.h` 头文件

### 已生成
- ✅ `windows_host/drio_client/bin32/release/shrike_drcov_nudge_apihook.dll` - API Hook DLL（102KB）
- ✅ `guest/runtime/drio/bin32/shrike_drcov_nudge.dll` - 已更新为 API Hook 版本
- ✅ `API_HOOK_ANALYSIS.md` - 本报告

### 测试数据
- Build ID: `APIHOOK_20260425_V1`
- MD5: `312858DAAF249657ECEAD04CB542C2BA`
- 测试报告: `reports/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2_20260425_151322/`

## 参考资料

### Intel PT
- Intel PT 文档: https://software.intel.com/content/www/us/en/develop/articles/processor-tracing.html
- perf 使用: https://perf.wiki.kernel.org/index.php/Perf_tools_support_for_Intel%C2%AE_Processor_Trace
- Windows Performance Toolkit: https://docs.microsoft.com/en-us/windows-hardware/test/wpt/

### 反调试技术
- Anti-Debug Tricks: https://anti-debug.checkpoint.com/
- Malware Analysis: https://www.malware-traffic-analysis.net/

### DynamoRIO
- 官方文档: https://dynamorio.org/
- API Reference: https://dynamorio.org/page_user_docs.html
