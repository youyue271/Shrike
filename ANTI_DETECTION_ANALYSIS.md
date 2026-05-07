# 勒索软件反检测分析与绕过方案

## 基于现有证据的分析

### 观察到的行为
1. **样本成功启动** - PID 5368，通过drrun.exe启动
2. **立即停止执行** - 没有样本代码的CFG trace
3. **最小化文件操作** - 只有2个文件操作事件
4. **大量注入事件** - 1754个Sysmon注入事件（可能是正常行为或检测到后的防御）

### 可能的反检测机制

#### 1. **DynamoRIO特征检测**
最可能的原因，勒索软件检测到：
- **DLL注入**: `dynamorio.dll`, `drwrap.dll`, `drmgr.dll`, `shrike_drcov_nudge.dll`
- **进程名称**: 父进程是`drrun.exe`
- **内存特征**: DynamoRIO修改的代码段

#### 2. **PEB检查**
```asm
mov eax, fs:[30h]      ; 获取PEB
mov al, [eax+2]        ; BeingDebugged标志
test al, al
jnz detected
```
虽然使用了`-bypass_antidebug`，但可能不完整。

#### 3. **时间检测**
- 连续调用`GetTickCount`检测执行延迟
- DynamoRIO会显著降低执行速度

#### 4. **异常处理**
- 使用异常作为控制流
- DynamoRIO可能干扰异常处理

#### 5. **环境检查**
- 检查虚拟机特征（Hyper-V）
- 检查沙箱环境标志

## 绕过方案

### 方案1: 增强DynamoRIO隐蔽性 ⭐推荐

修改DynamoRIO客户端代码：

```c
// 1. 重命名DLL
dynamorio.dll -> msvcr120.dll
drwrap.dll -> msvcp120.dll
shrike_drcov_nudge.dll -> vcruntime140.dll

// 2. 隐藏模块
// 在PEB中unlink DynamoRIO模块
void hide_module(HMODULE hModule) {
    PPEB peb = (PPEB)__readfsdword(0x30);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase == hModule) {
            // Unlink from lists
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
            break;
        }
        curr = curr->Flink;
    }
}

// 3. Hook反检测API
BOOL WINAPI Hook_IsDebuggerPresent() {
    return FALSE;
}

NTSTATUS WINAPI Hook_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = Real_NtQueryInformationProcess(...);
    if (ProcessInformationClass == ProcessDebugPort) {
        *(PDWORD)ProcessInformation = 0;
    }
    return status;
}
```

### 方案2: 修改样本 ⭐最直接

使用IDA Pro patch反检测代码：

```python
# ida_patch_anti_detection.py
import idc
import idaapi

def patch_anti_debug():
    # 1. NOP掉IsDebuggerPresent调用
    for xref in idautils.XrefsTo(idc.get_name_ea_simple("IsDebuggerPresent")):
        # call IsDebuggerPresent -> xor eax, eax; nop; nop
        idc.patch_byte(xref.frm, 0x31)  # xor
        idc.patch_byte(xref.frm+1, 0xC0)  # eax, eax
        idc.patch_byte(xref.frm+2, 0x90)  # nop
        idc.patch_byte(xref.frm+3, 0x90)  # nop
        idc.patch_byte(xref.frm+4, 0x90)  # nop
    
    # 2. Patch PEB检查
    # mov eax, fs:[30h]; mov al, [eax+2]; test al, al
    # -> xor eax, eax; nop; nop; nop; nop
    ea = idc.find_binary(0, idc.SEARCH_DOWN, "64 A1 30 00 00 00 8A 40 02")
    while ea != idc.BADADDR:
        for i in range(9):
            idc.patch_byte(ea+i, 0x90)
        idc.patch_byte(ea, 0x31)
        idc.patch_byte(ea+1, 0xC0)
        ea = idc.find_binary(ea+1, idc.SEARCH_DOWN, "64 A1 30 00 00 00 8A 40 02")
    
    # 3. 保存patched文件
    output = idc.get_input_file_path().replace(".exe", "_patched.exe")
    idaapi.save_database(output, 0)
```

### 方案3: 使用Intel PT ⭐硬件级trace

Intel PT是硬件级trace，几乎无法检测：

```bash
python sandbox/scripts/run_offline_task.py \
  samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2 \
  --task-profile sandbox/profiles/deep_cfg_intelpt.json \
  --timeout-seconds 300
```

优点：
- 硬件级，无DLL注入
- 性能影响小
- 几乎无法检测

缺点：
- 需要CPU支持（Intel Processor Trace）
- trace数据量大

### 方案4: 改进bypass_antidebug实现

当前DynamoRIO客户端的bypass可能不完整，需要增强：

```c
// shrike_drcov_nudge.dll 需要增加的hook

// Hook NtQueryInformationProcess
static NTSTATUS (WINAPI *Real_NtQueryInformationProcess)(...) = NULL;

NTSTATUS WINAPI Hook_NtQueryInformationProcess(...) {
    NTSTATUS status = Real_NtQueryInformationProcess(...);
    
    if (NT_SUCCESS(status)) {
        switch (ProcessInformationClass) {
            case ProcessDebugPort:
                *(PDWORD)ProcessInformation = 0;
                break;
            case ProcessDebugObjectHandle:
                *(PHANDLE)ProcessInformation = NULL;
                status = STATUS_PORT_NOT_SET;
                break;
            case ProcessDebugFlags:
                *(PDWORD)ProcessInformation = 1;  // PROCESS_DEBUG_INHERIT
                break;
        }
    }
    return status;
}

// Hook GetTickCount - 防止时间检测
static DWORD last_tick = 0;
DWORD WINAPI Hook_GetTickCount() {
    if (last_tick == 0) {
        last_tick = Real_GetTickCount();
    }
    // 返回正常速度的时间
    last_tick += 10;  // 假装10ms过去了
    return last_tick;
}

// 隐藏DynamoRIO模块
void hide_dynamorio_modules() {
    HMODULE modules[] = {
        GetModuleHandleA("dynamorio.dll"),
        GetModuleHandleA("drwrap.dll"),
        GetModuleHandleA("drmgr.dll"),
        GetModuleHandleA("shrike_drcov_nudge.dll")
    };
    
    for (int i = 0; i < 4; i++) {
        if (modules[i]) {
            hide_module_from_peb(modules[i]);
        }
    }
}
```

## 实施步骤

### 立即可行（推荐顺序）：

1. **尝试Intel PT** (5分钟)
   - 最简单，如果CPU支持就能用
   - 几乎无法被检测

2. **Patch样本** (30分钟)
   - 用IDA Pro打开样本
   - 运行`ida_analyze_anti_detection.py`找到检测点
   - 手动或脚本patch
   - 测试patched版本

3. **增强DynamoRIO客户端** (2-4小时)
   - 修改`shrike_drcov_nudge.dll`源码
   - 添加更多API hook
   - 实现PEB unlinking
   - 重新编译

## 快速测试

先用简单的测试程序验证DynamoRIO：

```c
// test_simple.c
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Starting...\n");
    
    for (int i = 0; i < 100; i++) {
        printf("Loop %d\n", i);
        Sleep(10);
    }
    
    printf("Done\n");
    return 0;
}
```

如果这个简单程序能正常trace，说明DynamoRIO工作正常，问题确实是样本的反检测。
