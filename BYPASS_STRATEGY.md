# DynamoRIO反检测增强方案

## 问题诊断

当前DynamoRIO客户端已经实现了：
- ✅ PEB.BeingDebugged清零
- ✅ PEB模块unlinking
- ✅ API hook (IsDebuggerPresent, CheckRemoteDebuggerPresent等)
- ✅ RDTSC/CPUID指令替换
- ✅ PE头擦除

但样本仍然检测到了DynamoRIO。可能的原因：

### 1. 检测时机问题
样本可能在DynamoRIO初始化**之前**就检测了：
- 在DLL_PROCESS_ATTACH时检查模块列表
- 在main()之前的TLS回调中检查

### 2. 检测方法遗漏
可能使用了未被hook的检测方法：
- `NtQuerySystemInformation` (SystemModuleInformation)
- `CreateToolhelp32Snapshot` + `Module32First/Next`
- 直接读取PEB而不是通过API
- 检查父进程名称（drrun.exe）

## 解决方案

### 方案A: 使用Loader替代drrun.exe ⭐推荐

创建一个自定义loader，不使用drrun.exe：

```c
// custom_loader.c
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <sample.exe>\n", argv[0]);
        return 1;
    }

    // 1. 加载DynamoRIO DLL（使用LoadLibrary）
    HMODULE hDynamoRIO = LoadLibraryA("C:\\Tools\\DynamoRIO\\bin32\\dynamorio.dll");
    if (!hDynamoRIO) {
        printf("Failed to load dynamorio.dll\n");
        return 1;
    }

    // 2. 获取dr_inject_process_inject函数
    typedef int (*dr_inject_process_inject_t)(HANDLE, bool, void*);
    dr_inject_process_inject_t dr_inject = 
        (dr_inject_process_inject_t)GetProcAddress(hDynamoRIO, "dr_inject_process_inject");

    // 3. 创建挂起的进程
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, 
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Failed to create process\n");
        return 1;
    }

    // 4. 注入DynamoRIO
    dr_inject(pi.hProcess, false, NULL);

    // 5. 恢复进程
    ResumeThread(pi.hThread);

    // 6. 等待完成
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

### 方案B: 早期注入 + 更强的隐藏

修改DynamoRIO客户端，在更早的时机执行隐藏：

```c
// 在dr_client_main最开始就执行
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    // 立即隐藏，在任何其他代码之前
    if (has_client_option(argc, argv, "-bypass_antidebug")) {
        // 1. 立即unlink PEB
        unlink_module_from_peb_early();
        
        // 2. 立即擦除PE头
        erase_drio_pe_headers_early();
        
        // 3. Hook CreateToolhelp32Snapshot
        hook_module_enumeration_apis();
    }
    
    // 然后继续正常初始化...
}

// 新增：Hook模块枚举API
static void hook_module_enumeration_apis() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    
    // Hook CreateToolhelp32Snapshot
    void *CreateToolhelp32Snapshot_addr = 
        GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    if (CreateToolhelp32Snapshot_addr) {
        drwrap_wrap(CreateToolhelp32Snapshot_addr, 
                    wrap_CreateToolhelp32Snapshot, NULL);
    }
    
    // Hook Module32First/Next
    drwrap_wrap(GetProcAddress(kernel32, "Module32FirstW"), 
                wrap_Module32First, NULL);
    drwrap_wrap(GetProcAddress(kernel32, "Module32NextW"), 
                wrap_Module32Next, NULL);
    
    // Hook NtQuerySystemInformation
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    drwrap_wrap(GetProcAddress(ntdll, "NtQuerySystemInformation"),
                wrap_NtQuerySystemInformation, NULL);
}

// 过滤模块枚举结果
static void wrap_Module32Next(void *wrapcxt, OUT void **user_data) {
    MODULEENTRY32W *me = (MODULEENTRY32W *)drwrap_get_arg(wrapcxt, 1);
    
    // 调用原始函数
    drwrap_skip_call(wrapcxt);
    BOOL result = Module32NextW(
        (HANDLE)drwrap_get_arg(wrapcxt, 0), me);
    
    // 如果是DynamoRIO模块，跳过
    while (result && is_drio_module_name(me->szModule)) {
        result = Module32NextW(
            (HANDLE)drwrap_get_arg(wrapcxt, 0), me);
    }
    
    drwrap_set_retval(wrapcxt, (void*)(ptr_int_t)result);
}
```

### 方案C: 使用进程镂空（Process Hollowing）

完全隐藏DynamoRIO：

```c
// 1. 创建合法进程（如notepad.exe）作为宿主
// 2. 挂起并清空其内存
// 3. 将样本映射到宿主进程
// 4. 注入DynamoRIO到宿主进程
// 5. 恢复执行

// 这样样本看到的父进程是notepad.exe而不是drrun.exe
```

### 方案D: 修改样本（最简单）

直接patch样本的反检测代码：

```python
# patch_sample.py
import sys

def patch_sample(input_file, output_file):
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    # 1. NOP掉IsDebuggerPresent调用
    # 搜索: FF 15 ?? ?? ?? ?? (call dword ptr [IsDebuggerPresent])
    # 替换为: 31 C0 90 90 90 90 (xor eax,eax; nop*4)
    
    # 2. Patch PEB检查
    # 搜索: 64 A1 30 00 00 00 (mov eax, fs:[30h])
    # 如果后面是: 8A 40 02 (mov al, [eax+2])
    # 替换整段为: 31 C0 + NOP
    
    # 3. Patch GetModuleHandle("dynamorio")
    # 搜索字符串"dynamorio"并替换为"xxxxxxxxxx"
    
    patterns = [
        # IsDebuggerPresent call
        (b'\xFF\x15', b'\x31\xC0\x90\x90'),
        # PEB.BeingDebugged check
        (b'\x64\xA1\x30\x00\x00\x00\x8A\x40\x02', 
         b'\x31\xC0\x90\x90\x90\x90\x90\x90\x90'),
        # String "dynamorio"
        (b'dynamorio', b'xxxxxxxxx'),
        (b'drrun', b'xxxxx'),
    ]
    
    for pattern, replacement in patterns:
        offset = 0
        while True:
            offset = data.find(pattern, offset)
            if offset == -1:
                break
            data[offset:offset+len(replacement)] = replacement
            offset += len(replacement)
            print(f"Patched at offset {offset:#x}")
    
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print(f"Patched sample saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python patch_sample.py <input> <output>")
        sys.exit(1)
    patch_sample(sys.argv[1], sys.argv[2])
```

## 立即可行的步骤

1. **先尝试patch样本**（5分钟）：
```bash
python patch_sample.py samples/8c716101...ccce2 samples/sample_patched.exe
python sandbox/scripts/run_offline_task.py samples/sample_patched.exe \
  --task-profile sandbox/profiles/deep_cfg_drio.json
```

2. **如果patch不行，重新编译DynamoRIO客户端**（30分钟）：
   - 添加更多API hook
   - 确保PEB unlinking在最早时机执行
   - 添加模块枚举API的hook

3. **最后尝试Intel PT**（如果CPU支持）

## 调试建议

在VM中手动运行样本查看行为：
```powershell
# 在VM中
cd C:\Sandbox\input
.\8c716101...ccce2.exe

# 观察是否有文件被加密
# 如果没有，说明确实有反检测
```
