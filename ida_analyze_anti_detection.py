import idaapi
import idautils
import idc

def find_anti_debug_checks():
    """查找反调试检测"""
    print("[*] Searching for anti-debug checks...")

    anti_debug_apis = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "QueryPerformanceCounter", "timeGetTime",
        "ZwQueryInformationProcess", "NtSetInformationThread",
        "RtlQueryProcessDebugInformation"
    ]

    findings = []
    for api in anti_debug_apis:
        for xref in idautils.XrefsTo(idc.get_name_ea_simple(api)):
            findings.append({
                'type': 'api_call',
                'api': api,
                'caller': xref.frm,
                'func': idc.get_func_name(xref.frm)
            })
            print(f"  [!] {api} called from {xref.frm:#x} in {idc.get_func_name(xref.frm)}")

    return findings

def find_peb_access():
    """查找PEB访问（fs:[30h]）"""
    print("\n[*] Searching for PEB access...")

    patterns = [
        "64 A1 30 00 00 00",  # mov eax, fs:[30h]
        "64 8B 15 30 00 00 00",  # mov edx, fs:[30h]
        "65 48 8B 04 25 60 00 00 00"  # mov rax, gs:[60h] (x64)
    ]

    findings = []
    for pattern in patterns:
        ea = idc.find_binary(0, idc.SEARCH_DOWN, pattern)
        while ea != idc.BADADDR:
            findings.append({'type': 'peb_access', 'addr': ea})
            print(f"  [!] PEB access at {ea:#x}")
            ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN, pattern)

    return findings

def find_timing_checks():
    """查找时间检测"""
    print("\n[*] Searching for timing checks...")

    timing_apis = ["GetTickCount", "QueryPerformanceCounter", "timeGetTime", "GetSystemTime"]

    # 查找连续两次调用时间API的模式
    findings = []
    for api in timing_apis:
        api_ea = idc.get_name_ea_simple(api)
        if api_ea == idc.BADADDR:
            continue

        for xref in idautils.XrefsTo(api_ea):
            func_ea = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
            if func_ea == idc.BADADDR:
                continue

            # 检查函数中是否有多次调用
            call_count = 0
            for item_ea in idautils.FuncItems(func_ea):
                if idc.print_insn_mnem(item_ea) == "call":
                    target = idc.get_operand_value(item_ea, 0)
                    if target == api_ea:
                        call_count += 1

            if call_count >= 2:
                findings.append({
                    'type': 'timing_check',
                    'api': api,
                    'func': func_ea,
                    'count': call_count
                })
                print(f"  [!] {api} called {call_count} times in {idc.get_func_name(func_ea)}")

    return findings

def find_dll_name_checks():
    """查找DLL名称检测"""
    print("\n[*] Searching for DLL name checks...")

    suspicious_strings = [
        "dynamorio", "drrun", "pin", "frida", "dbghelp", "dbgcore",
        "x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "ghidra"
    ]

    findings = []
    for s in suspicious_strings:
        for string_ea in idautils.Strings():
            if s.lower() in str(string_ea).lower():
                findings.append({
                    'type': 'dll_check',
                    'string': str(string_ea),
                    'addr': string_ea.ea
                })
                print(f"  [!] Found '{s}' at {string_ea.ea:#x}")

                # 查找引用
                for xref in idautils.XrefsTo(string_ea.ea):
                    print(f"      Referenced from {xref.frm:#x}")

    return findings

def find_exception_handlers():
    """查找异常处理器"""
    print("\n[*] Searching for exception handlers...")

    handler_apis = [
        "RtlAddVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
        "AddVectoredExceptionHandler"
    ]

    findings = []
    for api in handler_apis:
        api_ea = idc.get_name_ea_simple(api)
        if api_ea == idc.BADADDR:
            continue

        for xref in idautils.XrefsTo(api_ea):
            findings.append({
                'type': 'exception_handler',
                'api': api,
                'caller': xref.frm
            })
            print(f"  [!] {api} called from {xref.frm:#x}")

    return findings

def analyze_sample():
    """主分析函数"""
    print("="*60)
    print("Anti-Detection Analysis")
    print("="*60)

    all_findings = []

    all_findings.extend(find_anti_debug_checks())
    all_findings.extend(find_peb_access())
    all_findings.extend(find_timing_checks())
    all_findings.extend(find_dll_name_checks())
    all_findings.extend(find_exception_handlers())

    print("\n" + "="*60)
    print(f"Total findings: {len(all_findings)}")
    print("="*60)

    # 保存结果
    output_file = idc.get_idb_path().replace(".idb", "_anti_detection.txt")
    with open(output_file, "w") as f:
        for finding in all_findings:
            f.write(f"{finding}\n")

    print(f"\n[*] Results saved to: {output_file}")

    return all_findings

if __name__ == "__main__":
    idaapi.auto_wait()
    analyze_sample()
