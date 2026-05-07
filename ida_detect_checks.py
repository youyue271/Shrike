import idaapi
import idautils
import idc

print("=== 查找 DynamoRIO 检测代码 ===\n")

# 1. 查找字符串引用
print("[1] 搜索 DynamoRIO 相关字符串:")
for s in idautils.Strings():
    s_str = str(s).lower()
    if any(kw in s_str for kw in ['dynamorio', 'drmgr', 'drwrap', 'drutil']):
        print(f"  找到字符串: '{str(s)}' @ {hex(s.ea)}")
        for xref in idautils.XrefsTo(s.ea):
            func = idaapi.get_func(xref.frm)
            if func:
                print(f"    -> 函数: {idc.get_func_name(func.start_ea)} @ {hex(func.start_ea)}")

# 2. 查找模块枚举 API
print("\n[2] 查找模块枚举 API 调用:")
apis = ['CreateToolhelp32Snapshot', 'Module32First', 'Module32Next', 'EnumProcessModules']
for api in apis:
    for ea, name in idautils.Names():
        if api.lower() in name.lower():
            xrefs = list(idautils.XrefsTo(ea))
            if xrefs:
                print(f"\n  {api} @ {hex(ea)} - {len(xrefs)} 个调用:")
                for xref in xrefs[:5]:
                    func = idaapi.get_func(xref.frm)
                    if func:
                        fname = idc.get_func_name(func.start_ea)
                        print(f"    {hex(xref.frm)}: {idc.GetDisasm(xref.frm)}")
                        print(f"      在函数: {fname} @ {hex(func.start_ea)}")

# 3. 查找 PEB 访问（fs:[0x30]）
print("\n[3] 查找 PEB 访问 (fs:[0x30]):")
count = 0
for func_ea in idautils.Functions():
    for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
        disasm = idc.GetDisasm(head)
        if 'fs:' in disasm and ('30h' in disasm or '0x30' in disasm):
            print(f"  {hex(head)}: {disasm}")
            print(f"    在函数: {idc.get_func_name(func_ea)}")
            count += 1
            if count >= 10:
                break
    if count >= 10:
        break

print("\n=== 完成 ===")
