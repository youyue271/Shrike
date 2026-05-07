import idautils
import idc
import idaapi

print("=== 查找反调试/反虚拟化代码 ===\n")

# 1. 查找模块枚举 API
print("[1] 模块枚举 API:")
module_apis = ['CreateToolhelp32Snapshot', 'Module32First', 'Module32Next',
               'EnumProcessModules', 'K32EnumProcessModules']
for name in idautils.Names():
    for api in module_apis:
        if api.lower() in name[1].lower():
            xrefs = list(idautils.XrefsTo(name[0]))
            if xrefs:
                print(f"  {name[1]} @ {hex(name[0])} - {len(xrefs)} 个引用")
                for xref in xrefs[:3]:
                    func = idaapi.get_func(xref.frm)
                    if func:
                        print(f"    调用自: {idc.get_func_name(func.start_ea)} @ {hex(xref.frm)}")

# 2. 查找 CPUID/RDTSC
print("\n[2] CPUID/RDTSC 指令:")
for func_ea in idautils.Functions():
    for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
        mnem = idc.print_insn_mnem(head)
        if mnem in ['cpuid', 'rdtsc']:
            print(f"  {mnem} @ {hex(head)} in {idc.get_func_name(func_ea)}")

# 3. 查找字符串
print("\n[3] 可疑字符串:")
keywords = ['dynamorio', 'drmgr', 'drwrap', 'vmware', 'vbox', 'qemu', 'debug']
for s in idautils.Strings():
    s_str = str(s).lower()
    for kw in keywords:
        if kw in s_str:
            print(f"  '{str(s)[:60]}' @ {hex(s.ea)}")
            for xref in idautils.XrefsTo(s.ea):
                func = idaapi.get_func(xref.frm)
                if func:
                    print(f"    引用自: {idc.get_func_name(func.start_ea)} @ {hex(xref.frm)}")
            break

print("\n完成!")
