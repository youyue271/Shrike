import idaapi
import idautils
import idc

# 查找模块枚举 API 的交叉引用
print("=== 查找模块枚举 API 调用 ===")
apis = ['CreateToolhelp32Snapshot', 'Module32First', 'Module32Next', 'EnumProcessModules']

for api in apis:
    for name_ea, name in idautils.Names():
        if api.lower() in name.lower():
            print(f"\n[{api}] @ {hex(name_ea)}")
            for xref in idautils.XrefsTo(name_ea):
                func = idaapi.get_func(xref.frm)
                if func:
                    print(f"  调用自: {idc.get_func_name(func.start_ea)} @ {hex(xref.frm)}")
                    # 显示调用指令
                    print(f"    指令: {idc.GetDisasm(xref.frm)}")
            break

print("\n=== 完成 ===")
