# DynamoRIO CFG提取失败 - 解决方案总结

## 问题现状

### 已尝试的方法（全部失败）
1. ✅ **PEB Unlinking** - 实现但无效（DynamoRIO模块不在PEB链表中）
2. ✅ **API Hooking** - 实现但无效（样本不使用API检测）
3. ✅ **样本Patching** - 实现但无效（检测机制未被patch）

### 根本原因
样本使用**底层内存扫描**检测DynamoRIO：
- 扫描进程内存查找"DynamoRIO"字符串
- 检测异常的RWX内存区域（代码缓存）
- 检测执行流程异常（返回地址在代码缓存中）
- 时序检测（DynamoRIO导致性能下降）

**结论：DynamoRIO无法绕过该样本的检测机制**

## 可行的CFG提取方案

### 方案1：静态CFG提取（推荐）
使用IDA Pro进行静态分析提取CFG：

```python
# ida_extract_cfg.py
import idaapi
import idautils
import idc
import json

def extract_cfg():
    cfg = {"nodes": [], "edges": []}
    
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        
        # 提取基本块
        func = idaapi.get_func(func_ea)
        if not func:
            continue
            
        flowchart = idaapi.FlowChart(func)
        for bb in flowchart:
            node = {
                "start": hex(bb.start_ea),
                "end": hex(bb.end_ea),
                "size": bb.end_ea - bb.start_ea,
                "function": func_name
            }
            cfg["nodes"].append(node)
            
            # 提取边
            for succ in bb.succs():
                edge = {
                    "from": hex(bb.start_ea),
                    "to": hex(succ.start_ea),
                    "type": "direct"
                }
                cfg["edges"].append(edge)
    
    with open("static_cfg.json", "w") as f:
        json.dump(cfg, f, indent=2)
    
    print(f"Extracted {len(cfg['nodes'])} nodes and {len(cfg['edges'])} edges")

extract_cfg()
```

### 方案2：Intel PT硬件trace
需要：
- Intel CPU支持PT（6代Core及以上）
- Windows 10 1703+
- 配置WPR/ETW

限制：
- 需要特定硬件
- trace文件巨大（GB级）
- 解码复杂

### 方案3：Hypervisor级trace
使用Hyper-V的虚拟化扩展：
- 不在guest进程内存中
- 需要自定义Hyper-V模块
- 开发复杂度高

### 方案4：修改样本移除检测（最实用）
使用IDA找到检测代码并patch：

```python
# 1. 在IDA中运行ida_detect_checks.py找到检测函数
# 2. 将检测函数patch为直接返回
# 3. 保存patched样本
# 4. 用DynamoRIO分析patched样本
```

## 推荐行动方案

**立即可行：静态CFG提取**
```bash
# 1. 在IDA中打开样本
ida64 samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2

# 2. 运行CFG提取脚本
# File -> Script file -> ida_extract_cfg.py

# 3. 导出结果
# 生成 static_cfg.json
```

**中期方案：精确patch检测代码**
```bash
# 1. 用IDA找到检测函数地址
python ida_detect_checks.py

# 2. patch检测函数为 "xor eax,eax; ret"
# 3. 用DynamoRIO重新分析
python sandbox/scripts/analyze_sample.py samples/sample_patched_v2.exe
```

**长期方案：Intel PT或自定义hypervisor trace**
- 需要硬件支持和大量开发工作
- 仅在其他方案都失败时考虑
