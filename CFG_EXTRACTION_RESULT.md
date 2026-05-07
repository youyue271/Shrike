# DynamoRIO CFG提取结果报告

## 执行摘要
✅ DynamoRIO沙箱环境配置成功  
✅ Trace数据生成成功（98,346行事件）  
❌ 样本代码CFG未提取到（只捕获了系统代码）

## 详细结果

### 成功部分
1. **沙箱运行正常**
   - 虚拟机启动成功
   - ISO和artifact磁盘正确挂载
   - 样本成功启动（PID 5368，通过drrun.exe）

2. **DynamoRIO trace生成**
   - 生成了trace文件（~4.6MB × 2个文件）
   - 包含98,346行trace事件
   - 捕获了18个basic blocks和30条edges

3. **Trace解析成功**
   - trace_backend_drio.ps1正确解析数据
   - 生成了标准化的CFG格式
   - 包含call/ret/branch/indirect-jump信息

### 问题分析

**核心问题：样本代码未被trace**
```
sample_basic_block_count: 0
sample_call_count: 0
system_only_trace: True
```

**可能原因：**
1. **反DynamoRIO检测**
   - 样本检测到DynamoRIO环境
   - 虽然使用了`-bypass_antidebug`，但可能不够
   - 样本可能检查DLL注入、内存特征等

2. **样本立即退出**
   - 样本可能在初始化阶段就退出
   - Sysmon显示样本进程启动但文件操作很少

3. **代码执行路径问题**
   - 样本主要逻辑可能在子进程中
   - 或者使用了代码注入到其他进程

## 数据统计

### Trace数据
- **总事件数**: 98,346
- **Basic blocks**: 18 (全部为系统代码)
- **Edges**: 30
- **Call events**: 4,096
- **Return events**: 5,461
- **Branch events**: 10,924
- **Indirect calls**: 5,460

### 模块加载
- **总模块数**: 23
- **样本模块**: 已加载（base=0xff0000, size=1.5MB）
- **系统DLL**: ntdll, kernel32, user32等

### Sysmon事件
- **进程事件**: 49
- **文件事件**: 101
- **注册表事件**: 3,327
- **注入事件**: 1,754

## 解决方案建议

### 方案1：增强反检测绕过
修改DynamoRIO客户端以更好地隐藏：
- 隐藏DLL名称
- 修改内存特征
- Hook反检测API

### 方案2：使用Intel PT
切换到Intel PT后端（已有配置）：
```bash
python sandbox/scripts/run_offline_task.py samples/sample.exe \
  --task-profile sandbox/profiles/deep_cfg_intelpt.json
```

### 方案3：静态分析补充
使用IDA Pro提取静态CFG：
```bash
python ida_extract_cfg.py samples/sample.exe
```

### 方案4：修改样本
如果可以修改样本，patch掉反检测代码：
```bash
python patch_sample.py samples/sample.exe
```

## 文件位置

### Artifact数据
```
E:\artifact\
├── dynamic_cfg_trace.ndjson (20MB, 98K行)
├── dynamic_cfg_trace_summary.json
├── sysmon_*.json
├── runner.log
└── trace_backend_diagnostic.txt
```

### 原始trace
```
C:\Sandbox\output\drio_logs\
├── trace.05540.ndjson (4.6MB)
└── trace.04440.ndjson (4.6MB)
```

## 下一步行动

1. **立即可行**：尝试Intel PT后端
2. **中期**：分析样本反检测机制
3. **长期**：改进DynamoRIO客户端的隐蔽性

## 技术细节

### 修复的问题
1. ✅ 修复了`run_task.ps1`使用fast模式的问题
2. ✅ 更新了虚拟机快照
3. ✅ 确认trace backend正确解析数据

### 配置
- **Profile**: deep_cfg_drio.json
- **Execution window**: 180秒
- **Bypass antidebug**: 启用
- **DynamoRIO**: bin32/drrun.exe + shrike_drcov_nudge.dll
