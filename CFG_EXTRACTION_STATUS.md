# CFG 提取状态报告

## 当前进度

### ✅ 已完成
1. **成功运行沙箱分析**
   - 样本：`8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2`
   - DynamoRIO 成功捕获了 **49,200 行原始 CFG 数据**
   - 包含 23,211 个基本块、9,556 次调用、10,924 次分支
   - Sysmon 捕获了 14,123 个行为事件

2. **诊断问题**
   - 发现 PEB unlinking 失败（`unlinked_count: 0`）
   - 根本原因：隐藏列表中缺少 `shrike_drcov_nudge_apihook.dll`
   - 样本检测到 DynamoRIO 后立即退出，只执行系统 DLL 代码

3. **修复源代码**
   - 已修改 `windows_host/drio_client/src/shrike_drcov_nudge.c`
   - 添加了所有 DLL 变体到隐藏列表：
     - `shrike_drcov_nudge_apihook.dll`
     - `shrike_drcov_nudge_final.dll`
     - `shrike_drcov_nudge_new.dll`

### 🔄 进行中
- **DynamoRIO 包下载**（后台运行）
  - 文件：`windows_host/third_party/DynamoRIO-Windows.zip`
  - 大小：312 MB
  - 进度：可用 `tail -f /tmp/drio_download.log` 查看
  - 预计时间：15-20 分钟

### ⏳ 待完成
1. **重新编译 DLL**（等待下载完成后）
   ```powershell
   cd D:\project\ransomware\method12-dev\windows_host\powershell
   .\11_build_drio_nudge_client.ps1 -Force
   ```

2. **更新 guest runtime**
   ```bash
   # 启动 maintenance VM
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File \
     D:\project\ransomware\method12-dev\windows_host\powershell\08_start_maintenance.ps1
   
   # 在 WSL 中部署
   cd /mnt/d/project/ransomware/method12-dev
   source .venv/bin/activate
   python sandbox/scripts/install_guest_runtime.py --guest-user root --guest-password root
   ```

3. **刷新快照**
   ```powershell
   cd D:\project\ransomware\method12-dev\windows_host\powershell
   Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
   .\07_refresh_snapshots.ps1 -Force
   ```

4. **重新运行样本分析**
   ```bash
   cd /mnt/d/project/ransomware/method12-dev
   source .venv/bin/activate
   
   python sandbox/scripts/analyze_sample.py \
     "samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2" \
     --task-profile sandbox/profiles/deep_cfg_drio_extended.json
   ```

## 当前分析结果

虽然样本没有执行恶意代码，但已获得大量数据：

### 原始 Trace 数据
```
reports/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2_20260426_115652/raw/
├── trace.06016.ndjson          # 49,200 行 CFG 事件
├── sysmon_process_events.json  # 99 个进程事件
├── sysmon_file_events.json     # 156 个文件事件
├── sysmon_registry_events.json # 10,363 个注册表事件
├── sysmon_injection_events.json # 3,269 个注入事件
└── 其他行为数据
```

### CFG 统计
- **基本块**：23,211 个
- **调用**：9,556 次（直接 + 间接）
- **分支**：10,924 次（taken + not taken）
- **加载模块**：22 个
- **样本执行**：0 个基本块（被检测到）

### 检测到的 DynamoRIO 模块
```
0x75830000: drwrap.dll
0x75850000: drmgr.dll
0x75860000: shrike_drcov_nudge_apihook.dll  ← 不在隐藏列表中
0x75910000: dynamorio.dll
```

### PEB Unlinking 结果
```json
{"event":"peb_unlink","status":"start","peb":"0x1746a0f4"}
{"event":"peb_unlink","status":"completed","unlinked_count":0}  ← 失败
```

### API Hook 结果
```json
{"event":"api_hook","function":"K32EnumProcessModules","status":"hooked"}
{"event":"api_hook","function":"CreateToolhelp32Snapshot","status":"hooked"}
{"event":"api_hook","function":"Module32First","status":"hooked"}
{"event":"api_hook","function":"Module32Next","status":"hooked"}
```

## 预期修复效果

修复后，PEB unlinking 应该成功隐藏所有 5 个 DynamoRIO 模块：
```json
{"event":"peb_unlink","status":"completed","unlinked_count":5}
```

样本将无法通过 PEB 遍历检测到 DynamoRIO，从而执行完整的恶意代码，生成真实的 CFG：
- 样本地址范围（0x00a30000-0x00axxxxx）的基本块
- 加密/解密函数的控制流
- 文件遍历和加密逻辑
- 勒索信息显示流程

## 快速检查命令

### 检查下载进度
```bash
tail -f /tmp/drio_download.log
# 或
ls -lh windows_host/third_party/DynamoRIO-Windows.zip
```

### 验证修复后的结果
```bash
# 查看最新报告
LATEST=$(ls -td reports/*/ | head -1)
echo "最新报告: $LATEST"

# 检查 PEB unlinking
grep '"event":"peb_unlink"' ${LATEST}raw/trace.*.ndjson

# 检查样本执行
grep '"src":"0x00a3' ${LATEST}raw/trace.*.ndjson | wc -l

# 查看 CFG 统计
cat ${LATEST}raw/dynamic_cfg_trace_summary.json
```

## 相关文档
- `FIX_PEB_UNLINKING.md` - 详细的修复步骤
- `README.md` - 沙箱使用文档
- `PROBLEM_DIAGNOSIS.md` - 问题诊断记录（如果存在）

## 时间线
- **2026-04-26 11:51** - 首次运行样本分析
- **2026-04-26 12:01** - 诊断问题并修复源代码
- **2026-04-26 16:55** - 开始下载 DynamoRIO
- **待定** - 重新编译和测试
