# 修复 PEB Unlinking 问题

## 问题诊断

分析 trace 数据发现：
- ✅ DynamoRIO 成功捕获了 49,200 行 CFG 数据（23,211 个基本块）
- ✅ API hook 成功部署（4 个模块枚举函数被 hook）
- ❌ **PEB unlinking 失败**：`unlinked_count: 0`
- ❌ 样本检测到 DynamoRIO 并拒绝执行恶意代码

## 根本原因

在 `windows_host/drio_client/src/shrike_drcov_nudge.c:1499-1506` 中，隐藏模块列表缺少实际加载的 DLL 名称：

```c
const wchar_t *hide_modules[] = {
    L"dynamorio.dll",
    L"drwrap.dll",
    L"drmgr.dll",
    L"drutil.dll",
    L"shrike_drcov_nudge.dll",  // ❌ 实际加载的是 shrike_drcov_nudge_apihook.dll
    NULL
};
```

实际加载的模块（从 trace 数据）：
- `dynamorio.dll` ✅
- `drmgr.dll` ✅
- `drwrap.dll` ✅
- `drutil.dll` ✅
- `shrike_drcov_nudge_apihook.dll` ❌ **不在隐藏列表中！**

## 修复方案

已修改源代码，添加所有可能的 DLL 变体到隐藏列表：

```c
const wchar_t *hide_modules[] = {
    L"dynamorio.dll",
    L"drwrap.dll",
    L"drmgr.dll",
    L"drutil.dll",
    L"shrike_drcov_nudge.dll",
    L"shrike_drcov_nudge_apihook.dll",  // ✅ 新增
    L"shrike_drcov_nudge_final.dll",    // ✅ 新增
    L"shrike_drcov_nudge_new.dll",      // ✅ 新增
    NULL
};
```

## 重新编译和部署步骤

### 1. 在 Windows PowerShell（管理员）中重新编译

```powershell
cd D:\project\ransomware\method12-dev\windows_host\powershell
.\11_build_drio_nudge_client.ps1 -Force
```

### 2. 更新 guest runtime

```powershell
# 启动 maintenance VM
.\08_start_maintenance.ps1
```

然后在 WSL 中：

```bash
cd /mnt/d/project/ransomware/method12-dev
source .venv/bin/activate
python sandbox/scripts/install_guest_runtime.py --guest-user root --guest-password root
```

### 3. 刷新快照

在 Windows PowerShell 中：

```powershell
cd D:\project\ransomware\method12-dev\windows_host\powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
```

### 4. 重新运行样本分析

在 WSL 中：

```bash
cd /mnt/d/project/ransomware/method12-dev
source .venv/bin/activate

python sandbox/scripts/analyze_sample.py \
  "samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2" \
  --task-profile sandbox/profiles/deep_cfg_drio_extended.json
```

### 5. 验证修复

检查新的 trace 数据：

```bash
# 查看 PEB unlinking 结果
grep '"event":"peb_unlink"' reports/<latest>/raw/trace.*.ndjson

# 应该看到：
# {"event":"peb_unlink","status":"completed","unlinked_count":5}  # 而不是 0

# 检查样本是否执行
grep '"src":"0x00a3' reports/<latest>/raw/trace.*.ndjson | wc -l

# 应该看到大量样本地址范围内的基本块
```

## 预期结果

修复后，PEB unlinking 应该成功隐藏所有 5 个 DynamoRIO 模块，样本将无法通过 PEB 遍历检测到 DynamoRIO，从而执行恶意代码并生成完整的 CFG。

## 当前分析结果位置

虽然样本没有执行恶意代码，但原始 trace 数据已保存在：

```
reports/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2_20260426_115652/raw/
├── trace.06016.ndjson  (49,200 行，23,211 个基本块)
├── sysmon_*.json       (14,123 个 Sysmon 事件)
└── 其他行为数据
```
