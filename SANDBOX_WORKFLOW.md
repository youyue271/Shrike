# 沙箱动态CFG追踪工作流程

## 前置条件
- VM名称: rw-sandbox-win10
- Guest凭据: root / root
- Snapshot名称: analysis-base
- Python venv: /mnt/d/project/ransomware/method12/.venv

## 完整操作流程（按顺序执行）

### 1. 启动VM并维护
```powershell
.\windows_host\powershell\08_maintain_vm.ps1
```

### 2. 部署Guest Runtime（包含增强的反调试DLL）
```bash
/mnt/d/project/ransomware/method12/.venv/bin/python sandbox/scripts/install_guest_runtime.py --guest-user root --guest-password root
```

### 3. 关闭VM（必须关闭才能运行离线任务）
```powershell
Stop-VM -Name rw-sandbox-win10 -Force
```

### 4. 刷新Snapshot
```powershell
.\windows_host\powershell\07_refresh_snapshot.ps1
```

### 5. 运行沙箱分析（获取动态CFG）
```bash
/mnt/d/project/ransomware/method12/.venv/bin/python sandbox/scripts/analyze_sample.py "/mnt/d/project/ransomware/method12-dev/samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2" --task-profile sandbox/profiles/deep_cfg_drio.json
```

## 反调试绕过功能

DynamoRIO客户端已增强以下反调试绕过：
- IsDebuggerPresent/CheckRemoteDebuggerPresent hook
- NtQueryInformationProcess hook (ProcessDebugPort/ObjectHandle/Flags)
- GetThreadContext hook (清除硬件断点Dr0-Dr7)
- NtQuerySystemInformation hook (隐藏内核调试器)
- RDTSC/CPUID指令替换
- GetTickCount/QueryPerformanceCounter时间API hook
- 异常处理API hook
- OutputDebugString hook

## 报告位置
分析完成后报告在: `reports/<sample_id>_<timestamp>/`
- `summary.json` - 完整分析数据
- `report.md` - 可读报告
- `raw/` - 原始artifact

## 验证反调试绕过成功
检查报告中：
- `bypass_antidebug_client: true`
- `sample_execution_seen: true`
- `sample_basic_block_count > 0`
