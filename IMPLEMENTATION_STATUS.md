# DynamoRIO 反检测改进 - 实施状态

## 当前状态

### ✅ 已完成
1. **问题诊断** - 通过 trace 数据确认样本通过模块枚举检测到 DynamoRIO
2. **根本原因分析** - PEB 解链在 DynamoRIO 模块加载后执行，导致无效
3. **代码修改** - 已修改 `shrike_drcov_nudge.c`，将 PEB 操作移到 `dr_client_main` 开始
4. **文档更新** - README.md 已更新，包含完整的问题诊断和解决方案

### ⏳ 待完成
**编译修改后的 DLL** - 需要 Visual Studio C++ 编译器

## 编译环境问题

### 尝试的方法
1. ❌ Windows 主机 - 没有 Visual Studio
2. ❌ Guest VM - 没有完整的 MSVC 工具链
3. ❌ WSL MinGW - 未安装交叉编译器

### 解决方案

#### 方案 A：安装 MinGW-w64（推荐，快速）
```bash
# 在 WSL 中安装
sudo apt update
sudo apt install mingw-w64 gcc-mingw-w64-i686

# 编译
cd /mnt/d/project/ransomware/method12-dev/windows_host/drio_client
i686-w64-mingw32-gcc -shared -O2 -DWINDOWS -DBUILD_ID='"STEALTH_20260425"' \
  -I/mnt/c/Tools/DynamoRIO/include \
  -I/mnt/c/Tools/DynamoRIO/ext/include \
  src/shrike_drcov_nudge.c \
  -o bin32/release/shrike_drcov_nudge.dll \
  -L/mnt/c/Tools/DynamoRIO/lib32/release \
  -L/mnt/c/Tools/DynamoRIO/ext/lib32/release \
  -ldynamorio -ldrmgr -ldrutil -ldrwrap -lws2_32
```

#### 方案 B：使用 Visual Studio Build Tools
在 Windows 主机上安装：
```powershell
# 下载并安装 Visual Studio Build Tools
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

# 然后运行
cd D:\project\ransomware\method12-dev\windows_host\drio_client
.\build_client.ps1
```

#### 方案 C：使用现有的构建环境
如果之前有构建过，可能有构建脚本或 CMake 配置。

## 验证步骤

编译成功后：

1. **部署新 DLL**
```powershell
# 复制到 guest runtime
Copy-Item bin32\release\shrike_drcov_nudge.dll C:\Sandbox\runtime\drio\bin32\ -Force

# 或刷新快照
.\windows_host\powershell\07_refresh_snapshots.ps1 -Force
```

2. **运行测试**
```bash
.venv/bin/python sandbox/scripts/analyze_sample.py \
  samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2 \
  --task-profile sandbox/profiles/deep_cfg_drio.json
```

3. **验证结果**
```bash
# 检查 PEB 解链是否成功
grep '"event":"peb_unlink"' reports/*/raw/trace.*.ndjson

# 预期输出：
# {"event":"peb_unlink","status":"completed","unlinked_count":5}

# 检查样本代码是否执行
grep '"src":"0x00c' reports/*/raw/trace.*.ndjson | head -10

# 预期：应该看到样本地址范围的执行事件
```

## 代码修改摘要

### 关键修改
```c
// 在 dr_client_main 开始时（第 1566-1570 行）
#ifdef WINDOWS
    if (g_bypass_antidebug) {
        patch_peb_fields();           // 修补 PEB.BeingDebugged
        unlink_module_from_peb();     // 从 PEB 链表移除 DR 模块
    }
#endif

// 在 drmgr_init() 之前执行，确保 DR 模块加载时已被隐藏
```

### 预期效果
- DynamoRIO 模块在加载时立即从 PEB 中隐藏
- 样本无法通过任何 PEB 遍历方式检测到 DynamoRIO
- 样本正常执行加密逻辑
- 成功捕获完整的 CFG

## 临时替代方案

如果无法立即编译，可以：

1. **使用其他样本测试** - 找一个没有反调试的样本验证沙箱功能
2. **静态分析** - 使用 IDA Pro 分析样本的加密流程
3. **Patch 样本** - 移除样本的反调试代码（仅用于研究）

## 文件清单

- ✅ `README.md` - 已更新
- ✅ `windows_host/drio_client/src/shrike_drcov_nudge.c` - 已修改
- ✅ `windows_host/drio_client/build_client.ps1` - 已创建
- ⏳ `windows_host/drio_client/bin32/release/shrike_drcov_nudge.dll` - 需要重新编译
