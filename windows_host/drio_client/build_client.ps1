# Build script for shrike_drcov_nudge.dll
# Requires Visual Studio with C++ tools installed

param(
    [string]$DynamoRIOPath = "D:\Temp\DynamoRIO",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

# Check for Visual Studio
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vsWhere)) {
    Write-Error "Visual Studio not found. Please install Visual Studio with C++ tools."
    exit 1
}

# Find Visual Studio installation
$vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    Write-Error "Visual Studio C++ tools not found. Please install C++ workload."
    exit 1
}

# Import Visual Studio environment
$vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvars32.bat"
if (-not (Test-Path $vcvarsPath)) {
    Write-Error "vcvars32.bat not found at: $vcvarsPath"
    exit 1
}

Write-Host "Using Visual Studio at: $vsPath"
Write-Host "Setting up build environment..."

# Set paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcFile = Join-Path $scriptDir "src\shrike_drcov_nudge.c"
$outDir = Join-Path $scriptDir "bin32\release"
$outDll = Join-Path $outDir "shrike_drcov_nudge.dll"

if (-not (Test-Path $srcFile)) {
    Write-Error "Source file not found: $srcFile"
    exit 1
}

if (-not (Test-Path $DynamoRIOPath)) {
    Write-Error "DynamoRIO not found at: $DynamoRIOPath"
    exit 1
}

# Create output directory
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Generate build ID
$buildId = "ED6EE248_$(Get-Date -Format 'yyyyMMddHHmmss')"

Write-Host "Building shrike_drcov_nudge.dll..."
Write-Host "  Source: $srcFile"
Write-Host "  Output: $outDll"
Write-Host "  Build ID: $buildId"

# Create temporary batch file to run compilation
$tempBat = [System.IO.Path]::GetTempFileName() + ".bat"
$tempLog = [System.IO.Path]::GetTempFileName() + ".log"

$batchContent = @"
@echo off
call "$vcvarsPath"
cd /d "$outDir"
cl.exe /LD /O2 /MT /DWINDOWS /DBUILD_ID="$buildId" ^
    /I"$DynamoRIOPath\include" ^
    /I"$DynamoRIOPath\ext\include" ^
    "$srcFile" ^
    /link /OUT:"$outDll" ^
    "$DynamoRIOPath\lib32\release\dynamorio.lib" ^
    "$DynamoRIOPath\ext\lib32\release\drmgr.lib" ^
    "$DynamoRIOPath\ext\lib32\release\drutil.lib" ^
    "$DynamoRIOPath\ext\lib32\release\drwrap.lib" ^
    ws2_32.lib
exit /b %ERRORLEVEL%
"@

Set-Content -Path $tempBat -Value $batchContent

# Run compilation
$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$tempBat`" > `"$tempLog`" 2>&1" -Wait -PassThru -NoNewWindow

# Read log
$buildLog = Get-Content $tempLog -Raw

# Clean up
Remove-Item $tempBat -Force -ErrorAction SilentlyContinue
Remove-Item $tempLog -Force -ErrorAction SilentlyContinue

if ($process.ExitCode -ne 0) {
    Write-Error "Build failed with exit code $($process.ExitCode)"
    Write-Host $buildLog
    exit 1
}

Write-Host "Build successful!"
Write-Host "Output: $outDll"

# Verify DLL exists
if (Test-Path $outDll) {
    $dllInfo = Get-Item $outDll
    Write-Host "DLL size: $($dllInfo.Length) bytes"
    Write-Host "Modified: $($dllInfo.LastWriteTime)"
} else {
    Write-Error "DLL not found after build: $outDll"
    exit 1
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Copy DLL to guest VM runtime:"
Write-Host "   Copy-Item '$outDll' 'C:\Sandbox\runtime\drio\bin32\shrike_drcov_nudge.dll' -Force"
Write-Host "2. Refresh VM snapshots:"
Write-Host "   .\windows_host\powershell\07_refresh_snapshots.ps1 -Force"
