param(
    [string]$DynamoRIOZipPath = "windows_host\third_party\DynamoRIO-Windows.zip",
    [string]$ClientSourcePath = "windows_host\drio_client\src\shrike_drcov_nudge.c",
    [string]$OutputRoot = "windows_host\drio_client",
    [switch]$Force
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "11_build_drio_nudge_client" -RepoRoot $repoRoot
$DynamoRIOZipPath = Resolve-ProjectPath -Path $DynamoRIOZipPath -RepoRoot $repoRoot
$ClientSourcePath = Resolve-ProjectPath -Path $ClientSourcePath -RepoRoot $repoRoot
$OutputRoot = Resolve-ProjectPath -Path $OutputRoot -RepoRoot $repoRoot

function Get-VcVarsAllPath {
    $vswherePath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswherePath)) {
        throw "vswhere.exe not found under the default Visual Studio Installer path."
    }

    $installationPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installationPath) {
        throw "Visual Studio Build Tools with VC x86/x64 components were not found."
    }

    $vcvarsallPath = Join-Path $installationPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsallPath)) {
        throw "vcvarsall.bat not found: $vcvarsallPath"
    }

    return $vcvarsallPath
}

function Get-CMakePath {
    $cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($cmakeCommand) {
        return $cmakeCommand.Source
    }

    $vswherePath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswherePath)) {
        throw "vswhere.exe not found under the default Visual Studio Installer path."
    }

    $installationPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installationPath) {
        throw "Visual Studio Build Tools with VC x86/x64 components were not found."
    }

    $cmakePath = Join-Path $installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (-not (Test-Path $cmakePath)) {
        throw "cmake.exe not found in PATH or Visual Studio Build Tools: $cmakePath"
    }

    return $cmakePath
}

function Expand-DynamoRIOPackage {
    param(
        [string]$PackagePath,
        [string]$TempRoot
    )

    if (Test-Path $TempRoot) {
        Remove-Item -Path $TempRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Force $TempRoot | Out-Null
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $TempRoot -Force

    $expandedChildren = @(Get-ChildItem -Path $TempRoot -Directory -Force)
    if ($expandedChildren.Count -eq 1) {
        return $expandedChildren[0].FullName
    }

    return $TempRoot
}

function Invoke-CMakeClientBuild {
    param(
        [string]$VcVarsAllPath,
        [string]$CMakePath,
        [string]$Arch,
        [string]$DrRoot,
        [string]$SourcePath,
        [string]$OutputDllPath,
        [string]$BuildRoot,
        [string]$LogPath,
        [string]$BuildId
    )

    $outputDir = Split-Path -Parent $OutputDllPath
    $machine = if ($Arch -eq "x86") { "x86" } else { "x64" }
    $platformName = if ($Arch -eq "x86") { "Win32" } else { "x64" }
    $sourceDir = Join-Path $BuildRoot ("src_{0}" -f $Arch)
    $binaryDir = Join-Path $BuildRoot ("build_{0}" -f $Arch)
    $cmakeListsPath = Join-Path $sourceDir "CMakeLists.txt"
    $commandPath = Join-Path $BuildRoot ("build_{0}.cmd" -f $Arch)

    New-Item -ItemType Directory -Force $outputDir | Out-Null
    New-Item -ItemType Directory -Force $sourceDir | Out-Null
    if (Test-Path $binaryDir) {
        Remove-Item -Path $binaryDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force $binaryDir | Out-Null

    $cmakeLists = @(
        "cmake_minimum_required(VERSION 3.14)",
        "project(shrike_drcov_nudge C CXX)",
        'set(CMAKE_CONFIGURATION_TYPES "RelWithDebInfo" CACHE STRING "" FORCE)',
        "set(DynamoRIO_USE_LIBC OFF)",
        "set(DynamoRIO_DIR ""$((Join-Path $DrRoot "cmake").Replace("\", "/"))"")",
        "set(PREFERRED_BASE 0x72000000)",
        "find_package(DynamoRIO REQUIRED)",
        "configure_DynamoRIO_global(OFF ON)",
        'set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS- /wd4100 /wd4127 /wd4054")',
        'set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS- /wd4100 /wd4127 /wd4054")',
        "add_definitions(-D_CRT_SECURE_NO_WARNINGS)",
        "include_directories(""$((Join-Path $DrRoot "ext\include").Replace("\", "/"))"")",
        "add_library(shrike_drcov_nudge SHARED ""$($SourcePath.Replace("\", "/"))"")",
        "target_compile_definitions(shrike_drcov_nudge PRIVATE BUILD_ID=""$BuildId"")",
        "configure_DynamoRIO_client(shrike_drcov_nudge)",
        "use_DynamoRIO_extension(shrike_drcov_nudge drmgr)",
        "use_DynamoRIO_extension(shrike_drcov_nudge drutil)",
        "use_DynamoRIO_extension(shrike_drcov_nudge drwrap)",
        'set_property(TARGET shrike_drcov_nudge APPEND_STRING PROPERTY LINK_FLAGS " /SUBSYSTEM:CONSOLE,5.02 /OSVERSION:5.02 /GUARD:NO")',
        "set_target_properties(shrike_drcov_nudge PROPERTIES RUNTIME_OUTPUT_DIRECTORY ""$($outputDir.Replace("\", "/"))"" LIBRARY_OUTPUT_DIRECTORY ""$($outputDir.Replace("\", "/"))"")"
    )
    Set-Content -Path $cmakeListsPath -Value ($cmakeLists -join "`r`n") -Encoding ASCII

    $commandLines = @(
        "@echo off",
        "setlocal",
        "call ""$VcVarsAllPath"" $machine >nul",
        ('"{0}" -S "{1}" -B "{2}" -G "Visual Studio 17 2022" -A {3} -DCMAKE_BUILD_TYPE=RelWithDebInfo' -f $CMakePath, $sourceDir, $binaryDir, $platformName),
        ('"{0}" --build "{1}" --config RelWithDebInfo --target shrike_drcov_nudge' -f $CMakePath, $binaryDir)
    )
    Set-Content -Path $commandPath -Value ($commandLines -join "`r`n") -Encoding ASCII

    $buildOutput = & cmd.exe /d /c $commandPath 2>&1 | Out-String
    Write-Log -Message ("build arch={0} output={1}" -f $Arch, $buildOutput.Trim()) -LogPath $LogPath

    if ($LASTEXITCODE -ne 0) {
        throw ("MSVC build failed for arch={0}. See log: {1}" -f $Arch, $LogPath)
    }

    $cmakeOutputDllPath = Join-Path (Join-Path $outputDir "RelWithDebInfo") "shrike_drcov_nudge.dll"
    if (Test-Path $cmakeOutputDllPath) {
        Copy-Item -Path $cmakeOutputDllPath -Destination $OutputDllPath -Force
    }

    if (-not (Test-Path $OutputDllPath)) {
        throw ("Expected output DLL was not produced: {0}" -f $OutputDllPath)
    }
}

try {
    if (-not (Test-Path $DynamoRIOZipPath)) {
        throw "DynamoRIO package not found: $DynamoRIOZipPath"
    }
    if (-not (Test-Path $ClientSourcePath)) {
        throw "Client source file not found: $ClientSourcePath"
    }

    $sourceHash = (Get-FileHash -Path $ClientSourcePath -Algorithm SHA256).Hash
    $buildTimestamp = Get-Date -Format "yyyyMMddHHmmss"
    $buildId = "$($sourceHash.Substring(0,8))_$buildTimestamp"

    Write-Log -Message ("Source file: {0}" -f $ClientSourcePath) -LogPath $logPath
    Write-Log -Message ("Source SHA256: {0}" -f $sourceHash) -LogPath $logPath
    Write-Log -Message ("Build ID: {0}" -f $buildId) -LogPath $logPath

    $vcvarsallPath = Get-VcVarsAllPath
    $cmakePath = Get-CMakePath
    $tempRoot = Join-Path $env:TEMP "shrike-drio-client-build"
    $drRoot = Expand-DynamoRIOPackage -PackagePath $DynamoRIOZipPath -TempRoot (Join-Path $tempRoot "expanded")

    $bin32OutputPath = Join-Path $OutputRoot "bin32\release\shrike_drcov_nudge.dll"
    $bin64OutputPath = Join-Path $OutputRoot "bin64\release\shrike_drcov_nudge.dll"

    if ($Force) {
        foreach ($existingPath in @($bin32OutputPath, $bin64OutputPath)) {
            if (Test-Path $existingPath) {
                Remove-Item -Path $existingPath -Force
            }
        }
    }

    Invoke-CMakeClientBuild -VcVarsAllPath $vcvarsallPath -CMakePath $cmakePath -Arch "x86" -DrRoot $drRoot -SourcePath $ClientSourcePath -OutputDllPath $bin32OutputPath -BuildRoot $tempRoot -LogPath $logPath -BuildId $buildId
    Invoke-CMakeClientBuild -VcVarsAllPath $vcvarsallPath -CMakePath $cmakePath -Arch "x64" -DrRoot $drRoot -SourcePath $ClientSourcePath -OutputDllPath $bin64OutputPath -BuildRoot $tempRoot -LogPath $logPath -BuildId $buildId

    $bin32Hash = (Get-FileHash -Path $bin32OutputPath -Algorithm SHA256).Hash
    $bin64Hash = (Get-FileHash -Path $bin64OutputPath -Algorithm SHA256).Hash
    $bin32Size = (Get-Item $bin32OutputPath).Length
    $bin64Size = (Get-Item $bin64OutputPath).Length
    $bin32Time = (Get-Item $bin32OutputPath).LastWriteTime
    $bin64Time = (Get-Item $bin64OutputPath).LastWriteTime

    Write-Log -Message ("Built custom drio client x86={0}" -f $bin32OutputPath) -LogPath $logPath
    Write-Log -Message ("  SHA256: {0}" -f $bin32Hash) -LogPath $logPath
    Write-Log -Message ("  Size: {0} bytes" -f $bin32Size) -LogPath $logPath
    Write-Log -Message ("  LastWriteTime: {0}" -f $bin32Time) -LogPath $logPath
    Write-Log -Message ("Built custom drio client x64={0}" -f $bin64OutputPath) -LogPath $logPath
    Write-Log -Message ("  SHA256: {0}" -f $bin64Hash) -LogPath $logPath
    Write-Log -Message ("  Size: {0} bytes" -f $bin64Size) -LogPath $logPath
    Write-Log -Message ("  LastWriteTime: {0}" -f $bin64Time) -LogPath $logPath

    [PSCustomObject]@{
        DynamoRIOZipPath = $DynamoRIOZipPath
        ClientSourcePath = $ClientSourcePath
        SourceSHA256 = $sourceHash
        BuildId = $buildId
        BuildTimestamp = $buildTimestamp
        Bin32Path = $bin32OutputPath
        Bin32SHA256 = $bin32Hash
        Bin32Size = $bin32Size
        Bin32LastWriteTime = $bin32Time
        Bin64Path = $bin64OutputPath
        Bin64SHA256 = $bin64Hash
        Bin64Size = $bin64Size
        Bin64LastWriteTime = $bin64Time
        LogPath = $logPath
    } | ConvertTo-Json -Depth 5

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
