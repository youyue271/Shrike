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

function Invoke-MsvcClientBuild {
    param(
        [string]$VcVarsAllPath,
        [string]$Arch,
        [string]$DrRoot,
        [string]$SourcePath,
        [string]$OutputDllPath,
        [string]$CommandPath,
        [string]$LogPath,
        [string]$BuildId
    )

    $libSuffix = if ($Arch -eq "x86") { "lib32" } else { "lib64" }
    $includeDir = Join-Path $DrRoot "include"
    $extIncludeDir = Join-Path $DrRoot "ext\include"
    $dynamorioLib = Join-Path $DrRoot ("{0}\release\dynamorio.lib" -f $libSuffix)
    $drmgrLib = Join-Path $DrRoot ("ext\{0}\release\drmgr.lib" -f $libSuffix)
    $drutilLib = Join-Path $DrRoot ("ext\{0}\release\drutil.lib" -f $libSuffix)
    $drwrapLib = Join-Path $DrRoot ("ext\{0}\release\drwrap.lib" -f $libSuffix)
    $outputDir = Split-Path -Parent $OutputDllPath
    $outputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputDllPath)
    $objectPath = Join-Path $outputDir ("{0}.obj" -f $outputBaseName)
    $machine = if ($Arch -eq "x86") { "x86" } else { "x64" }
    $archDefine = if ($Arch -eq "x86") { "X86_32" } else { "X86_64" }

    New-Item -ItemType Directory -Force $outputDir | Out-Null

    $commandLines = @(
        "@echo off",
        "setlocal",
        "call ""$VcVarsAllPath"" $machine >nul",
        "cl.exe /nologo /LD /O2 /MT /DWINDOWS /D$archDefine /DBUILD_ID=\`"$BuildId\`" /I ""$includeDir"" /I ""$extIncludeDir"" /Fo""$objectPath"" /Fe""$OutputDllPath"" ""$SourcePath"" ""$dynamorioLib"" ""$drmgrLib"" ""$drutilLib"" ""$drwrapLib"""
    )
    Set-Content -Path $CommandPath -Value ($commandLines -join "`r`n") -Encoding ASCII

    $buildOutput = & cmd.exe /d /c $CommandPath 2>&1 | Out-String
    Write-Log -Message ("build arch={0} output={1}" -f $Arch, $buildOutput.Trim()) -LogPath $LogPath

    if ($LASTEXITCODE -ne 0) {
        throw ("MSVC build failed for arch={0}. See log: {1}" -f $Arch, $LogPath)
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

    Invoke-MsvcClientBuild -VcVarsAllPath $vcvarsallPath -Arch "x86" -DrRoot $drRoot -SourcePath $ClientSourcePath -OutputDllPath $bin32OutputPath -CommandPath (Join-Path $tempRoot "build_x86.cmd") -LogPath $logPath -BuildId $buildId
    Invoke-MsvcClientBuild -VcVarsAllPath $vcvarsallPath -Arch "x64" -DrRoot $drRoot -SourcePath $ClientSourcePath -OutputDllPath $bin64OutputPath -CommandPath (Join-Path $tempRoot "build_x64.cmd") -LogPath $logPath -BuildId $buildId

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
