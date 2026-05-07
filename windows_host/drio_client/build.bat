@echo off
setlocal enabledelayedexpansion

set DRIO_PATH=D:\Temp\DynamoRIO
set SRC=D:\project\ransomware\method12-dev\windows_host\drio_client\src\shrike_drcov_nudge.c
set OUT_DIR=D:\project\ransomware\method12-dev\windows_host\drio_client\bin32\release
set OUT_DLL=%OUT_DIR%\shrike_drcov_nudge.dll
set BUILD_ID=ED6EE248_20260502120000

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

call "C:\Download\msvc\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

cd /d "%OUT_DIR%"

cl.exe /LD /O2 /MT /DWINDOWS /DX86_32 /DBUILD_ID=\"%BUILD_ID%\" ^
    /I"%DRIO_PATH%\include" ^
    /I"%DRIO_PATH%\ext\include" ^
    "%SRC%" ^
    /link /OUT:"%OUT_DLL%" ^
    "%DRIO_PATH%\lib32\release\dynamorio.lib" ^
    "%DRIO_PATH%\ext\lib32\release\drmgr.lib" ^
    "%DRIO_PATH%\ext\lib32\release\drutil.lib" ^
    "%DRIO_PATH%\ext\lib32\release\drwrap.lib" ^
    ws2_32.lib

echo Build exit code: %ERRORLEVEL%
