@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo Building exediff.sln in Release x64...

set "MSBUILD=C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe"
if exist "%MSBUILD%" goto :build

for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do (
    set "MSBUILD=%%i"
    goto :build
)

where msbuild.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "MSBUILD=msbuild.exe"
    goto :build
)

echo Error: MSBuild not found! Please build the project manually in Visual Studio.
exit /b 1

:build
"%MSBUILD%" "exediff.sln" /p:Configuration=Release /p:Platform=x64 /m /v:minimal /nologo

if %ERRORLEVEL% EQU 0 (
    echo Build completed successfully!
) else (
    echo Build failed! Check the errors above.
    exit /b 1
)

endlocal
