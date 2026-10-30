@echo off
setlocal EnableDelayedExpansion

echo ==============================================================================
echo    VAPT DEFENSIVE SECURITY PLATFORM -- SAFE APPLICATION UPGRADE (Prompt 44)
echo ==============================================================================

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\..") do set "REPO_ROOT=%%~fI"

cd /d "%REPO_ROOT%"

if exist "%REPO_ROOT%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%REPO_ROOT%\.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Executing verified upgrade drill with automated snapshot backup...
"%PYTHON_EXE%" "%REPO_ROOT%\scripts\upgrade_platform.py"
if %errorlevel% neq 0 (
    echo ==============================================================================
    echo [FAIL] Platform upgrade failed. Pre-upgrade database backup is preserved in:
    echo        %REPO_ROOT%\backend\data\backups\
    echo ==============================================================================
    exit /b 1
)

echo ==============================================================================
echo [SUCCESS] Upgrade completed cleanly. Schema and preflight integrity verified.
echo ==============================================================================
endlocal
