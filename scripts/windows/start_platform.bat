@echo off
setlocal EnableDelayedExpansion

echo ==============================================================================
echo    VAPT DEFENSIVE SECURITY PLATFORM -- SECURE WINDOWS LAUNCHER
echo ==============================================================================

rem Determine root directory relative to this script
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\..") do set "REPO_ROOT=%%~fI"

cd /d "%REPO_ROOT%"

rem 1. Locate Python executable (prefer repository virtual environment)
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%REPO_ROOT%\.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python was not found in .venv or system PATH.
        echo Please ensure Python 3.11+ is installed or virtual environment created.
        exit /b 1
    )
    set "PYTHON_EXE=python"
)

rem 2. Verify configuration (.env)
if not exist "%REPO_ROOT%\.env" (
    if exist "%REPO_ROOT%\backend\data\.env" (
        copy /y "%REPO_ROOT%\backend\data\.env" "%REPO_ROOT%\.env" >nul
        echo [INFO] Restored .env from backend/data.
    ) else if exist "%REPO_ROOT%\.env.example" (
        copy /y "%REPO_ROOT%\.env.example" "%REPO_ROOT%\.env" >nul
        echo [WARNING] No .env found. Created default development .env from .env.example.
        echo [WARNING] For production deployment, set a strong SECRET_KEY before accepting traffic.
    ) else (
        echo [ERROR] Configuration file .env is missing and no template was found.
        exit /b 1
    )
)

rem 3. Ensure data and backup directories exist
if not exist "%REPO_ROOT%\backend\data" mkdir "%REPO_ROOT%\backend\data"
if not exist "%REPO_ROOT%\backend\data\backups" mkdir "%REPO_ROOT%\backend\data\backups"

rem 4. Apply database migrations to current revision
echo [*] Checking database schema and applying pending migrations...
cd /d "%REPO_ROOT%\backend"
"%PYTHON_EXE%" -m alembic upgrade head
if %errorlevel% neq 0 (
    echo [ERROR] Alembic database migration failed. Aborting startup to prevent data corruption.
    exit /b 1
)
cd /d "%REPO_ROOT%"

rem 5. Run startup preflight security and environment checks
echo [*] Executing startup preflight checks...
"%PYTHON_EXE%" -c "import sys; sys.path.insert(0, r'%REPO_ROOT%\backend'); from app.services.startup_preflight_service import startup_preflight_service; res = startup_preflight_service.run_preflight_checks(); sys.exit(1 if res.status == 'FATAL_ERROR' else 0)"
if %errorlevel% neq 0 (
    echo [ERROR] Startup preflight check failed. Review log diagnostics.
    exit /b 1
)
echo [PASS] Preflight health and security baseline verified.

rem 6. Start Uvicorn Backend Server
echo [*] Starting FastAPI backend on http://127.0.0.1:8000...
cd /d "%REPO_ROOT%\backend"
start "VAPT Backend" /b "%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
cd /d "%REPO_ROOT%"

rem 7. Bounded readiness wait loop (max 15 seconds)
echo [*] Waiting for platform backend API readiness...
set /a ATTEMPTS=0
:WAIT_LOOP
timeout /t 1 /nobreak >nul
set /a ATTEMPTS+=1
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/v1/health' -TimeoutSec 2 -UseBasicParsing; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] VAPT Backend is operational at http://127.0.0.1:8000
    echo [API DOCS] Interactive documentation at http://127.0.0.1:8000/docs
    goto START_FRONTEND
)
if %ATTEMPTS% geq 15 (
    echo [WARNING] Backend readiness check timed out after 15 seconds.
    echo Check logs or ensure port 8000 is available.
    goto START_FRONTEND
)
goto WAIT_LOOP

:START_FRONTEND
rem 8. Start Frontend Client
if exist "%REPO_ROOT%\frontend\dist\index.html" (
    echo [*] Production frontend bundle detected at frontend/dist.
    echo [*] Launching static preview server on http://127.0.0.1:5173...
    cd /d "%REPO_ROOT%\frontend"
    start "VAPT Frontend" /b "%PYTHON_EXE%" -m http.server 5173 --directory dist --bind 127.0.0.1
    cd /d "%REPO_ROOT%"
    echo [SUCCESS] Frontend application available at http://127.0.0.1:5173
) else (
    where npm >nul 2>&1
    if %errorlevel% equ 0 (
        echo [*] Launching Vite development server...
        cd /d "%REPO_ROOT%\frontend"
        start "VAPT Frontend Dev" /b cmd /c "npm run dev -- --host 127.0.0.1 --port 5173"
        cd /d "%REPO_ROOT%"
        echo [SUCCESS] Frontend development server launching on http://127.0.0.1:5173
    ) else (
        echo [INFO] Frontend dist not built and npm not found. Backend API running.
    )
)

echo ==============================================================================
echo    VAPT PLATFORM ONLINE -- PRESS CTRL+C IN BACKGROUND WINDOW TO STOP
echo ==============================================================================
endlocal
