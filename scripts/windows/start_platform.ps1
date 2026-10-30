<#
.SYNOPSIS
    Secure Windows Native Launcher for VAPT Platform (Prompt 44).
.DESCRIPTION
    Launches backend and frontend services with configuration checks,
    automatic migration validation, port conflict detection, and bounded health probes.
.PARAMETER Environment
    Application environment: 'development' (default) or 'production'.
.PARAMETER Port
    Port for the backend service (default: 8000).
.PARAMETER SkipFrontend
    If specified, only the backend API server is launched.
#>
[CmdletBinding()]
param (
    [ValidateSet("development", "production")]
    [string]$Environment = "development",
    [int]$Port = 8000,
    [string]$HostAddress = "127.0.0.1",
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "   VAPT PLATFORM -- SECURE WINDOWS NATIVE LAUNCHER (Prompt 44)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Resolve-Path "$ScriptDir\..\.." | Select-Object -ExpandProperty Path
Set-Location $RepoRoot

# 1. Resolve Python
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCmd) {
        Write-Error "Python 3.11+ is required but neither .venv nor system Python was found."
        exit 1
    }
    $PythonExe = "python"
}
Write-Host "[*] Using Python: $PythonExe" -ForegroundColor Gray

# 2. Check Configuration
$EnvPath = Join-Path $RepoRoot ".env"
if (-not (Test-Path $EnvPath)) {
    $BackendEnv = Join-Path $RepoRoot "backend\data\.env"
    $EnvExample = Join-Path $RepoRoot ".env.example"
    if (Test-Path $BackendEnv) {
        Copy-Item $BackendEnv $EnvPath
        Write-Host "[+] Restored .env from backend/data/.env" -ForegroundColor Green
    } elseif (Test-Path $EnvExample) {
        Copy-Item $EnvExample $EnvPath
        Write-Host "[!] Generated default development .env from .env.example" -ForegroundColor Yellow
    } else {
        Write-Error "No .env or configuration template found."
        exit 1
    }
}

# 3. Check Port Conflicts
$TcpConn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($TcpConn) {
    Write-Host "[!] Port $Port is currently in use by process ID $($TcpConn.OwningProcess)." -ForegroundColor Yellow
    Write-Host "[!] Ensure existing platform instances or conflicting servers are stopped." -ForegroundColor Yellow
}

# 4. Apply Database Migrations
Write-Host "[*] Validating and applying database migrations to head..." -ForegroundColor Cyan
Push-Location "$RepoRoot\backend"
try {
    & $PythonExe -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Alembic migration failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
Write-Host "[+] Database schema verified and up to date." -ForegroundColor Green

# 5. Startup Preflight Health & Security Checks
Write-Host "[*] Executing preflight security baseline validation..." -ForegroundColor Cyan
$PreflightCmd = "import sys; sys.path.insert(0, r'$RepoRoot\backend'); from app.services.startup_preflight_service import startup_preflight_service; res = startup_preflight_service.run_preflight_checks(); sys.exit(1 if res.status == 'FATAL_ERROR' else 0)"
& $PythonExe -c $PreflightCmd
if ($LASTEXITCODE -ne 0) {
    Write-Error "Preflight check failed. Aborting startup."
    exit 1
}
Write-Host "[+] Preflight security baseline confirmed." -ForegroundColor Green

# 6. Start Backend Process
Write-Host "[*] Launching backend server on http://$HostAddress`:$Port..." -ForegroundColor Cyan
$BackendArgs = "-m uvicorn app.main:app --host $HostAddress --port $Port"
$BackendProcess = Start-Process -FilePath $PythonExe -ArgumentList $BackendArgs -WorkingDirectory "$RepoRoot\backend" -PassThru -WindowStyle Hidden
Write-Host "[+] Backend started with Process ID: $($BackendProcess.Id)" -ForegroundColor Green

# 7. Bounded Readiness Probe
Write-Host "[*] Probing API readiness at http://$HostAddress`:$Port/api/v1/health..." -ForegroundColor Gray
$Ready = $false
$Attempts = 0
while (-not $Ready -and $Attempts -lt 15) {
    Start-Sleep -Seconds 1
    $Attempts++
    try {
        $Response = Invoke-WebRequest -Uri "http://$HostAddress`:$Port/api/v1/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($Response.StatusCode -eq 200) {
            $Ready = $true
        }
    } catch {
        # Retry until timeout
    }
}

if ($Ready) {
    Write-Host "[SUCCESS] VAPT Backend API is operational!" -ForegroundColor Green
    Write-Host "          API Health: http://$HostAddress`:$Port/api/v1/health" -ForegroundColor Gray
    Write-Host "          Swagger Docs: http://$HostAddress`:$Port/docs" -ForegroundColor Gray
} else {
    Write-Host "[WARNING] Readiness probe timed out. Backend may still be initializing." -ForegroundColor Yellow
}

# 8. Start Frontend Client (if not skipped)
if (-not $SkipFrontend) {
    $DistIndex = Join-Path $RepoRoot "frontend\dist\index.html"
    if (Test-Path $DistIndex) {
        Write-Host "[*] Launching production distribution static server on http://127.0.0.1:5173..." -ForegroundColor Cyan
        $FrontendArgs = "-m http.server 5173 --directory dist --bind 127.0.0.1"
        $FrontendProcess = Start-Process -FilePath $PythonExe -ArgumentList $FrontendArgs -WorkingDirectory "$RepoRoot\frontend" -PassThru -WindowStyle Hidden
        Write-Host "[SUCCESS] Frontend UI is active at http://127.0.0.1:5173 (PID: $($FrontendProcess.Id))" -ForegroundColor Green
    } else {
        $NpmCmd = Get-Command npm -ErrorAction SilentlyContinue
        if ($NpmCmd) {
            Write-Host "[*] Launching Vite development server on http://127.0.0.1:5173..." -ForegroundColor Cyan
            $FrontendProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm run dev -- --host 127.0.0.1 --port 5173" -WorkingDirectory "$RepoRoot\frontend" -PassThru -WindowStyle Hidden
            Write-Host "[SUCCESS] Frontend dev server started (PID: $($FrontendProcess.Id))" -ForegroundColor Green
        }
    }
}

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "   VAPT PLATFORM INITIALIZED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
