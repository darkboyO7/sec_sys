<#
.SYNOPSIS
    Safe Windows Native Upgrade Script for VAPT Platform (Prompt 44).
.DESCRIPTION
    Creates pre-upgrade point-in-time database snapshot, applies Alembic migrations,
    verifies post-upgrade schema health, and provides unambiguous rollback paths.
#>
[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "   VAPT PLATFORM -- SAFE APPLICATION UPGRADE (Prompt 44)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Resolve-Path "$ScriptDir\..\.." | Select-Object -ExpandProperty Path
Set-Location $RepoRoot

$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$UpgradeScript = Join-Path $RepoRoot "scripts\upgrade_platform.py"
& $PythonExe $UpgradeScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "Upgrade process exited with failure code $LASTEXITCODE. Database backup preserved in backend\data\backups\."
    exit 1
}

Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "   UPGRADE VERIFIED AND COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
