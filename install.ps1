# =============================================================================
# Igris Automated Installer for Windows (PowerShell)
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "               Installing Igris Malware Analysis Platform            " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$RepoRoot = (Resolve-Path $PSScriptRoot).Path
Write-Host "[1/5] Repository location: $RepoRoot" -ForegroundColor Gray

# 1. Check Python
Write-Host "[2/5] Checking Python environment..." -ForegroundColor Yellow
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    Write-Error "Python 3.11+ is required but was not found on PATH. Please install Python from https://python.org."
}

# 2. Check Node & npm
Write-Host "[3/5] Checking Node.js and npm..." -ForegroundColor Yellow
$NpmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $NpmCmd) {
    $NpmCmd = Get-Command npm -ErrorAction SilentlyContinue
}
if (-not $NpmCmd) {
    Write-Error "Node.js (v18+) and npm are required for frontend building. Please install Node.js from https://nodejs.org."
}

# 3. Setup Python Virtual Environment and Backend Dependencies
Write-Host "[4/5] Setting up backend dependencies and CLI launcher..." -ForegroundColor Yellow
$UvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($UvCmd) {
    Push-Location $RepoRoot
    try {
        & uv sync --extra dev
    } finally {
        Pop-Location
    }
} else {
    Write-Host "uv not found; using standard python venv and pip..." -ForegroundColor Gray
    $VenvDir = Join-Path $RepoRoot ".venv"
    if (-not (Test-Path $VenvDir)) {
        & python -m venv $VenvDir
    }
    $PipExe = Join-Path $VenvDir "Scripts\pip.exe"
    & $PipExe install -e .
}

# 4. Build Frontend Production Bundle
Write-Host "[5/5] Building frontend production bundle..." -ForegroundColor Yellow
$FrontendDir = Join-Path $RepoRoot "frontend"
Push-Location $FrontendDir
try {
    if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
        Write-Host "Installing frontend npm packages..." -ForegroundColor Gray
        & $NpmCmd install
    }
    Write-Host "Compiling Vite production bundle..." -ForegroundColor Gray
    & $NpmCmd run build
} finally {
    Pop-Location
}

# 5. Configure Global Launcher Shim and PATH
$GlobalBinDir = Join-Path $env:USERPROFILE ".igris\bin"
if (-not (Test-Path $GlobalBinDir)) {
    New-Item -ItemType Directory -Path $GlobalBinDir -Force | Out-Null
}

$LauncherCmd = Join-Path $GlobalBinDir "igris.cmd"
$PythonVenvExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

$CmdContent = @"
@echo off
setlocal
set "IGRIS_HOME=$RepoRoot"
if exist "$PythonVenvExe" (
    "$PythonVenvExe" -m igris.cli.launcher %*
) else (
    echo Error: Igris Python virtual environment not found at "$PythonVenvExe".
    echo Run install.ps1 to repair the environment.
    exit /b 1
)
"@

Set-Content -Path $LauncherCmd -Value $CmdContent -Encoding ASCII

# Ensure $GlobalBinDir is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$GlobalBinDir*") {
    $NewUserPath = "$UserPath;$GlobalBinDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    Write-Host "Added '$GlobalBinDir' to User PATH environment variable." -ForegroundColor Green
}

# Update current process PATH so igris is immediately available
if ($env:Path -notlike "*$GlobalBinDir*") {
    $env:Path = "$GlobalBinDir;$env:Path"
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "            Igris has been installed successfully!                  " -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now open Command Prompt or PowerShell from ANY directory and run:" -ForegroundColor White
Write-Host "    igris" -ForegroundColor Cyan
Write-Host ""
Write-Host "Available commands:" -ForegroundColor White
Write-Host "    igris             # Start Igris & open GUI in your browser" -ForegroundColor Gray
Write-Host "    igris --status    # Check running server status" -ForegroundColor Gray
Write-Host "    igris --stop      # Stop background server instance" -ForegroundColor Gray
Write-Host "    igris --repair    # Rebuild frontend and verify dependencies" -ForegroundColor Gray
Write-Host "    igris --version   # Display installed version" -ForegroundColor Gray
Write-Host "    igris --help      # Show all options" -ForegroundColor Gray
Write-Host "====================================================================" -ForegroundColor Green
