# =============================================================================
# Igris Automated Uninstaller for Windows (PowerShell)
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "               Uninstalling Igris Global Launcher                    " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$GlobalBinDir = Join-Path $env:USERPROFILE ".igris\bin"
$LauncherCmd = Join-Path $GlobalBinDir "igris.cmd"

# Remove launcher shim
if (Test-Path $LauncherCmd) {
    Remove-Item -Path $LauncherCmd -Force
    Write-Host "Removed launcher command: $LauncherCmd" -ForegroundColor Green
}

# Remove from User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -like "*$GlobalBinDir*") {
    $PathEntries = $UserPath -split ";" | Where-Object { $_ -and ($_ -ne $GlobalBinDir) }
    $NewUserPath = $PathEntries -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    Write-Host "Removed '$GlobalBinDir' from User PATH environment variable." -ForegroundColor Green
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "            Igris Global Launcher Uninstalled Successfully!         " -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "Note: Your sample binaries, database records, notes, and analysis" -ForegroundColor Gray
Write-Host "artifacts in the repository directory have been preserved." -ForegroundColor Gray
