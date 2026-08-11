# Install Jerrick Cloud so it starts automatically when this PC boots (your "server OS" step).
# Uses a built-in Windows Scheduled Task — no extra software. Run in an *elevated* PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\install-service.ps1
# Remove later with:  schtasks /Delete /TN JerrickCloud /F

$ErrorActionPreference = 'Stop'
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Error 'node not found on PATH. Install Node.js first.'; exit 1 }

$dir    = $PSScriptRoot
$server = Join-Path $dir 'server.js'
if (-not (Test-Path $server)) { Write-Error "server.js not found in $dir"; exit 1 }

# __dirname makes the server cwd-independent, so we only need node + the script path.
$action = "`"$node`" `"$server`""
schtasks /Create /TN 'JerrickCloud' /TR $action /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null

Write-Host "Installed. Jerrick Cloud will start on every boot as task 'JerrickCloud'."
Write-Host "Start it now without rebooting:  schtasks /Run /TN JerrickCloud"
Write-Host "Then open http://localhost:8080  (apps you left running are auto-restored on boot)."
