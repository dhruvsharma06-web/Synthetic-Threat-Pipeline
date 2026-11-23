# Start the range on Windows. Usage: .\Start-SOC.ps1 [-Soc]   (-Soc adds Wazuh, needs ~8 GB RAM)
param([switch]$Soc)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .env)) {
    Write-Error "No .env found. Run: Copy-Item .env.example .env  and set the passwords."
}

$profiles = @("--profile", "range", "--profile", "ui")
if ($Soc) { $profiles += @("--profile", "soc") }

foreach ($d in "cowrie", "vsftpd", "dvwa", "sar2html", "victim") {
    New-Item -ItemType Directory -Force -Path "logs\$d" | Out-Null
}
docker compose @profiles up -d --build --wait
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose @profiles ps
Write-Host "Range is up. Dashboard: http://localhost:8081   Grafana: http://localhost:3000" -ForegroundColor Green
