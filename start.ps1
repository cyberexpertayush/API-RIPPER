<#
    API RIPPER — Start Script
    Launches backend (FastAPI) and frontend (Vite) simultaneously
#>

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║           API RIPPER — Starting Up           ║" -ForegroundColor Cyan
Write-Host "  ║   Advanced API Security Scanner Platform     ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = $PSScriptRoot

# ── Backend ──────────────────────────────────────────────────
Write-Host "[1/2] Starting Backend (FastAPI + GSec Engine)..." -ForegroundColor Yellow

$backendDir = Join-Path $ProjectRoot "backend"

# Check if requirements are installed
Write-Host "  > Installing Python dependencies..." -ForegroundColor DarkGray
Push-Location $backendDir
pip install -r requirements.txt -q 2>$null
Pop-Location

Write-Host "  > Launching uvicorn on http://127.0.0.1:8000" -ForegroundColor Green
$backendJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    Set-Location ..  # Go to API RIPPER root so 'backend.main' is importable
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
} -ArgumentList $backendDir

Start-Sleep -Seconds 3

# ── Frontend ─────────────────────────────────────────────────
Write-Host "[2/2] Starting Frontend (Vite + React)..." -ForegroundColor Yellow

$frontendDir = Join-Path $ProjectRoot "frontend"

# Install node_modules if missing
if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "  > Installing npm dependencies..." -ForegroundColor DarkGray
    Push-Location $frontendDir
    npm install --silent 2>$null
    Pop-Location
}

Write-Host "  > Launching Vite on http://localhost:5173" -ForegroundColor Green
$frontendJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    npm run dev
} -ArgumentList $frontendDir

Start-Sleep -Seconds 2

# ── Status ───────────────────────────────────────────────────
Write-Host ""
Write-Host "  ✓ Backend:  http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  ✓ API Docs: http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "  ✓ Frontend: http://localhost:5173" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop both servers" -ForegroundColor DarkGray
Write-Host ""

# Wait and forward output
try {
    while ($true) {
        Receive-Job $backendJob -ErrorAction SilentlyContinue | Write-Host
        Receive-Job $frontendJob -ErrorAction SilentlyContinue | Write-Host
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host ""
    Write-Host "Stopping servers..." -ForegroundColor Yellow
    Stop-Job $backendJob -ErrorAction SilentlyContinue
    Stop-Job $frontendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob -Force -ErrorAction SilentlyContinue
    Remove-Job $frontendJob -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Servers stopped" -ForegroundColor Green
}
