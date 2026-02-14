# Anti-Fraud Platform - Quick Start

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "ANTI-FRAUD PLATFORM - STARTING SERVICES" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Start ML Service
Write-Host "Starting ML Service..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd C:\hack\anti-fraud-platform\ml-service; Write-Host '🤖 ML Service' -ForegroundColor Green; C:\hack\anti-fraud-platform\ml-service\venv\Scripts\python.exe main.py"

Start-Sleep -Seconds 3

# Start Backend
Write-Host "Starting Backend API..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd C:\hack\anti-fraud-platform\backend; Write-Host '⚙️  Backend API' -ForegroundColor Green; npm run dev"

Start-Sleep -Seconds 3

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " SERVICES STARTED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "`n ML Service: http://localhost:8000" -ForegroundColor White
Write-Host "   Backend API: http://localhost:5000" -ForegroundColor White
Write-Host "`nAPI Endpoints:" -ForegroundColor Cyan
Write-Host "   POST http://localhost:5000/api/auth/register" -ForegroundColor White
Write-Host "   POST http://localhost:5000/api/auth/login" -ForegroundColor White
Write-Host "   POST http://localhost:5000/api/email/analyze" -ForegroundColor White
Write-Host "   GET  http://localhost:5000/api/email/history" -ForegroundColor White
Write-Host "   GET  http://localhost:5000/health" -ForegroundColor White
Write-Host "`n Test with: node tests\integration.test.js" -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Green
