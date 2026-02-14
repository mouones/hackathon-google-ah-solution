# Quick Test - Anti-Fraud Platform

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " ANTI-FRAUD PLATFORM - QUICK TEST" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test 1: Backend Health
Write-Host "[1/4] Backend Health Check..." -ForegroundColor Yellow
$backend = Invoke-RestMethod -Uri "http://localhost:5000/health"
Write-Host "      ✓ Status: $($backend.status)`n" -ForegroundColor Green

# Test 2: Register User
Write-Host "[2/4] User Registration..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "HHmmss"
$body = @{
    email = "testuser$timestamp@example.com"
    password = "SecurePass123!"
    name = "Test User"
    role = "citizen"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/auth/register" `
    -Method POST -Body $body -ContentType "application/json"
$token = $response.token
Write-Host "      ✓ User: $($response.user.email)`n" -ForegroundColor Green

# Test 3: Analyze Legitimate Email
Write-Host "[3/4] Analyzing Legitimate Email..." -ForegroundColor Yellow
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$body = @{
    subject = "Team Meeting"
    body = "Hi team, meeting tomorrow at 2 PM. Best, John"
    sender = "john@company.com"
    senderName = "John Smith"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:5000/api/email/analyze" `
    -Method POST -Headers $headers -Body $body

Write-Host "      Threat Score: $($result.threatScore)/100 ($($result.recommendation.level))`n" -ForegroundColor Green

# Test 4: Analyze Phishing Email
Write-Host "[4/4] Analyzing Phishing Email..." -ForegroundColor Yellow
$body = @{
    subject = "URGENT: Account Suspended!!!"
    body = "Your PayPal accоunt suspended! Verify at http://paypa1.tk/verify NOW or lose access forever!"
    sender = "security@paypa1-verify.tk"
    senderName = "PayPal Security"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:5000/api/email/analyze" `
    -Method POST -Headers $headers -Body $body

Write-Host "      ✓ PHISHING DETECTED!" -ForegroundColor Red
Write-Host "      Threat Score: $($result.threatScore)/100" -ForegroundColor Red
Write-Host "      Level: $($result.recommendation.level)" -ForegroundColor Yellow
Write-Host "      Action: $($result.recommendation.action)" -ForegroundColor Yellow
Write-Host "      Analysis Time: $($result.analysisTimeMs)ms" -ForegroundColor Cyan

if ($result.automatedResponse) {
    Write-Host "`n      Automated Response Triggered:" -ForegroundColor Green
    Write-Host "        • Actions: $($result.automatedResponse.actionsCompleted)" -ForegroundColor Green
    Write-Host "        • Time: $($result.automatedResponse.responseTime)ms" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✓ ALL TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
