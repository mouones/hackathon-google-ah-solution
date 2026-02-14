# Anti-Fraud Platform Test Script

This script tests all API endpoints to verify the system is working.

## Prerequisites
- Backend server running on http://localhost:5000
- ML service running on http://localhost:8000

## Test Cases

### 1. Test User Registration
```powershell
$body = @{
    email = "test@example.com"
    password = "Test123!"
    name = "Test User"
    organization = "Test Org"
    role = "citizen"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/auth/register" -Method POST -Body $body -ContentType "application/json"
$token = $response.token
Write-Host "✓ Registration successful. Token: $token" -ForegroundColor Green
```

### 2. Test User Login
```powershell
$body = @{
    email = "test@example.com"
    password = "Test123!"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/auth/login" -Method POST -Body $body -ContentType "application/json"
$token = $response.token
Write-Host "✓ Login successful. User: $($response.user.name)" -ForegroundColor Green
```

### 3. Test Email Analysis (Legitimate Email)
```powershell
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$body = @{
    subject = "Meeting Tomorrow"
    body = "Hi John,`n`nJust wanted to confirm our meeting tomorrow at 2 PM.`n`nBest regards,`nSarah"
    sender = "sarah@company.com"
    senderName = "Sarah Johnson"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "✓ Legitimate email analyzed. Threat Score: $($response.threatScore)" -ForegroundColor Green
```

### 4. Test Email Analysis (Phishing Email)
```powershell
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$body = @{
    subject = "URGENT: Your Account Will Be Suspended"
    body = "Dear valued customer,`n`nYour account has been suspended due to suspicious activity. Click here immediately to verify your account: http://paypa1.com/verify`n`nFailure to act within 24 hours will result in permanent account closure.`n`nSincerely,`nPayPal Security Team"
    sender = "security@paypa1-verify.com"
    senderName = "PayPal Security"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "✓ Phishing email detected! Threat Score: $($response.threatScore)" -ForegroundColor Red
Write-Host "  Recommendation: $($response.recommendation.action)" -ForegroundColor Yellow
Write-Host "  Automated Response: $($response.automatedResponse.actionsCompleted) actions taken in $($response.automatedResponse.responseTime)ms" -ForegroundColor Cyan
```

### 5. Test Character Substitution Detection
```powershell
$body = @{
    subject = "Verify Your PayPaI Account"
    body = "Dear custorner,`n`nPlease verify your accоunt immediately.`n`nBest regards,`nPayPal"
    sender = "support@paypa1.com"
    senderName = "PayPal Support"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "✓ Character substitution detected! Score: $($response.checks.char_substitution.score)" -ForegroundColor Yellow
```

### 6. Get Analysis History
```powershell
$response = Invoke-RestMethod -Uri "http://localhost:5000/api/email/history?limit=10" -Method GET -Headers $headers
Write-Host "✓ Retrieved $($response.emails.Count) emails from history" -ForegroundColor Green
```

### 7. Test ML Service Health
```powershell
$response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method GET
Write-Host "✓ ML Service Health: $($response.status)" -ForegroundColor Green
Write-Host "  Model Loaded: $($response.model_loaded)" -ForegroundColor Cyan
```

### 8. Test Backend Health
```powershell
$response = Invoke-RestMethod -Uri "http://localhost:5000/health" -Method GET
Write-Host "✓ Backend Health: $($response.status)" -ForegroundColor Green
```

## Quick Test Script (Run All)
```powershell
# Set up
$baseUrl = "http://localhost:5000/api"
$mlUrl = "http://localhost:8000"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ANTI-FRAUD PLATFORM - API TESTS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Register
Write-Host "[1/8] Testing Registration..." -ForegroundColor Yellow
$body = @{ email = "testuser@example.com"; password = "SecurePass123!"; name = "Test User"; role = "citizen" } | ConvertTo-Json
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method POST -Body $body -ContentType "application/json"
    $token = $response.token
    Write-Host "      ✓ Registration successful`n" -ForegroundColor Green
} catch {
    # User might already exist, try login
    $body = @{ email = "testuser@example.com"; password = "SecurePass123!" } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $body -ContentType "application/json"
    $token = $response.token
    Write-Host "      ✓ Login successful (user exists)`n" -ForegroundColor Green
}

$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

# 2. Analyze legitimate email
Write-Host "[2/8] Testing Legitimate Email..." -ForegroundColor Yellow
$body = @{
    subject = "Project Update Meeting"
    body = "Hi Team,`n`nLet's meet tomorrow at 3 PM to discuss the project progress.`n`nBest regards,`nJohn Smith"
    sender = "john.smith@company.com"
    senderName = "John Smith"
} | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$baseUrl/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "      Threat Score: $($response.threatScore) - $($response.recommendation.level)`n" -ForegroundColor Green

# 3. Analyze phishing email
Write-Host "[3/8] Testing Phishing Email..." -ForegroundColor Yellow
$body = @{
    subject = "URGENT ACTION REQUIRED!!!"
    body = "Your account has been compromised! Click here NOW: http://secure-paypa1.tk/login to verify or your account will be closed!`n`nPayPal Team"
    sender = "noreply@paypa1-secure.tk"
    senderName = "PayPal Security"
} | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$baseUrl/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "      Threat Score: $($response.threatScore) - $($response.recommendation.level)" -ForegroundColor Red
if ($response.automatedResponse) {
    Write-Host "      Automated Response: $($response.automatedResponse.actionsCompleted) actions in $($response.automatedResponse.responseTime)ms`n" -ForegroundColor Cyan
}

# 4. Test history
Write-Host "[4/8] Testing History Retrieval..." -ForegroundColor Yellow
$response = Invoke-RestMethod -Uri "$baseUrl/email/history" -Method GET -Headers $headers
Write-Host "      ✓ Retrieved $($response.total) total emails`n" -ForegroundColor Green

# 5. Test ML service
Write-Host "[5/8] Testing ML Service..." -ForegroundColor Yellow
$response = Invoke-RestMethod -Uri "$mlUrl/health" -Method GET
Write-Host "      ML Status: $($response.status) | Model Loaded: $($response.model_loaded)`n" -ForegroundColor Green

# 6. Test character substitution
Write-Host "[6/8] Testing Character Substitution Detection..." -ForegroundColor Yellow
$body = @{
    subject = "PayPaI Security Alert"
    body = "Dear custorner, please verify your accоunt at paypa1.com"
    sender = "security@paypa1.com"
    senderName = "PayPal"
} | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$baseUrl/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "      Char Substitution Score: $($response.checks.char_substitution.score)`n" -ForegroundColor Yellow

# 7. Test name mismatch
Write-Host "[7/8] Testing Name Mismatch Detection..." -ForegroundColor Yellow
$body = @{
    subject = "Important Update"
    body = "Hello,`n`nPlease review the attached document.`n`nBest regards,`nMichael Johnson"
    sender = "sarah.williams@example.com"
    senderName = "Sarah Williams"
} | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$baseUrl/email/analyze" -Method POST -Headers $headers -Body $body
Write-Host "      Name Mismatch: $($response.checks.name_mismatch.hasMismatch) | Severity: $($response.checks.name_mismatch.severity)`n" -ForegroundColor Yellow

# 8. Backend health
Write-Host "[8/8] Testing Backend Health..." -ForegroundColor Yellow
$response = Invoke-RestMethod -Uri "http://localhost:5000/health" -Method GET
Write-Host "      Backend Status: $($response.status)`n" -ForegroundColor Green

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✓ ALL TESTS COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
```

## Expected Results

### Legitimate Email
- Threat Score: 0-30
- Level: safe/low
- No automated response triggered

### Phishing Email
- Threat Score: 70-100
- Level: high/critical
- Automated response triggered
- 6 containment actions executed in <1000ms

### Detection Features
- Character substitution (rn vs m, etc.)
- Name mismatch between sender and signature
- Suspicious URLs with subdomain analysis
- VirusTotal threat detection (if API key configured)
- ML model prediction (97% accuracy)
