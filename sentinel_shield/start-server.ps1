# Sentinel Shield - Start Server
# PowerShell script to start the FastAPI backend server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sentinel Shield - Starting Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "+" -NoNewline
    Write-Host " Virtual environment found" -ForegroundColor Green
    Write-Host "Activating venv..." -ForegroundColor Yellow
    & "venv\Scripts\Activate.ps1"
}
else {
    Write-Host "!" -NoNewline  
    Write-Host " Virtual environment not found" -ForegroundColor Yellow
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "+" -NoNewline
        Write-Host " Virtual environment created" -ForegroundColor Green
        & "venv\Scripts\Activate.ps1"
    }
    else {
        Write-Host "x Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# Check if dependencies are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$fastapi_check = python -c "import fastapi; print(fastapi.__version__)" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "!" -NoNewline
    Write-Host " Dependencies not installed" -ForegroundColor Yellow
    Write-Host "Installing requirements..." -ForegroundColor Yellow
    Write-Host ""
    
    pip install -r requirements.txt
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "+" -NoNewline
        Write-Host " Dependencies installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host ""
        Write-Host "x Failed to install dependencies" -ForegroundColor Red
        Write-Host "Try manually: pip install -r requirements.txt" -ForegroundColor Yellow
        exit 1
    }
}
else {
    Write-Host "+" -NoNewline
    Write-Host " FastAPI $fastapi_check installed" -ForegroundColor Green
}

Write-Host ""

# Check if database is configured
if (-not (Test-Path "config\database.env")) {
    Write-Host "!" -NoNewline
    Write-Host " Database configuration not found" -ForegroundColor Yellow
    Write-Host "Creating default configuration..." -ForegroundColor Yellow
    
    if (-not (Test-Path "config")) {
        New-Item -ItemType Directory -Path "config" | Out-Null
    }
    
    $configContent = @"
# Sentinel Shield - Database Configuration
DATABASE_URL=sqlite:///./sentinel_shield.db
REDIS_URL=redis://localhost:6379
SECRET_KEY=dev-secret-key-change-in-production
"@
    
    $configContent | Out-File -FilePath "config\database.env" -Encoding UTF8
    
    Write-Host "+" -NoNewline
    Write-Host " Default configuration created" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting Sentinel Shield Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 Server starting on http://localhost:8000" -ForegroundColor White
Write-Host "📄 API Documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host "📊 Dashboard: http://localhost:8000/dashboard" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host ""

# Change to src directory and start server
cd src

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "X Server failed to start" -ForegroundColor Red
    exit 1
}
