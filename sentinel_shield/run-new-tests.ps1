# Sentinel Shield - Quick Test Runner
# Run integration tests for new security modules

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sentinel Shield - Integration Tests" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found. Please install Python 3.11+" -ForegroundColor Red
    exit 1
}

# Check if pytest is installed
Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$pytestCheck = python -c "import pytest; print(pytest.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ pytest not found. Installing..." -ForegroundColor Yellow
    pip install pytest
} else {
    Write-Host "✓ pytest: $pytestCheck" -ForegroundColor Green
}

# Run tests
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running Integration Tests..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Change to tests directory
cd tests

# Run pytest with verbose output
pytest test_new_security_modules.py -v --tb=short --color=yes

# Check result
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ All Tests Passed!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ✗ Some Tests Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}

# Return to root
cd ..
