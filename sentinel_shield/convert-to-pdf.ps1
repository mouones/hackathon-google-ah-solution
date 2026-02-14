# Sentinel Shield - Convert Presentation to PDF
# PowerShell script to convert Markdown slides to PDF

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sentinel Shield - PDF Converter" -ForegroundColor Cyan
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

Write-Host ""
Write-Host "Checking for PDF conversion tools..." -ForegroundColor Yellow
Write-Host ""

# Try running the Python converter
Write-Host "Running PDF converter..." -ForegroundColor Cyan
python convert_to_pdf.py

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ PDF Created Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output: Sentinel_Shield_Presentation.pdf" -ForegroundColor White
    Write-Host ""
    
    # Open PDF if created
    if (Test-Path "Sentinel_Shield_Presentation.pdf") {
        Write-Host "Opening PDF..." -ForegroundColor Yellow
        Start-Process "Sentinel_Shield_Presentation.pdf"
    }
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Conversion Failed - Installing Tools" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    
    # Try installing Python packages
    Write-Host "Installing Python PDF conversion packages..." -ForegroundColor Yellow
    Write-Host ""
    
    pip install markdown weasyprint Pillow
    
    Write-Host ""
    Write-Host "Retrying conversion..." -ForegroundColor Yellow
    python convert_to_pdf.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Success after installing packages!" -ForegroundColor Green
        if (Test-Path "Sentinel_Shield_Presentation.pdf") {
            Start-Process "Sentinel_Shield_Presentation.pdf"
        }
    } else {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  Manual Installation Required" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Install Pandoc (recommended):" -ForegroundColor White
        Write-Host "  1. Download from: https://pandoc.org/installing.html" -ForegroundColor Gray
        Write-Host "  2. Or use Chocolatey: choco install pandoc" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Then run this script again." -ForegroundColor White
    }
}
