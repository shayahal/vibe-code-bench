# Setup script for vibe-code-bench venv
# This script creates a fresh venv and installs everything

Write-Host "Setting up virtual environment..." -ForegroundColor Green

# Remove existing venv if it exists
if (Test-Path "venv") {
    Write-Host "Removing existing venv..." -ForegroundColor Yellow
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Remove-Item -Recurse -Force venv -ErrorAction SilentlyContinue
}

# Create fresh venv
Write-Host "Creating new virtual environment..." -ForegroundColor Green
python -m venv venv

# Bootstrap pip
Write-Host "Bootstrapping pip..." -ForegroundColor Green
.\venv\Scripts\python.exe -m ensurepip --upgrade

# Upgrade pip, setuptools, wheel
Write-Host "Upgrading pip, setuptools, wheel..." -ForegroundColor Green
.\venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel

# Install package with all dependencies
Write-Host "Installing vibe-code-bench and dependencies..." -ForegroundColor Green
Write-Host "This may take a few minutes..." -ForegroundColor Yellow
.\venv\Scripts\python.exe -m pip install -e .

# Test imports
Write-Host "`nTesting imports..." -ForegroundColor Green
$env:PYTHONPATH = "$PWD\src"
.\venv\Scripts\python.exe test_setup.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Setup complete! Virtual environment is ready." -ForegroundColor Green
    Write-Host "`nTo activate the venv, run:" -ForegroundColor Cyan
    Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "`nOr set PYTHONPATH and use:" -ForegroundColor Cyan
    Write-Host "  `$env:PYTHONPATH=`"$PWD\src`"" -ForegroundColor White
} else {
    Write-Host "`n⚠ Some imports failed. Check the output above." -ForegroundColor Yellow
}

