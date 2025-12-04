# Quick activation script - sets PYTHONPATH for vibe_code_bench
$env:PYTHONPATH = "$PWD\src"
Write-Host "PYTHONPATH set to: $env:PYTHONPATH" -ForegroundColor Green
Write-Host "You can now use: .\venv\Scripts\python.exe" -ForegroundColor Cyan

