# ============================================================
#  HoursLog — Production Launcher (PowerShell)
# ============================================================

# Check for .env file
if (-not (Test-Path ".env")) {
    Write-Warning "No .env file found. Copy .env.example to .env and fill in SECRET_KEY and DATABASE_URL before running in production."
    Write-Host ""
}

# Force production environment
$env:FLASK_ENV = "production"

Write-Host "Starting HoursLog in production mode ..." -ForegroundColor Green

try {
    python wsgi.py
}
catch {
    Write-Error "Server failed to start: $_"
}
