@echo off
REM ============================================================
REM  HoursLog — Production Launcher (Windows)
REM ============================================================

REM Check for .env file
if not exist ".env" (
    echo [WARNING] No .env file found. Copy .env.example to .env and
    echo           fill in SECRET_KEY and DATABASE_URL before running
    echo           in production.
    echo.
)

REM Force production environment
set FLASK_ENV=production

echo Starting HoursLog in production mode ...
python wsgi.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Server failed to start. Check the output above.
    pause
)
