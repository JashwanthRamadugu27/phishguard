@echo off
setlocal enabledelayedexpansion
title PHISHING SENTINEL AI - Autonomous Threat Defense System

cd /d "%~dp0"
color 0B

echo ==============================================================================
echo        ___  _     _     _     _                ____            _   _            _ 
echo       / _ \| ^|__ (_)___^| ^|__ (_)_ __   __ _   / ___^|  ___ _ __^| ^|_(_)_ __   ___^| ^|
echo      ^| ^|_^| ^| '_ \^| / __^| '_ \^| ^| '_ \ / _` ^|  \___ \ / _ \ '__^| __^| ^| '_ \ / _ \ ^|
echo      ^|  _^| ^| ^| ^| ^| \__ \ ^| ^| ^| ^| ^| ^| ^| (_^| ^|   ___) ^|  __/ ^|  ^| ^|_^| ^| ^| ^| ^|  __/ ^|
echo      ^|_^|   ^|_^| ^|_^|_^|___/_^| ^|_^|_^|_^| ^|_^|\__, ^|  ^|____/ \___^|_^|   \__^|_^|_^| ^|_^|\___^|_^|
echo                                         ^|___/                                     
echo                      Autonomous AI Security Agent
echo ==============================================================================
echo.

:: 1. Verify .env configuration
if not exist ".env" (
    if exist ".env.example" (
        echo [!] Initializing .env from .env.example template...
        copy ".env.example" ".env" >nul
    ) else (
        echo [!] Creating default .env configuration file...
        (
            echo VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
            echo URLSCAN_API_KEY=your_urlscan_api_key_here
            echo DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_id/your_webhook_token
            echo LLM_API_KEY=your_groq_api_key_here
            echo LLM_MODEL=openai/gpt-oss-20b
            echo LLM_BASE_URL=https://api.groq.com/openai/v1
            echo VIRUSTOTAL_RATE_LIMIT=4
            echo VIRUSTOTAL_RATE_LIMIT_PERIOD=60.0
            echo VIRUSTOTAL_TIMEOUT=30.0
            echo URLSCAN_POLL_INTERVAL=5.0
            echo URLSCAN_TIMEOUT=60.0
            echo HTTP_REQUEST_TIMEOUT=15.0
            echo MAX_RETRIES=3
            echo RETRY_BACKOFF_FACTOR=1.5
            echo APP_ENV=development
            echo LOG_LEVEL=INFO
        ) > .env
    )
    echo [+] Config ready. Add your live API keys to .env or run with built-in threat simulations!
)


:: 2. Check Python Environment
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] ERROR: Python is not installed or not in PATH! Please install Python 3.10+
    pause
    exit /b 1
)

:: 3. Check for existing running instances on port 8000 / 5173
set PORT8000_RUNNING=0
set PORT5173_RUNNING=0
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    set PORT8000_RUNNING=1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do (
    set PORT5173_RUNNING=1
)

if %PORT8000_RUNNING% equ 1 (
    echo [+] Detected Backend Server already running on port 8000!
)
if %PORT5173_RUNNING% equ 1 (
    echo [+] Detected Frontend Console already running on port 5173!
)

if %PORT8000_RUNNING% equ 1 (
    echo.
    echo [*] Opening active Phishing Sentinel Console in your browser...
    if %PORT5173_RUNNING% equ 1 (
        start http://localhost:5173
    ) else (
        start http://localhost:8000
    )
    echo.
    echo ==============================================================================
    echo [+] App is ALREADY LIVE AND RUNNING:
    echo     • Web UI Console : http://localhost:5173 (or http://localhost:8000)
    echo     • API Docs (Swagger): http://localhost:8000/docs
    echo ==============================================================================
    echo.
    echo  [1] Keep Running and View Dashboard in Browser (Default)
    echo  [2] Restart All Services (Kill existing processes & restart cleanly)
    echo  [3] Run Automated Test Suite (pytest)
    echo  [4] Run Fast CLI Phishing Threat Demo Scan
    echo  [5] Exit
    echo ==============================================================================
    echo.
    set /p SUBCHOICE="Enter choice [1-5] (Press ENTER to view Dashboard): "
    if "%SUBCHOICE%"=="" set SUBCHOICE=1
    if "!SUBCHOICE!"=="1" exit /b 0
    if "!SUBCHOICE!"=="2" goto RESTART_SERVICES
    if "!SUBCHOICE!"=="3" goto RUN_TESTS
    if "!SUBCHOICE!"=="4" goto RUN_CLI
    if "!SUBCHOICE!"=="5" exit /b 0
)

:: If not running, start services
goto START_NEW_SERVICES

:RESTART_SERVICES
echo [*] Stopping previous backend & frontend processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 1 /nobreak >nul
echo [+] Previous instances cleared.

:START_NEW_SERVICES
echo [*] Installing / checking Python dependencies...
python -m pip install -r requirements.txt --quiet

set HAS_NPM=0
npm --version >nul 2>&1
if %errorlevel% equ 0 (
    set HAS_NPM=1
    if not exist "frontend\node_modules" (
        echo [*] Installing frontend packages...
        cd frontend && npm install --silent && cd ..
    )
)

echo.
echo [*] Launching Phishing Sentinel Backend API Server...
start "Phishing Sentinel API Server" cmd /k "color 0A && title Phishing Sentinel API Server && python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 2 /nobreak >nul

if "%HAS_NPM%"=="1" (
    echo [*] Launching Vite React Cyber Command Console...
    start "Phishing Sentinel Frontend" cmd /k "color 0E && title Phishing Sentinel UI && cd frontend && npm run dev"
    timeout /t 2 /nobreak >nul
    echo [*] Opening UI Console in your browser (http://localhost:5173)...
    start http://localhost:5173
) else (
    echo [*] Opening UI Console in your browser (http://localhost:8000)...
    start http://localhost:8000
)

echo.
echo ==============================================================================
echo [+] Phishing Sentinel is now LIVE and DEPLOYED!
echo.
echo  • Web UI Command Center : http://localhost:5173  (or http://localhost:8000)
echo  • REST API Documentation: http://localhost:8000/docs
echo  • Health Endpoint Check : http://localhost:8000/api/health
echo.
echo Keep the backend and frontend terminal windows open.
echo ==============================================================================
echo.
pause
exit /b 0

:RUN_CLI
echo.
echo [*] Executing Autonomous Phishing Threat Analysis Demo...
echo.
python -m app.main
echo.
pause
exit /b 0

:RUN_TESTS
echo.
echo [*] Running complete pytest test suite...
echo.
python -m pytest -v
echo.
pause
exit /b 0
