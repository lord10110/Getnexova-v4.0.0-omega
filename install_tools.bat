@echo off
REM ════════════════════════════════════════════════════════
REM GetNexova v4.0.0 OMEGA — Windows Tool Installer
REM ════════════════════════════════════════════════════════
REM Run this script in PowerShell or CMD as Administrator
REM Requires: Go 1.22+, Python 3.10+, Git
REM ════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   GetNexova Tool Installer (Windows)     ║
echo  ╚══════════════════════════════════════════╝
echo.

REM Check Go installation
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Go is not installed. Please install Go from https://go.dev/dl/
    echo     Then re-run this script.
    pause
    exit /b 1
)
echo [+] Go found: 
go version

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Install from https://python.org
    pause
    exit /b 1
)
echo [+] Python found:
python --version

REM Install Python dependencies
echo.
echo [*] Installing Python dependencies...
pip install -r requirements.txt

REM Install Go tools
echo.
echo [*] Installing subfinder...
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo [*] Installing httpx...
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo [*] Installing nuclei...
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo [*] Installing dalfox...
go install github.com/hahwul/dalfox/v2@latest

echo [*] Installing gitleaks...
go install github.com/gitleaks/gitleaks/v8@latest

REM Update nuclei templates
echo.
echo [*] Updating nuclei templates...
nuclei -update-templates 2>nul

REM Create workspace
echo.
echo [*] Creating workspace directories...
if not exist "data" mkdir data
if not exist "reports" mkdir reports
if not exist "logs" mkdir logs
if not exist "memory\store" mkdir memory\store

REM Setup environment
echo.
if not exist ".env" (
    echo [*] Creating .env from template...
    copy .env.example .env
    echo [!] Please edit .env and add your API keys
)

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Installation Complete!                  ║
echo  ╠══════════════════════════════════════════╣
echo  ║                                          ║
echo  ║  Run health check:                       ║
echo  ║    python cli.py --health-check           ║
echo  ║                                          ║
echo  ║  Start scanning:                          ║
echo  ║    python cli.py -t target.com            ║
echo  ║                                          ║
echo  ╚══════════════════════════════════════════╝
echo.
pause
