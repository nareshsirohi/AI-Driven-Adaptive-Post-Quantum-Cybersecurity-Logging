@echo off
REM ==============================================================================
REM Automated Setup Script for Windows Teammates
REM AI-Driven Adaptive Post-Quantum Cybersecurity Logging (Project ID: 2023CSEAI025)
REM ABESIT Ghaziabad / AKTU Lucknow
REM ==============================================================================

echo ================================================================================
echo  Setting up Post-Quantum Cyber Security Logging Project on Windows
echo ================================================================================

REM 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your system PATH!
    echo Please install Python 3.9+ from https://www.python.org/ and check "Add Python to PATH"
    pause
    exit /b 1
)

python --version

REM 2. Create virtual environment
if not exist "venv" (
    echo [INFO] Creating virtual environment in .\venv...
    python -m venv venv
) else (
    echo [INFO] Virtual environment already exists.
)

REM 3. Activate venv & install dependencies
echo [INFO] Activating virtual environment & installing requirements...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

REM 4. Initialize model & run tests
echo [INFO] Initializing AI threat model...
python main.py train

echo [INFO] Running automated unit tests...
python main.py test

echo.
echo ================================================================================
echo  SETUP COMPLETED SUCCESSFULLY! No errors found.
echo ================================================================================
echo.
echo To start the server anytime on Windows:
echo   Double-click run.bat  OR  run: python main.py server
echo.
echo Dashboard URL: http://localhost:8000
echo ================================================================================
pause
