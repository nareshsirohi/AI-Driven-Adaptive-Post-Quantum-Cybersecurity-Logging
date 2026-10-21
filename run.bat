@echo off
REM ==============================================================================
REM 1-Click Server Runner for Windows Teammates
REM ==============================================================================

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo ================================================================================
echo  Starting Post-Quantum Cyber Security Logging Dashboard
echo  Open in browser: http://localhost:8000
echo ================================================================================
echo.
echo Press Ctrl + C to stop the server anytime.
echo.

python main.py server --port 8000
pause
