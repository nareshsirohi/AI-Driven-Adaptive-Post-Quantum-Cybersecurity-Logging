#!/bin/bash
cd "$(dirname "$0")"

# Activate Python Virtual Environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

echo "================================================================================"
echo " 🛡️  AI-Driven Adaptive Post-Quantum Cybersecurity Logging System"
echo " 📍  ABESIT / AKTU Capstone Project (ID: 2023CSEAI025)"
echo " 🌐  Starting SOC Dashboard on http://localhost:8000"
echo "================================================================================"
echo ""
echo "Press Ctrl + C to stop the server anytime."
echo ""

python3 main.py server --port 8000
