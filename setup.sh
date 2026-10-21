#!/bin/bash
# ==============================================================================
# Automated Setup Script for macOS and Linux Teammates
# AI-Driven Adaptive Post-Quantum Cybersecurity Logging (Project ID: 2023CSEAI025)
# ABESIT Ghaziabad / AKTU Lucknow
# ==============================================================================

set -e
cd "$(dirname "$0")"

echo "================================================================================"
echo " 🛡️  Setting up Post-Quantum Cyber Security Logging Project"
echo "================================================================================"

# 1. Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed or not in your PATH."
    echo "Please install Python 3.9+ from https://www.python.org/"
    exit 1
fi

PY_VER=$(python3 --version)
echo "✅ Found $PY_VER"

# 2. Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment in ./venv..."
    python3 -m venv venv
else
    echo "✅ Virtual environment already exists."
fi

# 3. Activate venv & upgrade pip
echo "🔄 Activating virtual environment & updating pip..."
source venv/bin/activate
python3 -m pip install --upgrade pip --quiet

# 4. Install dependencies
echo "📥 Installing required packages from requirements.txt..."
python3 -m pip install -r requirements.txt --quiet

# 5. Train initial model & create directories
echo "🧠 Initializing AI Threat Model & directories..."
python3 main.py train

# 6. Run quick self-test
echo "🧪 Running unit tests to verify installation..."
python3 main.py test

echo ""
echo "================================================================================"
echo " 🎉 SETUP COMPLETED SUCCESSFULLY! No errors found."
echo "================================================================================"
echo ""
echo "To start the project:"
echo "  Option 1: Run in terminal:  ./run.sh"
echo "  Option 2: Open in VS Code:  code . (Then press F5 or Run main.py)"
echo ""
echo "Dashboard URL: http://localhost:8000"
echo "================================================================================"
