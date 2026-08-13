#!/bin/bash

# GitHub Security Auditor - One Command Launcher
# Usage: ./run.sh

set -e

echo "═════════════════════════════════════════════════════════════"
echo "  GitHub Security Auditor"
echo "  Standards-Based Security Audit Tool"
echo "═════════════════════════════════════════════════════════════"
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Install Python 3 from https://www.python.org/"
    exit 1
fi

echo "[INFO] Python 3 found: $(python3 --version)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Install/update requirements
echo "[INFO] Checking dependencies..."
pip install -q -r requirements.txt 2>/dev/null || pip install -r requirements.txt

# Create audit results directory
mkdir -p audit_results

# Start the web server
echo ""
echo "═════════════════════════════════════════════════════════════"
echo ""
echo "  Starting GitHub Security Auditor Web Interface"
echo ""
echo "  Access the application at: http://localhost:5000"
echo ""
echo "  Press Ctrl+C to stop the server"
echo ""
echo "═════════════════════════════════════════════════════════════"
echo ""

# Run Flask app
python3 app.py
