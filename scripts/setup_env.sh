#!/bin/bash
#
# PolicyProbe Backend Environment Setup
#
# This script creates a Python virtual environment and installs dependencies.
# Run from the project root: ./scripts/setup_env.sh
#
# Override Python version: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "  Setting up Python Environment"
echo "=========================================="
echo ""

# Find suitable Python interpreter (3.10+)
# Load python helper using dot (POSIX) with strict path validation
if [ ! -f "$PROJECT_ROOT/scripts/python_helper.sh" ]; then
    echo "ERROR: python_helper.sh not found at expected path" >&2
    exit 1
fi
. "$PROJECT_ROOT/scripts/python_helper.sh"
echo ""

cd "$PROJECT_ROOT/backend"

# Create virtual environment if it doesn't exist
if [ -d ".venv" ]; then
    echo "✓ Virtual environment already exists"
    echo "  To recreate, remove the .venv directory manually and re-run this script."
    echo ""
else
    echo "Creating Python virtual environment..."
    "$PYTHON_CMD" -m venv .venv
    echo "✓ Virtual environment created"
    echo ""
fi

# Activate virtual environment
echo "Activating virtual environment..."
# Validate activate script before sourcing
if [ ! -f ".venv/bin/activate" ]; then
    echo "ERROR: Virtual environment activation script not found" >&2
    exit 1
fi
. .venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip
echo "✓ pip upgraded"
echo ""

# Install requirements
echo "Installing Python dependencies..."
pip install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Install frontend dependencies
echo "Installing frontend dependencies..."
cd "$PROJECT_ROOT/frontend"
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/next" ]; then
    echo "Installing npm packages..."
    npm install
    echo "✓ Frontend dependencies installed"
else
    echo "✓ Frontend dependencies already installed"
fi
echo ""

echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  Virtual environment: backend/.venv"
echo "  To activate manually: source backend/.venv/bin/activate"
echo ""
echo "=========================================="
