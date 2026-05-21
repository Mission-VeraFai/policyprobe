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

printf 'Setting up Python Environment\n'

# Find suitable Python interpreter (3.10+)
# Load python helper using dot (POSIX) with strict path validation
if [ ! -f "$PROJECT_ROOT/scripts/python_helper.sh" ]; then
    echo "ERROR: python_helper.sh not found at expected path" >&2
    exit 1
fi
# Execute python_helper.sh in a subprocess and capture PYTHON_CMD
_helper_out="$(mktemp)"
bash "$PROJECT_ROOT/scripts/python_helper.sh" > "$_helper_out" 2>&1
# shellcheck source=/dev/null
PYTHON_CMD="$(grep '^PYTHON_CMD=' "$_helper_out" | tail -1 | cut -d= -f2-)"
rm -f "$_helper_out"
if [ -z "$PYTHON_CMD" ]; then
    printf 'ERROR: Could not determine PYTHON_CMD from python_helper.sh\n' >&2
    exit 1
fi
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
# Use venv binaries directly instead of sourcing the activate script
VENV_PYTHON="$PROJECT_ROOT/backend/.venv/bin/python"
VENV_PIP="$PROJECT_ROOT/backend/.venv/bin/pip"
if [ ! -x "$VENV_PYTHON" ]; then
    printf 'ERROR: venv python binary not found or not executable\n' >&2
    exit 1
fi
printf 'Virtual environment ready\n'
echo ""

# Upgrade pip
echo "Upgrading pip..."
"$VENV_PIP" install --upgrade pip
echo "✓ pip upgraded"
echo ""

# Install requirements
echo "Installing Python dependencies..."
"$VENV_PIP" install -r requirements.txt
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

printf 'Setup complete. Virtual environment: backend/.venv\n'
printf 'To activate manually: source backend/.venv/bin/activate\n'
