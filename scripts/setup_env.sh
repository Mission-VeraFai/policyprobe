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
    printf 'ERROR: python_helper.sh not found at expected path\n' >&2
    exit 1
fi
# Execute python_helper.sh in a subprocess and capture PYTHON_CMD
_helper_out="$(mktemp)"
bash "$PROJECT_ROOT/scripts/python_helper.sh" > "$_helper_out" 2>&1
# shellcheck source=/dev/null
PYTHON_CMD="$(grep '^PYTHON_CMD=' "$_helper_out" | tail -1 | cut -d= -f2-)"
# Remove temp file only if it is a regular file under /tmp
if [ -f "$_helper_out" ] && [[ "$_helper_out" == /tmp/* ]]; then
    # HITL approval required before deleting temporary file
printf 'APPROVAL REQUIRED: About to delete temporary file: %s\n' "$_helper_out"
printf 'Type "yes" to approve this deletion: '
read -r _hitl_approval
if [ "$_hitl_approval" != "yes" ]; then
    printf 'Deletion not approved. Aborting setup.\n' >&2
    exit 1
fi
unlink "$_helper_out"
fi
if [ -z "$PYTHON_CMD" ]; then
    printf 'ERROR: Could not determine PYTHON_CMD from python_helper.sh\n' >&2
    exit 1
fi
echo ""

cd "$PROJECT_ROOT/backend"

# Create virtual environment if it doesn't exist
if [ -d ".venv" ]; then
    printf '✓ Virtual environment already exists\n'
    printf '  To recreate, remove the .venv directory manually and re-run this script.\n'
    printf '\n'
else
    printf 'Creating Python virtual environment...\n'
    "$PYTHON_CMD" -m venv .venv
    printf '✓ Virtual environment created\n'
    printf '\n'
fi

# Activate virtual environment
printf 'Activating virtual environment...\n'
# Validate activate script before sourcing
if [ ! -f ".venv/bin/activate" ]; then
    printf 'ERROR: Virtual environment activation script not found\n' >&2
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
printf 'Upgrading pip...\n'
# Upgrade pip to a known-safe minimum version rather than unconditionally fetching latest
"$VENV_PIP" install --upgrade "pip>=23.3,<25"
printf '✓ pip upgraded\n'
printf '\n'

# Install requirements
printf 'Installing Python dependencies...\n'
"$VENV_PIP" install -r requirements.txt
printf '✓ Dependencies installed\n'
printf '\n'

# Install frontend dependencies
printf 'Installing frontend dependencies...\n'
cd "$PROJECT_ROOT/frontend"
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/next" ]; then
    printf 'Installing npm packages...\n'
    # Use 'npm ci' to install strictly from package-lock.json, preventing arbitrary dependency resolution
    npm ci
    printf '✓ Frontend dependencies installed\n'
else
    printf '✓ Frontend dependencies already installed\n'
fi
printf '\n'

printf 'Setup complete. Virtual environment: backend/.venv\n'
printf 'To activate manually: source backend/.venv/bin/activate\n'
