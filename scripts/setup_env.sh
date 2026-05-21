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

# Find suitable Python interpreter (3.10+) — inline discovery, no external script execution
PYTHON_CMD=""
for _candidate in "${PYTHON_PATH:-}" python3.12 python3.11 python3.10 python3; do
    [ -z "$_candidate" ] && continue
    # Resolve to absolute path and ensure it lives under known safe prefixes
    _abs="$(command -v "$_candidate" 2>/dev/null || true)"
    [ -z "$_abs" ] && continue
    case "$_abs" in
        /usr/*|/opt/*|/home/*/.pyenv/*|/usr/local/*) ;;
        *) printf 'WARN: Skipping interpreter at unexpected path: %s\n' "$_abs" >&2; continue ;;
    esac
    # Verify version is 3.10+
    _ver="$("$_abs" -c 'import sys; print("%d%02d" % sys.version_info[:2])' 2>/dev/null || true)"
    if [ -n "$_ver" ] && [ "$_ver" -ge 31000 ] 2>/dev/null; then
        PYTHON_CMD="$_abs"
        break
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    printf 'ERROR: No suitable Python 3.10+ interpreter found\n' >&2
    exit 1
fi
printf '\n'

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
printf '\n'

# Upgrade pip
printf 'Upgrading pip...\n'
# Upgrade pip to a known-safe minimum version rather than unconditionally fetching latest
"$VENV_PIP" install --upgrade "pip==24.3.1"
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
printf 'To activate manually, run the activation script: backend/.venv/bin/activate\n'
