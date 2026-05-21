#!/bin/bash
#
# PolicyProbe Development Server
#
# This script starts both the frontend and backend servers for development.
# Run from the project root: ./scripts/run_dev.sh
#
# Override Python version: PYTHON_PATH=/path/to/python ./scripts/run_dev.sh
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "  PolicyProbe Development Server"
echo "=========================================="
echo ""

# Find suitable Python interpreter (3.10+)
# Source python helper only if it exists within the project root
HELPER_SCRIPT="$PROJECT_ROOT/scripts/python_helper.sh"
case "$HELPER_SCRIPT" in
    "$PROJECT_ROOT"/*) ;;
    *) printf 'ERROR: python_helper.sh path escapes project root\n' >&2; exit 1 ;;
esac
if [ -f "$HELPER_SCRIPT" ] && [ ! -L "$HELPER_SCRIPT" ]; then
    # shellcheck source=scripts/python_helper.sh
    . "$HELPER_SCRIPT"
else
    printf 'ERROR: python_helper.sh not found or is a symlink at expected path\n' >&2
    exit 1
fi
echo ""

# Check for required environment variables
if [ -z "$OPENROUTER_API_KEY" ]; then
    printf 'WARNING: OPENROUTER_API_KEY not set\n' >&2
    printf 'The LLM features will not work without it.\n' >&2
    printf 'Set it with: export OPENROUTER_API_KEY=your_key_here\n' >&2
    printf '\n' >&2
fi

# Function to cleanup background processes on exit
cleanup() {
    echo ""
    echo "Shutting down servers..."
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -TERM "$BACKEND_PID"
    fi
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        kill -TERM "$FRONTEND_PID"
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start backend
echo "Starting Python backend..."
cd "$PROJECT_ROOT/backend"

# Check if virtual environment exists
VENV_ACTIVATE="$PROJECT_ROOT/backend/.venv/bin/activate"
if [ ! -d "$PROJECT_ROOT/backend/.venv" ]; then
    echo "Creating Python virtual environment..."
    "$PYTHON_CMD" -m venv "$PROJECT_ROOT/backend/.venv"
    if [ -f "$VENV_ACTIVATE" ] && [ ! -L "$VENV_ACTIVATE" ]; then
        # shellcheck source=/dev/null
        . "$VENV_ACTIVATE"
    else
        printf 'ERROR: venv activate script missing or is a symlink\n' >&2
        exit 1
    fi
    printf 'Installing Python dependencies...\n'
    pip install -r requirements.txt
else
    if [ -f "$VENV_ACTIVATE" ] && [ ! -L "$VENV_ACTIVATE" ]; then
        # shellcheck source=/dev/null
        . "$VENV_ACTIVATE"
    else
        printf 'ERROR: venv activate script missing or is a symlink\n' >&2
        exit 1
    fi
fi

# Start uvicorn in background
uvicorn main:app --reload --host 127.0.0.1 --port 5500 &
BACKEND_PID=$!
echo "Backend started (PID: $BACKEND_PID)"
echo "Backend URL: http://localhost:5500"
echo ""

# Wait for backend to be ready
echo "Waiting for backend to be ready..."
sleep 3

# Start frontend
echo "Starting Next.js frontend..."
cd "$PROJECT_ROOT/frontend"

# Check if node_modules exists and is valid
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
elif [ ! -f "node_modules/.bin/next" ]; then
        echo "⚠️  node_modules exists but is incomplete. Reinstalling..."
    echo "APPROVAL REQUIRED: About to run 'rm -rf node_modules' (destructive delete)."
    read -r -p "Do you approve deleting node_modules and reinstalling? [y/N]: " HITL_CONFIRM
    if [[ ! "$HITL_CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled by user. Aborting."
        kill $BACKEND_PID 2>/dev/null || true
        exit 1
    fi
    TARGET_DIR="$PROJECT_ROOT/frontend/node_modules"
    case "$TARGET_DIR" in
        "$PROJECT_ROOT/frontend/"*) ;;
        *) printf 'ERROR: node_modules path escapes frontend directory\n' >&2; kill "$BACKEND_PID" 2>/dev/null || true; exit 1 ;;
    esac
    find "$TARGET_DIR" -mindepth 1 -delete
    rmdir "$TARGET_DIR"
    npm install
fi

# Start Next.js in background on port 5001
npm run dev -- -p 5001 &
FRONTEND_PID=$!
echo "Frontend started (PID: $FRONTEND_PID)"
echo ""

# Wait for frontend to start and verify it's still running
echo "Waiting for frontend to initialize..."
sleep 3

if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    echo "❌ ERROR: Frontend failed to start!"
    echo "   Check for errors above or try: cd frontend && npm install"
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -TERM "$BACKEND_PID"
    fi
    exit 1
fi

echo "=========================================="
echo "  Servers are running!"
echo "=========================================="
echo ""
echo "  Frontend: http://localhost:5001"
echo "  Backend:  http://localhost:5500"
echo "  API Docs: http://localhost:5500/docs"
echo ""
echo "  Press Ctrl+C to stop all servers"
echo "=========================================="
echo ""

# Wait for both processes
wait
