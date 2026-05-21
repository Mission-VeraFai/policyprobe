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
    # Verify helper script is a regular file owned by current user before sourcing
    _helper_owner="$(stat -c '%u' "$HELPER_SCRIPT" 2>/dev/null || stat -f '%u' "$HELPER_SCRIPT" 2>/dev/null)"
    _current_uid="$(id -u)"
    if [ "$_helper_owner" != "$_current_uid" ]; then
        printf 'ERROR: python_helper.sh is not owned by the current user\n' >&2
        exit 1
    fi
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
        _venv_owner="$(stat -c '%u' "$VENV_ACTIVATE" 2>/dev/null || stat -f '%u' "$VENV_ACTIVATE" 2>/dev/null)"
        if [ "$_venv_owner" != "$(id -u)" ]; then
            printf 'ERROR: venv activate script is not owned by the current user\n' >&2
            exit 1
        fi
        # shellcheck source=/dev/null
        . "$VENV_ACTIVATE"
    else
        printf 'ERROR: venv activate script missing or is a symlink\n' >&2
        exit 1
    fi
    printf 'Installing Python dependencies...\n'
    pip install --require-hashes -r requirements.txt
else
    if [ -f "$VENV_ACTIVATE" ] && [ ! -L "$VENV_ACTIVATE" ]; then
        _venv_owner2="$(stat -c '%u' "$VENV_ACTIVATE" 2>/dev/null || stat -f '%u' "$VENV_ACTIVATE" 2>/dev/null)"
        if [ "$_venv_owner2" != "$(id -u)" ]; then
            printf 'ERROR: venv activate script is not owned by the current user\n' >&2
            exit 1
        fi
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
    # Construct and validate TARGET_DIR with strict literal checks before any destructive operation
    _EXPECTED_NODE_MODULES="${PROJECT_ROOT}/frontend/node_modules"
    # Resolve PROJECT_ROOT to an absolute path and reject traversal attempts
    case "$PROJECT_ROOT" in
        /*) ;;
        *) printf 'ERROR: PROJECT_ROOT is not an absolute path\n' >&2; kill "$BACKEND_PID" 2>/dev/null || true; exit 1 ;;
    esac
    case "$PROJECT_ROOT" in
        *../*|*/..*) printf 'ERROR: PROJECT_ROOT contains path traversal\n' >&2; kill "$BACKEND_PID" 2>/dev/null || true; exit 1 ;;
    esac
    # Reject if TARGET resolves to root, home, or any path shorter than expected depth
    case "$_EXPECTED_NODE_MODULES" in
        /|/home|/home/*|/root|/usr|/etc|/var|/tmp) printf 'ERROR: Refusing to delete sensitive directory\n' >&2; kill "$BACKEND_PID" 2>/dev/null || true; exit 1 ;;
    esac
    # Final guard: path must end exactly with /frontend/node_modules
    case "$_EXPECTED_NODE_MODULES" in
        */frontend/node_modules) ;;
        *) printf 'ERROR: node_modules path does not match expected pattern\n' >&2; kill "$BACKEND_PID" 2>/dev/null || true; exit 1 ;;
    esac
    # Confirm directory exists and is not a symlink before deletion
    if [ ! -d "$_EXPECTED_NODE_MODULES" ] || [ -L "$_EXPECTED_NODE_MODULES" ]; then
        printf 'ERROR: node_modules is missing or is a symlink; aborting deletion\n' >&2
        kill "$BACKEND_PID" 2>/dev/null || true
        exit 1
    fi
    readonly TARGET_DIR="$_EXPECTED_NODE_MODULES"
    printf 'AUDIT: Deleting contents of %s\n' "$TARGET_DIR" >&2
    read -r -p "Final confirmation: permanently delete '$TARGET_DIR' and all contents? [y/N]: " _DEL_CONFIRM
    if [[ ! "$_DEL_CONFIRM" =~ ^[Yy]$ ]]; then
        printf 'Deletion cancelled by user. Aborting.\n' >&2
        kill "$BACKEND_PID" 2>/dev/null || true
        exit 1
    fi
    find "$TARGET_DIR" -mindepth 1 -maxdepth 10 -not -path "$TARGET_DIR" -delete
    printf 'AUDIT: Removing directory %s\n' "$TARGET_DIR" >&2
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

if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "❌ ERROR: Frontend failed to start!"
    echo "   Check for errors above or try: cd frontend && npm install"
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        printf 'AUDIT: About to send SIGTERM to backend PID %s due to frontend startup failure.\n' "$BACKEND_PID" >&2
        read -r -p "Approve terminating backend process $BACKEND_PID? [y/N]: " _KILL_CONFIRM
        if [[ "$_KILL_CONFIRM" =~ ^[Yy]$ ]]; then
            kill -TERM "$BACKEND_PID"
        else
            printf 'Backend termination skipped by user.\n' >&2
        fi
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
