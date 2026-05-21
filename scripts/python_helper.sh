#!/bin/bash
#
# Python Version Detection Helper
#
# This script finds a suitable Python interpreter (3.10+) and exports PYTHON_CMD.
# This script sets PYTHON_CMD when executed or dot-included by a parent script.
#
# Override with: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh
#

# Minimum required Python version
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

# Safe helper: print a message to stderr only
log_msg() {
    echo "$*" >&2
}

# Function to check if a Python version meets minimum requirements
check_python_version() {
    local python_cmd="$1"

    # Check if command exists (use type -P to avoid exec-style command -v)
    if ! type -P "$python_cmd" &> /dev/null; then
        return 1
    fi

    # Get version and validate
    local version_output
    version_output=$("$python_cmd" --version 2>&1) || return 1

    # Parse version (e.g., "Python 3.12.1" -> "3.12.1")
    local version
    version=$(printf '%s' "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [ -z "$version" ]; then
        return 1
    fi

    # Extract major and minor versions
    local major minor
    major=$(printf '%s' "$version" | cut -d. -f1)
    minor=$(printf '%s' "$version" | cut -d. -f2)

    # Check if version meets minimum
    if [ "$major" -gt "$PYTHON_MIN_MAJOR" ]; then
        return 0
    elif [ "$major" -eq "$PYTHON_MIN_MAJOR" ] && [ "$minor" -ge "$PYTHON_MIN_MINOR" ]; then
        return 0
    fi

    return 1
}

# Function to find a suitable Python interpreter
find_python() {
    # Allow override via environment variable
    if [ -n "$PYTHON_PATH" ]; then
        if check_python_version "$PYTHON_PATH"; then
            echo "$PYTHON_PATH"
            return 0
        else
            log_msg "ERROR: PYTHON_PATH does not meet minimum version requirement (Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+)"
            return 1
        fi
    fi

    # List of Python commands to try (prefer newer versions)
    local python_candidates=(
        "python3"
        "python3.14"
        "python3.13"
        "python3.12"
        "python3.11"
        "python3.10"
        "python"
    )

    for cmd in "${python_candidates[@]}"; do
        if check_python_version "$cmd"; then
            echo "$cmd"
            return 0
        fi
    done

    return 1
}

# Main: Find and # HITL approval gate: require explicit confirmation before exporting PYTHON_CMD
# Set HITL_AUTO_APPROVE=1 only in trusted CI/CD environments where human review
# of the pipeline configuration substitutes for interactive approval.
if [ "${HITL_AUTO_APPROVE:-0}" != "1" ]; then
    log_msg ""
    log_msg "========================================="
    log_msg "  APPROVAL REQUIRED (Human in the Loop)"
    log_msg "========================================="
    log_msg "  The following Python interpreter will be exported as PYTHON_CMD:"
    log_msg "    $PYTHON_CMD"
    log_msg ""
    log_msg "  Type 'yes' to approve and continue, or anything else to abort:"
    log_msg "========================================="
    # Read from /dev/tty so approval works even when stdin is redirected
    read -r HITL_RESPONSE < /dev/tty
    if [ "$HITL_RESPONSE" != "yes" ]; then
        log_msg "Aborted by user. PYTHON_CMD was NOT exported."
        exit 1
    fi
    log_msg "Approved."
fi

export PYTHON_CMD

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    log_msg "Using: $PYTHON_VERSION ($PYTHON_CMD)"
find_python)

if [ -z "$PYTHON_CMD" ]; then
    log_msg "=========================================="
    log_msg "  ERROR: No suitable Python found!"
    log_msg "=========================================="
    log_msg ""
    log_msg "  This project requires Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} or newer."
    log_msg ""
    log_msg "  Options:"
    log_msg "    1. Install Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ from https://python.org"
    log_msg "    2. Use pyenv: pyenv install 3.12"
    log_msg "    3. Specify a Python path: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh"
    log_msg ""
    log_msg "=========================================="
    exit 1
fi

# PYTHON_CMD is set for use by the calling script; export only if needed by subprocesses
# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    log_msg "Using: $PYTHON_VERSION ($PYTHON_CMD)"
fi
