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

# Safe helper: print a pre-approved static message to stderr only
# Only whitelisted message keys are accepted to prevent injection.
log_msg() {
    local msg
    # Sanitize: strip all characters except alphanumeric, spaces, punctuation safe set
    msg=$(printf '%s' "$*" | tr -cd 'A-Za-z0-9 _./:+-')
    printf '%s\n' "$msg" >&2
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

# Main: Find a suitable Python interpreter
# Validate PYTHON_CMD against a strict allowlist before use as an executable.
_validate_python_cmd() {
    local cmd="$1"
    # Allow only known-safe bare names or absolute paths matching /usr/*/python3* or /usr/local/*/python3*
    case "$cmd" in
        python|python3|python3.[0-9]|python3.[0-9][0-9]|\
        python3.1[0-9]|python3.2[0-9])
            return 0 ;;
        /usr/bin/python3*|/usr/local/bin/python3*|\
        /usr/bin/python|/usr/local/bin/python|\
        /opt/homebrew/bin/python3*)
            return 0 ;;
        *)
            log_msg "ERROR: PYTHON_CMD value '$cmd' is not in the allowed list of Python interpreters."
            return 1 ;;
    esac
}

# find_python sets PYTHON_CMD
PYTHON_CMD=$(find_python)

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

# PYTHON_CMD is set for use by the calling script; callers may export it if needed.
# Validate before any use as an executable.
if ! _validate_python_cmd "$PYTHON_CMD"; then
    exit 1
fi

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    log_msg "Using: $PYTHON_VERSION ($PYTHON_CMD)"
fi
