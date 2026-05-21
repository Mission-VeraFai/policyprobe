#!/bin/bash
#
# PolicyProbe Development Server Stop Script
#
# This script stops both the frontend and backend servers.
# Run from anywhere: ./scripts/stop_dev.sh
#

printf '%s\n' "=========================================="
printf '%s\n' "  Stopping PolicyProbe Servers"
printf '%s\n' "=========================================="
printf '\n'

# Safely stop a process listening on a given port.
# Usage: stop_port <port> <label>
stop_port() {
    local port="$1"
    local label="$2"
    local pid

    pid=$(lsof -i ":${port}" -t 2>/dev/null | head -n 1)
    if [ -z "${pid}" ]; then
        printf -- '- %s was not running\n' "${label}"
        return 0
    fi

    # Validate that pid is a positive integer before using it
    if ! printf '%s' "${pid}" | grep -qE '^[0-9]+$'; then
        printf 'ERROR: unexpected value from lsof for port %s; skipping.\n' "${port}" >&2
        return 1
    fi

    # Attempt graceful termination first
    kill -TERM "${pid}" 2>/dev/null

    # Wait up to 5 seconds for the process to exit
    local waited=0
    while kill -0 "${pid}" 2>/dev/null && [ "${waited}" -lt 5 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    # Force-kill only if the process is still alive after the grace period
    if kill -0 "${pid}" 2>/dev/null; then
        kill -KILL "${pid}" 2>/dev/null
    fi

    printf -- '\xe2\x9c\x93 %s stopped (port %s)\n' "${label}" "${port}"
}

# Stop backend on port 5500
stop_port 5500 "Backend"

# Stop frontend on port 5001
stop_port 5001 "Frontend"

printf '\n'
printf '%s\n' "=========================================="
printf '%s\n' "  All servers stopped"
printf '%s\n' "=========================================="
