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

    # Verify the PID belongs to the current user before sending any signal.
    # This prevents accidental or malicious termination of other users' processes.
    local pid_owner
    pid_owner=$(ps -o user= -p "${pid}" 2>/dev/null)
    if [ "${pid_owner}" != "$(id -un)" ]; then
        printf 'ERROR: PID %s on port %s is not owned by current user; skipping.\n' "${pid}" "${port}" >&2
        return 1
    fi

    # Send SIGTERM to request graceful shutdown of the development server process.
    # SIGTERM is the standard, non-destructive way to ask a process to exit cleanly.
    /bin/kill -TERM "${pid}" 2>/dev/null

    # Wait up to 5 seconds for the process to exit
    local waited=0
    # SIGKILL=0 check: used only to test process liveness (no signal is delivered).
    while /bin/kill -0 "${pid}" 2>/dev/null && [ "${waited}" -lt 5 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    # Send SIGKILL only if the process is still alive after the grace period.
    # This is a last-resort measure limited to the current user's own dev-server process.
    if /bin/kill -0 "${pid}" 2>/dev/null; then
        /bin/kill -KILL "${pid}" 2>/dev/null
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
