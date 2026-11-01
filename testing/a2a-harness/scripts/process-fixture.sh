#!/usr/bin/env bash
# Shared by A2A fixture launchers; no process is accepted merely because a port answers.
A2A_PROCESS_FIXTURE_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")/../a2aht" && pwd)/process_fixture.py"

# Turn interruption into a normal exit so the launcher's EXIT reaper runs.
fixture_exit_on_signal() {
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

fixture_owns_listener() {
  fixture_same_process "$1" && python3 -I "$A2A_PROCESS_FIXTURE_PY" "$1" "$2" && fixture_same_process "$1"
}

fixture_track_pid() {
  local identity=""
  if fixture_is_job "$1"; then
    identity="$(python3 -I "$A2A_PROCESS_FIXTURE_PY" identity "$1")"
    fixture_is_job "$1" || identity=""
  fi
  printf -v "A2A_FIXTURE_ID_$1" '%s' "$identity"
}

fixture_is_job() {
  local pid jobs
  jobs="$(jobs -pr)" || return 1
  for pid in $jobs; do
    [ "$pid" != "$1" ] || return 0
  done
  return 1
}

fixture_same_process() {
  local name="A2A_FIXTURE_ID_$1" identity
  identity="${!name:-}"
  [ -n "$identity" ] && [ "$(python3 -I "$A2A_PROCESS_FIXTURE_PY" identity "$1")" = "$identity" ]
}

fixture_signal() {
  local name="A2A_FIXTURE_ID_$1"
  python3 -I "$A2A_PROCESS_FIXTURE_PY" signal "$1" "${!name:-}" "$2"
}

# fixture_await_card <pid> <port> <tries> <interval> [url]
# Callers retain their existing readiness windows.
fixture_await_card() {
  local pid="$1" port="$2" tries="$3" interval="$4"
  local url="${5:-http://127.0.0.1:$2/.well-known/agent-card.json}"
  local attempt
  for ((attempt=0; attempt<tries; attempt++)); do
    fixture_same_process "$pid" || return 1
    if fixture_owns_listener "$pid" "$port" &&
        curl -fsS -m 2 -o /dev/null "$url" &&
        fixture_owns_listener "$pid" "$port"; then
      return 0
    fi
    sleep "$interval"
  done
  return 1
}

# Reuse the TCK's existing five-second TERM grace, then reap even after KILL.
fixture_stop() {
  local pid="${1:-}" attempt killed=0
  [ -n "$pid" ] || return 0
  fixture_signal "$pid" 15 || true
  for ((attempt=0; attempt<50; attempt++)); do
    fixture_same_process "$pid" || break
    sleep 0.1
  done
  if fixture_same_process "$pid" && fixture_signal "$pid" 9; then killed=1; fi
  if [ "$killed" -eq 0 ] && kill -0 "$pid" 2>/dev/null; then
    echo "could not prove termination of fixture child $pid; refusing an unbounded wait" >&2
    return 1
  fi
  wait "$pid" 2>/dev/null || true
  unset "A2A_FIXTURE_ID_$pid"
}
