#!/usr/bin/env bash
# Reference fixture controls. Existing dependency caches may be supplied through
# A2A_TCK_WORK, A2AHT_CONTROL_SRC, A2AHT_CONTROL_BIN and A2A_REFERENCE_PYTHON.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
source "$ROOT/testing/a2a-harness/scripts/process-fixture.sh"
: "${A2A_REFERENCE_OUT:?set a fresh evidence output directory}"
mkdir -p "$A2A_REFERENCE_OUT"
A2A_REFERENCE_OUT="$(cd "$A2A_REFERENCE_OUT" && pwd)"
export TZ="${A2A_TCK_TZ:-America/New_York}"
export A2A_TCK_OUT="$A2A_REFERENCE_OUT/tck"

battery_go() (
  binding="$1"
  transport=http_json
  [ "$binding" != jsonrpc ] || transport=jsonrpc
  port="${A2A_REFERENCE_PORT:-9099}"
  rm -f "$A2A_REFERENCE_OUT/battery-go-$binding.json"
  cd "$ROOT/testing/a2a-harness"
  exec python3 -m a2aht run --tier pre-release --role server \
    --launch "$HERE/go/serve.sh $port $transport" --port "$port" \
    --label "reference-fixture:a2a-go-v2.4.0/$binding/server" \
    --json "$A2A_REFERENCE_OUT/battery-go-$binding.json"
)

# Measure the Go SDK server and CLI client together. The unchanged assertion
# floor cannot qualify the client-only profile (nine asserted rows, floor ten).
battery_go_client() (
  : "${A2AHT_CONTROL_BIN:?set the pinned Go CLI binary directory}"
  port="${A2A_REFERENCE_PORT:-9099}"
  rm -f "$A2A_REFERENCE_OUT/battery-go-client.json"
  cd "$ROOT/testing/a2a-harness"
  exec python3 -m a2aht run --tier pre-release --roles server client \
    --launch "$HERE/go/serve.sh $port http_json" --port "$port" \
    --client-drive "$A2AHT_CONTROL_BIN/a2a send {url} hello-from-harness" \
    --label "reference-fixture:a2a-go-v2.4.0/server+client" \
    --json "$A2A_REFERENCE_OUT/battery-go-client.json"
)

battery_python() (
  port="${A2A_REFERENCE_PORT:-41241}"
  rm -f "$A2A_REFERENCE_OUT/battery-python.json"
  "$HERE/python/serve.sh" "$port" > "$A2A_REFERENCE_OUT/python-server.log" 2>&1 &
  pid=$!
  trap 'fixture_stop "$pid" || exit 2' EXIT
  fixture_exit_on_signal
  fixture_track_pid "$pid"
  fixture_await_card "$pid" "$port" 60 1 || {
    cat "$A2A_REFERENCE_OUT/python-server.log" >&2
    exit 2
  }
  cd "$ROOT/testing/a2a-harness"
  python3 -m a2aht run --tier pre-release --role server \
    --endpoint "http://127.0.0.1:$port" \
    --label "reference-fixture:a2a-python-1.1.2/server" \
    --json "$A2A_REFERENCE_OUT/battery-python.json"
)

case "${1:-}" in
  tck-go-rest) exec "$ROOT/testing/a2a-tck/run-tck.sh" control-http-json ;;
  tck-go-jsonrpc) exec "$ROOT/testing/a2a-tck/run-tck.sh" control-jsonrpc ;;
  battery-go-rest) battery_go rest ;;
  battery-go-jsonrpc) battery_go jsonrpc ;;
  battery-python) battery_python ;;
  battery-go-client) battery_go_client ;;
  *) echo 'usage: run-controls.sh tck-go-rest|tck-go-jsonrpc|battery-go-rest|battery-go-jsonrpc|battery-python|battery-go-client' >&2; exit 2 ;;
esac
