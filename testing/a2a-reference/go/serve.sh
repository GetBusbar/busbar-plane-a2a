#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${A2AHT_CONTROL_BIN:-$HERE/bin}"
"$HERE/build.sh" >&2
exec "$BIN/a2a-reference-go" --port "${1:?port required}" --transport "${2:?transport required}"
