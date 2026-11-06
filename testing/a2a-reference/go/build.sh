#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${A2AHT_CONTROL_BIN:-$HERE/bin}"
mkdir -p "$BIN"
cd "$HERE"
[ "$(go list -m -f '{{.Version}}' github.com/a2aproject/a2a-go/v2)" = v2.4.0 ]
go mod verify
go build -trimpath -o "$BIN/a2a-reference-go" .
go version -m "$BIN/a2a-reference-go" | awk '$1 == "dep" && $2 == "github.com/a2aproject/a2a-go/v2" && $3 == "v2.4.0" {found=1} END {exit !found}'
