#!/usr/bin/env bash
# Activate the public tools admitted and mounted read-only by the native controller.
# No download, package installation, or fallback is permitted in the candidate.
_a2a_bundle=/opt/busbar-conformance/a2a-tools
python3 -I "$ROOT/testing/conformance/offline_bundle.py" check "$_a2a_bundle" "$ROOT" || return 1
export PATH="$_a2a_bundle/python/bin:$_a2a_bundle/go/bin:$_a2a_bundle/node/bin:$PATH"
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
export GOPATH="$W/gopath" GOMODCACHE="$_a2a_bundle/gomodcache" GOCACHE="$W/gocache"
export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 CARGO_NET_OFFLINE=true
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$A2AHT_CONTROL_BIN" "$A2AHT_CONTROL_SRC" "$A2A_TCK_WORK" "$A2A_SCENARIO_AGENT_WORK" || return 1
cp "$_a2a_bundle/bin/a2a" "$A2AHT_CONTROL_BIN/a2a" || return 1
# The official TCK writes its reports within its checkout; only its work copy is writable.
cp -R "$_a2a_bundle/a2a-tck" "$A2A_TCK_WORK/" || return 1
ln -s "$_a2a_bundle/venv-tck" "$A2A_TCK_WORK/venv" || return 1
ln -s "$_a2a_bundle/venv-python" "$A2AHT_CONTROL_SRC/venv" || return 1
_a2a_reqhash="$(shasum -a 256 "$ROOT/testing/conformance/requirements-py.txt" | awk '{print $1}')"
ln -s "$_a2a_bundle/venv-python" "$A2A_SCENARIO_AGENT_WORK/venv-1.1.2-$_a2a_reqhash" || return 1
"$A2A_TCK_WORK/venv/bin/python" -c 'import pytest, grpc, jsonschema' || return 1
"$A2AHT_CONTROL_SRC/venv/bin/python" -c 'import a2a; from importlib.metadata import version; assert version("a2a-sdk") == "1.1.2"' || return 1
go version
