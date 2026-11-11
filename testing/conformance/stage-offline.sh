#!/usr/bin/env bash
# Trusted public-only collector, run on Linux OUTSIDE the candidate sandbox.
# Usage: stage-offline.sh <new bundle directory> <empty scratch directory>
# The result is admitted as a2a-tools and mounted at /opt/busbar-conformance/a2a-tools.
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'stage-offline.sh requires Linux' >&2; exit 2; }
bundle="${1:?new output bundle directory required}"
scratch="${2:?empty scratch directory required}"
[[ "$bundle" = /* && "$scratch" = /* ]] || { echo 'use absolute output and scratch paths' >&2; exit 2; }
[ ! -e "$bundle" ] && [ ! -e "$scratch" ] || { echo 'output and scratch must be absent' >&2; exit 2; }
mkdir -p "$scratch"
scratch="$(cd "$scratch" && pwd)"
export CONFORMANCE_OUT="$scratch/output" BUSBAR_CHECKOUT="$scratch/unused-host"
export MODERNCI_CACHE_DIR="${A2A_STAGE_CACHE:-$scratch/cache}" TMPDIR="$scratch/tmp"
export A2A_CONFORMANCE_LIBRARY_ONLY=1
unset BUSBAR_CONFORMANCE_INPUTS
mkdir -p "$TMPDIR"
source "$(dirname "${BASH_SOURCE[0]}")/a2a.sh"
# Staging must collect the exact release asset even when the builder has Node already.
load_tool_helpers() { source "$ROOT/testing/conformance/tools.sh"; }
load_tool_helpers
node_plat="$(_ct_plat)"
node_sha="$(sed -n "s/^ *$node_plat) *sha=\\([0-9a-f]*\\).*$/\\1/p" "$ROOT/testing/conformance/tools.sh")"
[ "${#node_sha}" = 64 ]
# The version is defined by the sourced canonical tools.sh.
# shellcheck disable=SC2154
node_dir="$CACHE/node-$_ct_node_ver-$node_plat"
node_archive="$node_dir.tar.gz"
_ct_fetch "https://nodejs.org/dist/$_ct_node_ver/node-$_ct_node_ver-$node_plat.tar.gz" "$node_sha" "$node_archive"
mkdir -p "$node_dir"
# Only Node is used by the judges; npm/corepack and their install surfaces are unnecessary.
tar -xzf "$node_archive" --strip-components=1 -C "$node_dir" "node-$_ct_node_ver-$node_plat/bin/node" "node-$_ct_node_ver-$node_plat/LICENSE"
_ct_integrity seal "$node_dir" bin/node
export PATH="$node_dir/bin:$PATH"
ensure_python
ensure_go
# --copies prevents venv interpreter links to a staging path outside the venv.
venv_from() {
  python3 -m venv --copies "$1"
  "$1/bin/python" -m pip -q install --disable-pip-version-check --no-cache-dir \
    --require-hashes --only-binary=:all: -r "$2"
}
provision
testing/a2a-tck/run-tck.sh prepare
testing/a2a-reference/go/build.sh
python3 -I "$ROOT/testing/conformance/offline_bundle.py" pack "$bundle" "$ROOT" "$W" "$CACHE"
echo "Public A2A tools staged at $bundle; controller admission must hash every file and executable mode."
