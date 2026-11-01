#!/usr/bin/env bash
# Install the pinned A2A control implementations.
#
# The versions here are PINNED ON PURPOSE. The control defines what
# "conformant" means for this harness, so a silent upgrade would silently
# change the answer. Bump them deliberately, re-record the baselines, and read
# the diff.
set -euo pipefail

CONTROL_GO_VERSION="v2.4.0"       # github.com/a2aproject/a2a-go
CONTROL_PY_VERSION="1.1.2"        # PyPI a2a-sdk
CONTROL_PY_SHA="3e6fa6a41d64f0581202df214a0515a0b0194832" # same sample commit as conformance/a2a.sh
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
umask 077

BIN_DIR="${A2AHT_CONTROL_BIN:-$HOME/.a2aht/bin}"
SRC_DIR="${A2AHT_CONTROL_SRC:-$HOME/.a2aht/src}"
mkdir -p "$BIN_DIR" "$SRC_DIR"

what="${1:-all}"

install_go() {
  echo "installing control: a2a-go ${CONTROL_GO_VERSION}"
  GOBIN="$BIN_DIR" go install \
    "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}"
  "$BIN_DIR/a2a" --help >/dev/null
  echo "  installed: $BIN_DIR/a2a"
}

install_py() {
  echo "installing control: a2a-python ${CONTROL_PY_VERSION}"
  python3 -m venv "$SRC_DIR/venv"
  "$SRC_DIR/venv/bin/pip" install -q --require-hashes --only-binary=:all: \
    -r "$HERE/../../conformance/requirements-py.txt"
  if [ ! -d "$SRC_DIR/a2a-python/.git" ]; then
    git init -q "$SRC_DIR/a2a-python"
    git -C "$SRC_DIR/a2a-python" remote add origin https://github.com/a2aproject/a2a-python.git
    git -C "$SRC_DIR/a2a-python" fetch -q --depth 1 origin "$CONTROL_PY_SHA"
    git -C "$SRC_DIR/a2a-python" -c advice.detachedHead=false checkout -q FETCH_HEAD
  fi
  [ "$(git -C "$SRC_DIR/a2a-python" rev-parse HEAD)" = "$CONTROL_PY_SHA" ] \
    || { echo "cached python samples do not match the pinned commit" >&2; return 1; }
  echo "  installed: $SRC_DIR/venv, samples at $SRC_DIR/a2a-python/samples"
}

case "$what" in
  go) install_go ;;
  python) install_py ;;
  all) install_go; install_py ;;
  *) echo "usage: $0 [go|python|all]" >&2; exit 2 ;;
esac

echo
echo "control versions pinned by this script:"
echo "  a2a-go      ${CONTROL_GO_VERSION}"
echo "  a2a-sdk     ${CONTROL_PY_VERSION}"
