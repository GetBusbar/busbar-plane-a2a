#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Run the OFFICIAL A2A Technology Compatibility Kit against one target.
#
# WHY THIS AND NOT A HAND-WRITTEN gRPC DRIVER. `a2aproject/a2a-tck` already covers all three
# transports the specification defines -- gRPC, JSON-RPC and HTTP+JSON -- across 36 test modules,
# and it is maintained by the people who publish the specification. Writing our own gRPC driver
# would be several days spent duplicating a suite somebody else keeps current. The independent
# battery in ../a2a-harness is a DIFFERENT instrument and both are wired: the battery is a
# clean-room reading of the spec with adversarial and hostile-peer coverage the TCK does not have,
# and the TCK is the publisher's own oracle with transport coverage the battery does not have.
# Neither substitutes for the other.
#
# WHAT IS PINNED, AND WHY EACH PIN IS LOAD-BEARING
#   TCK_REF        the suite defines what "conformant" means here; a silent upgrade silently
#                  changes the answer.
#   CONTROL_GO_VERSION  the reference implementation the control legs judge; it must match
#                  ../a2a-harness/scripts/install-control.sh so both instruments talk about the
#                  same peer, and `install_control` refuses to run when the two disagree or when
#                  the installed binary is not the pinned module version.
#   TZ             NOT cosmetic. a2a-go v2.4.0 serialises task timestamps in the HOST's local
#                  zone rather than UTC, which is a real spec violation (SPEC 5.6.1) that is
#                  INVISIBLE on a UTC host -- and CI runners are UTC. Running these legs in UTC
#                  would silently retire a real finding and quietly weaken the suite. So the zone
#                  is fixed to a non-UTC one, and `tz-is-load-bearing.sh` proves the choice still
#                  changes the result rather than sitting there as decoration.
#
# LICENCE: see LICENSING.md next to this file. The TCK's terms are AMBIGUOUS in its own tree, so
# nothing from it is vendored; it is fetched at a pinned commit at run time and used as a tool.
#
# USAGE
#   run-tck.sh control-http-json     pinned control, HTTP+JSON binding; suite verdict reported
#   run-tck.sh control-jsonrpc       pinned control, JSON-RPC binding; suite verdict reported
#   run-tck.sh control-scenario      the agent the SUBJECT leg fronts, judged directly with no
#                                    busbar in the path. Reports the same peer directly; no
#                                    numerical ceiling or baseline comparison is imposed.
#   run-tck.sh subject               the endpoint in BUSBAR_A2A_ENDPOINT; reported, never pinned
#   run-tck.sh prepare               fetch + install the pinned suite only, and print the paths another
#                                    instrument can borrow (used by testing/a2a-supplement)
set -euo pipefail
umask 077

TCK_REF="5996b79f9cefa6fc390980e383e358a66fb9e49e"   # a2aproject/a2a-tck, 2026-06-29
CONTROL_GO_VERSION="v2.4.0"                          # github.com/a2aproject/a2a-go
export TZ="${A2A_TCK_TZ:-America/New_York}"

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/../a2a-harness/scripts/process-fixture.sh"
WORK="${A2A_TCK_WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/busbar-a2a/tck}"
TCK_DIR="$WORK/a2a-tck"
VENV="$WORK/venv"
BIN_DIR="${A2AHT_CONTROL_BIN:-$WORK/bin}"
OUT="${A2A_TCK_OUT:-$WORK/out}"
mkdir -p "$WORK" "$BIN_DIR" "$OUT" 2>/dev/null || {
  echo "could not create the work directories under $WORK, $BIN_DIR and $OUT -- refusing to run" >&2
  exit 2
}

say () { printf '\n=== %s ===\n' "$*"; }

# discard <dir> <what>: remove a half-made <what> so the next run builds it again instead of
# trusting it, and say whether it is gone (a refusal names both outcomes; it never assumes one).
discard () {
  if [ ! -e "$1" ]; then
    echo "nothing was left at $1"
    return 0
  fi
  rm -rf "$1" 2>/dev/null || true
  if [ -e "$1" ]; then
    echo "the half-made $2 at $1 could not be removed; remove it by hand"
  else
    echo "the half-made $2 at $1 was removed"
  fi
}

# read_pin <file> <NAME> -> prints the value of the first NAME="..." line. Refuses (exit 2) when
# the file is not there or cannot be read; prints nothing when it holds no such line. One sed pass
# that quits on the first match, so no pipe can fail under pipefail.
read_pin () {
  local file="$1" name="$2" text=""
  if [ ! -e "$file" ]; then
    echo "the pin file $file is not there -- refusing to run" >&2
    exit 2
  fi
  text="$(cat "$file" 2>/dev/null)" \
    || { echo "the pin file $file cannot be read -- refusing to run" >&2; exit 2; }
  sed -n "/^$name=\"/{s/^$name=\"\([^\"]*\)\".*/\1/p;q;}" <<< "$text"
}

fetch_tck () {
  if [ ! -d "$TCK_DIR/.git" ]; then
    say "fetching a2a-tck at pinned ${TCK_REF}"
    # A half-made checkout is removed, so the next run fetches again instead of trusting it.
    git init -q "$TCK_DIR" \
      && git -C "$TCK_DIR" remote add origin https://github.com/a2aproject/a2a-tck.git \
      && git -C "$TCK_DIR" fetch -q --depth 1 origin "$TCK_REF" \
      && git -C "$TCK_DIR" checkout -q FETCH_HEAD \
      || {
        note="$(discard "$TCK_DIR" checkout)"
        echo "could not fetch a2a-tck at $TCK_REF into $TCK_DIR; $note -- refusing to run" >&2
        exit 2
      }
  fi
  got="$(git -C "$TCK_DIR" rev-parse HEAD 2>/dev/null)" || got="no commit"
  # A pin that is not verified after checkout is a wish. A cached working copy from an earlier,
  # different pin would otherwise be used silently to judge a different suite.
  if [ "$got" != "$TCK_REF" ]; then
    echo "a2a-tck checkout is $got, pin is $TCK_REF -- refusing to run" >&2
    exit 2
  fi
  echo "a2a-tck @ $got"
}

install_tck () {
  if [ ! -x "$VENV/bin/python" ]; then
    say "installing a2a-tck into $VENV"
    python3 -m venv "$VENV" \
      && "$VENV/bin/pip" -q install --require-hashes --only-binary=:all: -r "$HERE/../conformance/requirements-tck.txt" \
      || {
        note="$(discard "$VENV" virtualenv)"
        echo "could not install a2a-tck into $VENV; $note -- refusing to run" >&2
        exit 2
      }
  fi
  "$VENV/bin/python" -c 'import pytest, grpc, jsonschema' \
    || { echo "a2a-tck dependencies did not import" >&2; exit 2; }
}

install_control () {
  # ONE PIN FOR ONE PEER. The harness installs the same control into the same cache; a version
  # spelled here and there that has drifted is two instruments describing different peers, so the
  # disagreement -- or a harness file that no longer states its pin -- refuses the run.
  local harness_pin_file="$HERE/../a2a-harness/scripts/install-control.sh" harness_pin=""
  harness_pin="$(read_pin "$harness_pin_file" CONTROL_GO_VERSION)" || exit 2
  if [ -z "$harness_pin" ]; then
    echo "no CONTROL_GO_VERSION pin in $harness_pin_file -- refusing to run" >&2
    exit 2
  fi
  if [ "$harness_pin" != "$CONTROL_GO_VERSION" ]; then
    echo "a2a-go pin disagreement: run-tck.sh pins $CONTROL_GO_VERSION, testing/a2a-harness pins \
$harness_pin -- reconcile them before running" >&2
    exit 2
  fi
  if [ ! -x "$BIN_DIR/a2a" ]; then
    say "installing control a2a-go ${CONTROL_GO_VERSION}"
    GOBIN="$BIN_DIR" go install \
      "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}" \
      || { echo "could not install control a2a-go ${CONTROL_GO_VERSION} into $BIN_DIR -- refusing to run" >&2; exit 2; }
  fi
  # A pin that is not verified after install is a wish. BIN_DIR is a persistent cache in the wired
  # recorder, so a binary another pin left there would otherwise be judged -- and, under
  # reported -- as a2a-go ${CONTROL_GO_VERSION}. The module version is read out
  # of the binary's own build information.
  local got=""
  got="$(go version -m "$BIN_DIR/a2a" 2>/dev/null \
    | awk '$1 == "mod" && $2 == "github.com/a2aproject/a2a-go/v2" { print $3 }')" || true
  if [ "$got" != "$CONTROL_GO_VERSION" ]; then
    echo "control binary $BIN_DIR/a2a is a2a-go '${got:-unreadable}', pin is \
$CONTROL_GO_VERSION -- refusing to run" >&2
    exit 2
  fi
  "$BIN_DIR/a2a" --help >/dev/null 2>&1 \
    || { echo "control binary $BIN_DIR/a2a does not run (\`a2a --help\` failed) -- refusing to run" >&2; exit 2; }
}

# run_tck <base-url> <report-name>  -> sets RUN_STARTED
run_tck () {
  local url="$1" name="$2" rc=0
  # The suite's own report directory from an earlier run goes first, for the same reason as the
  # copied report below: what is found there afterwards must be this run's.
  rm -rf "$TCK_DIR/reports" 2>/dev/null || true
  if [ -e "$TCK_DIR/reports" ]; then
    echo "could not remove the suite's previous reports directory $TCK_DIR/reports -- refusing to run" >&2
    exit 2
  fi
  # A REPORT AN EARLIER RUN COPIED HERE IS NOT THIS RUN'S EVIDENCE. OUT sits under WORK, which the
  # wired recorder keeps in a persistent cache; left in place, the last good run's report would be
  # read as the report of a run that crashed before writing one. Remove it before
  # the suite starts; require_report also refuses evidence older than RUN_STARTED.
  rm -f "$OUT/$name.json" 2>/dev/null || true
  if [ -e "$OUT/$name.json" ]; then
    echo "could not remove the previous run's report $OUT/$name.json -- refusing to run" >&2
    exit 2
  fi
  RUN_STARTED="$(date +%s)"
  ( cd "$TCK_DIR" && "$VENV/bin/python" run_tck.py --sut-host "$url" ) \
    > "$OUT/$name.txt" 2>&1 || rc=$?
  echo "  (a2a-tck exit $rc; the suite's protocol verdict is preserved)"
  if [ -f "$TCK_DIR/reports/compatibility.json" ]; then
    cp "$TCK_DIR/reports/compatibility.json" "$OUT/$name.json" 2>/dev/null \
      || { echo "could not copy the suite's report to $OUT/$name.json -- refusing to run" >&2; exit 2; }
  fi
  # Keep the requirement IDs and assertion details below FAILED REQUIREMENTS;
  # ending at that heading discards the only actionable failure evidence.
  sed -n '/A2A TCK Compatibility Report/,$p' "$OUT/$name.txt" || true
  require_report "$OUT/$name.json" || return 2
  return "$rc"
}

require_report () {
  python3 - "$1" "$RUN_STARTED" <<'PY'
import json, os, sys
path, started = sys.argv[1:]
try:
    if os.path.getmtime(path) < int(started):
        raise ValueError("compatibility report predates this run")
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    per = report.get("per_requirement")
    if not isinstance(per, dict) or not per:
        raise ValueError("compatibility report has no requirement results")
    if any(not isinstance(item, dict) or item.get("status") not in
           {"PASS", "FAIL", "SKIPPED", "NOT TESTED"} for item in per.values()):
        raise ValueError("compatibility report has a malformed requirement verdict")
    if not any(item["status"] in {"PASS", "FAIL"} for item in per.values()):
        raise ValueError("compatibility report records no executed requirement")
except (OSError, ValueError) as error:
    print("the TCK run produced no usable fresh report: %s" % error, file=sys.stderr)
    sys.exit(2)
PY
}

# await_card <port> <tries> <interval> <what> <log>
#
# Waits for the peer started as CONTROL_PID to serve its card. A peer that has already exited will
# never serve it, so that ends the wait at once instead of after every try; either way the run is
# refused with the peer's own log.
await_card () {
  local port="$1" tries="$2" interval="$3" what="$4" log="$5"
  fixture_await_card "$CONTROL_PID" "$port" "$tries" "$interval" && return 0
  cat "$log" >&2 || true
  stop_control
  echo "$what did not come up on port $port -- refusing to run" >&2
  exit 2
}

# serve_control <port> <transport>  -> exports CONTROL_PID
serve_control () {
  local port="$1" transport="$2"
  "$HERE/../a2a-reference/go/serve.sh" "$port" "$transport" \
    > "$OUT/control-$transport.log" 2>&1 &
  CONTROL_PID=$!
  trap 'stop_control || exit 2' EXIT
  fixture_exit_on_signal
  fixture_track_pid "$CONTROL_PID"
  await_card "$port" 50 0.2 control "$OUT/control-$transport.log"
}

# stop_control: kill the peer AND wait for it, so its port is free when this returns. A peer that
# ignores the polite signal for five seconds gets SIGKILL, so the wait is bounded.
stop_control () { fixture_stop "${CONTROL_PID:-}" || return 1; CONTROL_PID=""; }

# serve_scenario_agent <port>  -> exports CONTROL_PID
#
# The agent the SUBJECT leg fronts, served here with NO busbar in the path. That is the whole point
# of this leg: `testing/a2a-subject/boot.sh` measures busbar-fronting-this-agent, and a number has
# no meaning without the number the same suite gives the same agent alone. The difference between
# the two is busbar's contribution, in both directions, and nothing else.
serve_scenario_agent () {
  local port="$1"
  "$HERE/scenario-agent/serve.sh" "$port" > "$OUT/control-scenario.log" 2>&1 &
  CONTROL_PID=$!
  trap 'stop_control || exit 2' EXIT
  fixture_exit_on_signal
  fixture_track_pid "$CONTROL_PID"
  # A first run installs a virtualenv, so this waits longer than the binary controls do.
  await_card "$port" 300 0.5 "the scenario agent" "$OUT/control-scenario.log"
}

# Repair an older cached environment using the same hash-pinned dependency set.
install_crypto () {
  "$VENV/bin/python" -c 'import cryptography' 2>/dev/null \
    || "$VENV/bin/pip" -q install --require-hashes --only-binary=:all: -r "$HERE/../conformance/requirements-tck.txt" \
    || { echo "could not install cryptography into $VENV; the card-signing checks cannot run" >&2; exit 2; }
}

control_leg () {          # control_leg <transport> <port> <name>
  local transport="$1" port="$2" name="$3"
  fetch_tck; install_tck; install_control
  "$HERE/../a2a-reference/go/build.sh"
  say "control: declared scenario fixture using a2a-go ${CONTROL_GO_VERSION} / ${transport} (TZ=$TZ)"
  serve_control "$port" "$transport"
  trap 'stop_control || exit 2' EXIT
  run_tck "http://127.0.0.1:$port" "$name"
  stop_control; trap - EXIT
}

case "${1:-}" in
  control-http-json) control_leg http_json 9701 control-a2a-go-http-json ;;
  control-jsonrpc)   control_leg jsonrpc   9702 control-a2a-go-jsonrpc ;;

  # The same suite and scenario agent the subject leg fronts, judged directly.
  # Preserve its actual suite verdict and report without a numeric ceiling.
  #
  control-scenario)
    fetch_tck; install_tck
    say "control: TCK scenario agent / jsonrpc, direct (TZ=$TZ)"
    serve_scenario_agent 9703
    trap 'stop_control || exit 2' EXIT
    run_tck "http://127.0.0.1:9703" control-scenario-agent
    stop_control; trap - EXIT
    ;;

  subject)
    : "${BUSBAR_A2A_ENDPOINT:?run-tck.sh subject needs BUSBAR_A2A_ENDPOINT}"
    fetch_tck; install_tck
    say "subject: $BUSBAR_A2A_ENDPOINT"
    run_tck "$BUSBAR_A2A_ENDPOINT" subject
    ;;

  # PREPARE ONLY: fetch the pinned suite, build its virtualenv, and print the two paths another
  # instrument needs to borrow them. It exists so that `testing/a2a-supplement` can speak gRPC over
  # the SPECIFICATION'S OWN generated stubs and validate against the same pinned artefacts, without
  # a second copy of the pin, a second venv, or a hand-rolled protobuf encoder. One pin, verified in
  # one place, used by both instruments.
  prepare)
    fetch_tck; install_tck
    # `cryptography` is included in the hash-pinned requirements. The supplementary
    # suite verifies agent-card JWS signatures, which needs asymmetric crypto, and the pinned TCK
    # does not depend on it. It is added to the WORK virtualenv, never to the pinned checkout --
    # `fetch_tck` still verifies the commit byte-for-byte and nothing in `$TCK_DIR` is touched.
    #
    # AND IT IS FATAL IF IT DOES NOT INSTALL. The alternative -- letting the signing checks report
    # "could not verify" -- is a suite that silently stops checking signatures the day a wheel
    # stops building. An unverified signature is never reported as a valid one, so the only honest
    # options are "verified" and "the run failed".
    install_crypto
    echo "A2A_TCK_DIR=$TCK_DIR"
    echo "A2A_TCK_PYTHON=$VENV/bin/python"
    ;;

  *) sed -n '/^# USAGE/,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
