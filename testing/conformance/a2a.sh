#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE `a2a` CONFORMANCE SUITE, as testing/conformance/run.sh runs it (suites.tsv). It writes
# $CONFORMANCE_OUT/verdict.json; `pass` only when all three legs held.
#
#   THE CONTROLS (always run): the official a2aproject/a2a-tck at TCK_REF against a2a-go v2.4.0 over
#       both bindings, each held to its pinned per-requirement baseline (testing/a2a-tck/baselines);
#       and the independent battery (testing/a2a-harness) against a2a-go v2.4.0 (both bindings) and
#       a2a-python 1.1.2, each held to its pinned baseline.
#   THE NEGATIVE CONTROLS: the battery's deliberately broken fake peer MUST grade red, with every
#       injected violation caught on it and absent from the honest twin; and the TCK pointed at a
#       broken relay of the scenario agent MUST report clearly more failed MUSTs than against the
#       honest agent itself.
#   THE SUBJECT: busbar built from $BUSBAR_CHECKOUT (the .busbar-ref pin) with THIS checkout's
#       plane-a2a patched in, booted by testing/a2a-subject/boot.sh, judged by the TCK (--tck) and by
#       the battery (--battery). A subject that cannot be built or booted is `fail`, never a skip.
#
# testing/a2a-supplement is busbar-authored and weaker evidence, and testing/a2a-governance is policy:
# neither is run here and neither is ever merged into these numbers.
#
# Tools: ModernCI compute has no go and no pip. go is a sha256-pinned release tarball below; every
# python dependency installs from a hash-pinned requirements file (--require-hashes) into a venv
# this script makes. Nothing is fetched unpinned.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2

: "${CONFORMANCE_SUITE:=a2a}"
: "${CONFORMANCE_OUT:?CONFORMANCE_OUT is the verdict directory}"
: "${BUSBAR_CHECKOUT:?BUSBAR_CHECKOUT is busbar at the .busbar-ref pin}"
mkdir -p "$CONFORMANCE_OUT"
CONFORMANCE_OUT="$(cd "$CONFORMANCE_OUT" && pwd)"

TCK_REF="$(sed -n '/^TCK_REF="/{s/^TCK_REF="\([0-9a-f]\{40\}\)".*/\1/p;q;}' testing/a2a-tck/run-tck.sh)"
[ -n "$TCK_REF" ] || TCK_REF="unreadable"
GO_VERSION=go1.26.10
GO_SHA_AMD64=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
GO_SHA_ARM64=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797
# python-build-standalone cpython 3.12 (the TCK needs python >= 3.11; ModernCI's python3 is older).
PY_TAG=20261026
PY_VER=3.12.16
PY_SHA_AMD64=6a79e922e50006b601f29e688407659da1c2b86ebcd4e9c7254cf234be8b89de
PY_SHA_ARM64=a945427411dc6851a1393533b74a4a1ac434321ae397f2ec69897a9b4fde032b
# github.com/a2aproject/a2a-python v1.1.2, by commit (the tag is mutable; the commit is not).
A2A_PY_SAMPLES_SHA=3e6fa6a41d64f0581202df214a0515a0b0194832

CACHE="${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools"
W="$CONFORMANCE_OUT/work"
LOGS="$CONFORMANCE_OUT/logs"
mkdir -p "$W" "$LOGS" "$CACHE"

# One place every shared tool of the repo's own scripts looks. TZ is NOT cosmetic (run-tck.sh).
export TZ="${A2A_TCK_TZ:-America/New_York}"
export A2AHT_CONTROL_BIN="$W/bin"
export A2AHT_CONTROL_SRC="$W/a2aht-src"
export A2A_TCK_WORK="$W/tck"
export A2A_SCENARIO_AGENT_WORK="$W/scenario-agent"
export TMPDIR="${TMPDIR:-/tmp}"

say() { printf 'a2a: %s\n' "$*" >&2; }

FAILED=()      # legs that did not hold, each "name: why"
LEGS=()        # every leg that ran
leg() {        # leg <name> <command...>: run it, log it, record it
  local name="$1"; shift
  local log="$LOGS/$name.log" rc=0
  say "--- $name"
  "$@" >"$log" 2>&1 || rc=$?
  LEGS+=("$name")
  if [ "$rc" -eq 0 ]; then
    say "    ok: $name"
  else
    say "    RED: $name (exit $rc); tail of $log:"
    tail -25 "$log" >&2
    FAILED+=("$name (exit $rc)")
  fi
  return 0
}

verdict() {   # verdict <status> <armed> <reason>
  python3 -I - "$CONFORMANCE_SUITE" "$1" "$2" "$3" "$TCK_REF" "$CONFORMANCE_OUT/verdict.json" <<'PY'
import json, sys
suite, status, armed, reason, tck, out = sys.argv[1:7]
v = {"suite": suite, "status": status, "armed": armed == "true",
     "standard": "Agent2Agent (A2A) protocol, specification v1.0",
     "plan": "a2aproject/a2a-tck + the independent a2aht battery; controls a2a-go v2.4.0 and "
             "a2a-python 1.1.2; subject busbar at the pin with this plane",
     "spec_version": "a2a-tck@" + tck, "reason": reason}
json.dump(v, open(out, "w"), indent=2, sort_keys=True)
PY
}

die() { say "$*"; verdict fail true "$*"; exit 1; }

# ------------------------------------------------------------------------------------------------
# tools: go (pinned tarball), a venv with the TCK's hash-pinned dependencies, one for the python
# control and the scenario agent.
# ------------------------------------------------------------------------------------------------
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

ensure_go() {
  local os arch sha dir tgz
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) return 1 ;; esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64; sha="$GO_SHA_AMD64" ;;
    aarch64|arm64) arch=arm64; sha="$GO_SHA_ARM64" ;;
    *) return 1 ;;
  esac
  # The pins above are linux release assets; a developer's mac uses the go it has.
  if [ "$os" != linux ]; then command -v go >/dev/null 2>&1; return; fi
  dir="$CACHE/$GO_VERSION-$os-$arch"
  tgz="$CACHE/$GO_VERSION.$os-$arch.tar.gz"
  if [ ! -x "$dir/go/bin/go" ]; then
    if [ ! -f "$tgz" ] || [ "$(sha256_of "$tgz")" != "$sha" ]; then
      curl -fsSL --retry 3 -o "$tgz.part" "https://go.dev/dl/$GO_VERSION.$os-$arch.tar.gz" || return 1
      [ "$(sha256_of "$tgz.part")" = "$sha" ] || { echo "go tarball sha256 mismatch" >&2; rm -f "$tgz.part"; return 1; }
      mv "$tgz.part" "$tgz"
    fi
    rm -rf "$dir"; mkdir -p "$dir" && tar -xzf "$tgz" -C "$dir" || return 1
  fi
  export PATH="$dir/go/bin:$PATH"
  export GOPATH="$W/gopath" GOCACHE="$W/gocache" GOFLAGS=-mod=mod GOTOOLCHAIN=local
  go version
}

ensure_python() {
  [ "$(uname -s)" = Linux ] || return 0
  local arch sha dir tgz
  case "$(uname -m)" in
    x86_64|amd64) arch=x86_64; sha="$PY_SHA_AMD64" ;;
    aarch64|arm64) arch=aarch64; sha="$PY_SHA_ARM64" ;;
    *) return 1 ;;
  esac
  dir="$CACHE/cpython-$PY_VER-$PY_TAG-$arch"
  tgz="$CACHE/cpython-$PY_VER-$PY_TAG-$arch.tar.gz"
  if [ ! -x "$dir/python/bin/python3" ]; then
    if [ ! -f "$tgz" ] || [ "$(sha256_of "$tgz")" != "$sha" ]; then
      curl -fsSL --retry 3 -o "$tgz.part" "https://github.com/astral-sh/python-build-standalone/releases/download/$PY_TAG/cpython-$PY_VER%2B$PY_TAG-$arch-unknown-linux-gnu-install_only.tar.gz" || return 1
      [ "$(sha256_of "$tgz.part")" = "$sha" ] || { echo "python tarball sha256 mismatch" >&2; rm -f "$tgz.part"; return 1; }
      mv "$tgz.part" "$tgz"
    fi
    rm -rf "$dir"; mkdir -p "$dir" && tar -xzf "$tgz" -C "$dir" || return 1
  fi
  export PATH="$dir/python/bin:$PATH"
  python3 --version
}

# venv_from <dir> <requirements>: a venv with exactly the hash-pinned set, or return 1.
venv_from() {
  local dir="$1" req="$2"
  [ -x "$dir/bin/python" ] && return 0
  python3 -m venv "$dir" || return 1
  "$dir/bin/python" -m pip -q install --disable-pip-version-check --no-cache-dir \
    --require-hashes --only-binary=:all: -r "$req" || { rm -rf "$dir"; return 1; }
}

provision() {
  ensure_python || return 1
  ensure_go || return 1
  # The TCK's venv is where run-tck.sh expects it; its own installer then finds it and only checks
  # that the suite's imports work.
  venv_from "$A2A_TCK_WORK/venv" "$ROOT/testing/conformance/requirements-tck.txt" || return 1
  # The scenario agent (a2a-sdk at the pin install-control.sh states).
  local pyver
  pyver="$(sed -n '/^CONTROL_PY_VERSION="/{s/^CONTROL_PY_VERSION="\([^"]*\)".*/\1/p;q;}' testing/a2a-harness/scripts/install-control.sh)"
  venv_from "$A2A_SCENARIO_AGENT_WORK/venv-$pyver" "$ROOT/testing/conformance/requirements-py.txt" || return 1
  # The battery's python control: a venv plus the sample agent at the pinned commit.
  mkdir -p "$A2AHT_CONTROL_SRC"
  venv_from "$A2AHT_CONTROL_SRC/venv" "$ROOT/testing/conformance/requirements-py.txt" || return 1
  if [ ! -d "$A2AHT_CONTROL_SRC/a2a-python/.git" ]; then
    git init -q "$A2AHT_CONTROL_SRC/a2a-python" \
      && git -C "$A2AHT_CONTROL_SRC/a2a-python" remote add origin https://github.com/a2aproject/a2a-python.git \
      && git -C "$A2AHT_CONTROL_SRC/a2a-python" fetch -q --depth 1 origin "$A2A_PY_SAMPLES_SHA" \
      && git -C "$A2AHT_CONTROL_SRC/a2a-python" -c advice.detachedHead=false checkout -q FETCH_HEAD || return 1
  fi
  [ "$(git -C "$A2AHT_CONTROL_SRC/a2a-python" rev-parse HEAD)" = "$A2A_PY_SAMPLES_SHA" ] || return 1
  # a2a-go, by `go install module@version` (verified against the Go checksum database), into the one
  # bin dir both instruments use.
  mkdir -p "$A2AHT_CONTROL_BIN"
  testing/a2a-harness/scripts/install-control.sh go
}

# ------------------------------------------------------------------------------------------------
# CONTROL legs
# ------------------------------------------------------------------------------------------------
tck_control() { testing/a2a-tck/run-tck.sh "$1"; }

battery_go() {   # battery_go <rest|jsonrpc> <baseline>
  local binding="$1" baseline="$2" extra=""
  [ "$binding" = jsonrpc ] && extra="--transport jsonrpc"
  ( cd testing/a2a-harness && mkdir -p reports \
    && python3 -m a2aht run \
         --launch "$A2AHT_CONTROL_BIN/a2a serve --echo --port 9099 --quiet $extra" --port 9099 \
         --label "control:a2a-go/$binding" --tier pre-release \
         --client-drive "$A2AHT_CONTROL_BIN/a2a send {url} hello-from-harness" \
         --known-deviations baselines/known-deviations-a2a-go.json \
         --json "reports/control-$binding.json" --allow-red
    python3 -m a2aht baseline --report "reports/control-$binding.json" --baseline "baselines/$baseline" )
}

battery_python() {
  ( cd testing/a2a-harness && mkdir -p reports
    "$A2AHT_CONTROL_SRC/venv/bin/python" "$A2AHT_CONTROL_SRC/a2a-python/samples/hello_world_agent.py" \
      > "$LOGS/a2a-python-agent.log" 2>&1 &
    local pid=$! up=0
    for _ in $(seq 1 60); do
      curl -fsS -m 2 -o /dev/null http://127.0.0.1:41241/.well-known/agent-card.json && { up=1; break; }
      sleep 1
    done
    if [ "$up" != 1 ]; then echo "the a2a-python control never served its card"; cat "$LOGS/a2a-python-agent.log"; kill "$pid" 2>/dev/null; exit 1; fi
    python3 -m a2aht run --endpoint http://127.0.0.1:41241 --label "control:a2a-python" \
      --tier pre-release --known-deviations baselines/known-deviations-a2a-python.json \
      --role server --allow-undriven-bindings GRPC --json reports/control-python.json --allow-red
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    python3 -m a2aht baseline --report reports/control-python.json --baseline baselines/control-a2a-python.json )
}

# ------------------------------------------------------------------------------------------------
# NEGATIVE controls: a broken peer MUST grade red. Both instruments are pointed at the battery's own
# fake peer (a2aht/fakes.py), once broken and once honest.
# ------------------------------------------------------------------------------------------------
await_card() {  # await_card <port> <what>
  local waited=0
  until curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$1/.well-known/agent-card.json"; do
    waited=$((waited + 1))
    [ "$waited" -lt 30 ] || { echo "the $2 peer never served a card on $1"; return 1; }
    sleep 1
  done
}

negative_battery() {
  ( cd testing/a2a-harness && mkdir -p reports
    python3 -m a2aht fake-peer --port 9402 --broken > "$LOGS/broken-peer.log" 2>&1 & local broken=$!
    python3 -m a2aht fake-peer --port 9403 > "$LOGS/honest-peer.log" 2>&1 & local honest=$!
    trap 'kill $broken $honest 2>/dev/null || true' EXIT
    await_card 9402 broken || exit 1
    await_card 9403 honest || exit 1
    local brc=0 hrc=0
    python3 -m a2aht run --endpoint http://127.0.0.1:9402 --label negative-control --tier pull-request \
      --role server --json reports/negative-control.json > "$LOGS/negative-run.txt" 2>&1 || brc=$?
    python3 -m a2aht run --endpoint http://127.0.0.1:9403 --label honest-control --tier pull-request \
      --role server --json reports/honest-control.json > "$LOGS/honest-run.txt" 2>&1 || hrc=$?
    echo "battery vs broken peer: exit $brc; vs honest peer: exit $hrc"
    [ "$brc" = 1 ] || { echo "the battery did not grade the broken peer red (exit $brc; want 1)"; exit 1; }
    [ "$hrc" != 3 ] || { echo "the battery never reached the honest peer"; exit 1; }
    python3 -I - <<'PY'
import json, sys
PAIRS = {
    "card.required_fields": "the REQUIRED `version` is absent",
    "card.protocol_version_no_patch": "protocolVersion carries a patch",
    "core.task_state_is_defined_enum": "emits an undefined TaskState",
    "adv.concurrent_interleaved_tasks": "one task id reused for every task",
    "core.stream_opens_with_task_or_message": "streams an event for a task never created",
}
def outcomes(path):
    return {r["id"]: r["outcome"] for r in json.load(open(path))["results"]}
broken = outcomes("reports/negative-control.json")
honest = outcomes("reports/honest-control.json")
bad = 0
for tid, why in sorted(PAIRS.items()):
    b, h = broken.get(tid, "ABSENT"), honest.get(tid, "ABSENT")
    ok = b == "FAIL" and h == "PASS"
    print("%-4s %-42s broken=%-6s honest=%-6s %s" % ("ok" if ok else "BAD", tid, b, h, why))
    bad += not ok
sys.exit(1 if bad else 0)
PY
  )
}

# The TCK against a broken peer: the honest scenario agent, and the same agent behind a relay that
# corrupts its answers (testing/a2a-tck/broken-agent). The same suite, the same verb, the same way;
# the broken peer MUST report clearly more failed MUSTs than the honest one.
tck_must_counts() {   # tck_must_counts <report.json>  ->  "<passed> <failed>"
  python3 -I - "$1" <<'PY'
import json, sys
per = json.load(open(sys.argv[1]))["per_requirement"]
must = [v for v in per.values() if v.get("level") == "MUST"]
print(sum(v["status"] == "PASS" for v in must), sum(v["status"] == "FAIL" for v in must))
PY
}

negative_tck() {
  local honest_out="$W/tck-honest" broken_out="$W/tck-broken" hp=9711 up=9712 bp=9713
  mkdir -p "$honest_out" "$broken_out"
  local pids=()
  trap 'kill "${pids[@]}" 2>/dev/null || true' RETURN
  testing/a2a-tck/scenario-agent/serve.sh "$hp" --public-url "http://127.0.0.1:$hp/" > "$LOGS/honest-scenario.log" 2>&1 & pids+=($!)
  testing/a2a-tck/scenario-agent/serve.sh "$up" --public-url "http://127.0.0.1:$bp/" > "$LOGS/broken-scenario.log" 2>&1 & pids+=($!)
  python3 testing/a2a-tck/broken-agent/broken_agent.py "$bp" "$up" > "$LOGS/broken-relay.log" 2>&1 & pids+=($!)
  local port
  for port in $hp $bp; do
    local waited=0
    until curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$port/.well-known/agent-card.json"; do
      waited=$((waited + 1)); [ "$waited" -lt 120 ] || { echo "the peer on $port never served a card"; return 1; }
      sleep 1
    done
  done
  A2A_TCK_OUT="$honest_out" BUSBAR_A2A_ENDPOINT="http://127.0.0.1:$hp" testing/a2a-tck/run-tck.sh subject || return 1
  A2A_TCK_OUT="$broken_out" BUSBAR_A2A_ENDPOINT="http://127.0.0.1:$bp" testing/a2a-tck/run-tck.sh subject || return 1
  [ -f "$honest_out/subject.json" ] && [ -f "$broken_out/subject.json" ] \
    || { echo "a negative-control run wrote no report"; return 1; }
  local hpass hfail bpass bfail
  read -r hpass hfail <<<"$(tck_must_counts "$honest_out/subject.json")"
  read -r bpass bfail <<<"$(tck_must_counts "$broken_out/subject.json")"
  echo "MUST honest scenario agent: $hpass pass, $hfail fail; broken relay: $bpass pass, $bfail fail"
  [ "$bfail" -ge $((hfail + 10)) ] && [ "$bpass" -lt "$hpass" ] \
    || { echo "the TCK did not grade the broken peer clearly worse than the honest one"; return 1; }
}

# ------------------------------------------------------------------------------------------------
# SUBJECT: busbar at the pin, this plane patched in, built here, booted by the repo's own boot.sh.
# ------------------------------------------------------------------------------------------------
build_subject() {
  # The package is busbar's default distribution (dist/default), staged by compose.sh with its rows
  # pointed at this plane's door and declares; the root crate (`-p busbar`) is core with no plane
  # linked and refuses the `agents:` section at boot. compose-selftest.sh holds the composition
  # first. The plane busbar links is a git dependency at a rev; this checkout's plane-a2a replaces
  # it by a run-time `--config` patch (nothing committed). busbar's own [patch] already routes the
  # busbar crates the plane names to BUSBAR_CHECKOUT.
  local stage="$W/subject-src" manifest
  bash testing/a2a-subject/compose-selftest.sh "$BUSBAR_CHECKOUT" "$stage" || return 1
  manifest="$(bash testing/a2a-subject/compose.sh "$BUSBAR_CHECKOUT" "$ROOT/plane-a2a" "$stage")" || return 1
  cargo build --manifest-path "$manifest" --bin busbar \
      --config "patch.\"https://github.com/GetBusbar/busbar-plane-a2a\".busbar-plane-a2a.path=\"$ROOT/plane-a2a\"" \
    || return 1
  SUBJECT_BIN="${CARGO_TARGET_DIR:-$(dirname "$manifest")/target}/debug/busbar"
  [ -x "$SUBJECT_BIN" ] || return 1
}

subject_tck()     { A2A_SUBJECT_BUSBAR_BIN="$SUBJECT_BIN" A2A_SUBJECT_WORKDIR="$W/subject-tck" testing/a2a-subject/boot.sh --tck; }
subject_battery() { A2A_SUBJECT_BUSBAR_BIN="$SUBJECT_BIN" A2A_SUBJECT_WORKDIR="$W/subject-battery" testing/a2a-subject/boot.sh --battery; }

# ------------------------------------------------------------------------------------------------
say "tck pin $TCK_REF; busbar pin ${BUSBAR_PIN:-?}; checkout $BUSBAR_CHECKOUT"
provision > "$LOGS/provision.log" 2>&1 || { tail -30 "$LOGS/provision.log" >&2; die "the pinned tools (go $GO_VERSION, hash-pinned python venvs, a2a-go) could not be provisioned"; }

leg control-tck-http-json   tck_control control-http-json
leg control-tck-jsonrpc     tck_control control-jsonrpc
leg control-battery-go-rest battery_go rest control-a2a-go-rest.json
leg control-battery-go-jsonrpc battery_go jsonrpc control-a2a-go-jsonrpc.json
leg control-battery-python  battery_python
leg negative-battery        negative_battery
leg negative-tck            negative_tck

SUBJECT_BIN=""
leg subject-build           build_subject
if [ -n "$SUBJECT_BIN" ] && [ -x "$SUBJECT_BIN" ]; then
  leg subject-tck           subject_tck
  leg subject-battery       subject_battery
else
  FAILED+=("subject: busbar with this plane could not be built, so the subject legs could not run")
fi

if [ "${#FAILED[@]}" -eq 0 ]; then
  say "all ${#LEGS[@]} legs held"
  verdict pass true "controls held their pinned baselines, the broken peers graded red, and busbar at the pin with this plane passed the TCK and the battery"
  exit 0
fi
reason="$(printf '%s; ' "${FAILED[@]}")"
say "RED: $reason"
verdict fail true "${reason%; }"
exit 1
