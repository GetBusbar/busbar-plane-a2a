#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-class-price` -- H2 (BUSBAR-1.6.0.md THE DESIGN, §1 step 6, METER) for the
# A2A plane, and the PRICING half of that step rather than the posting half. h2-meter-row.sh proves
# ONE served call settles to ONE row carrying the flat fee (#44). This leg asks the question that
# one cannot: what did the call MEASURE, and what does the card charge for it (#71 -- "a plane's
# whole money obligation is to emit ONE fact per unit: raw counts keyed by plane-declared class
# strings ... the MONEY VIEW computes Σ count × rate").
#
# THE CLASS IS NOT A CHOICE THIS SCRIPT MAKES. This plane declares exactly ONE meter class and names
# it in a constant: `bytes`, family `byte`, direction `Response`, `default_divisor: 1`
# (`plane-a2a/src/statement.rs` `BILLABLE_CLASSES`). Divisor one is load-bearing for the expected value:
# "a byte is a byte: the class's own quantity is the quantity, so nothing is divided", so there is no
# per-N-units term and therefore no rounding to argue about (#44). The expected price of one served
# `message/send` is exactly
#
#     price = bytes_count × rate(bytes)   [+ the flat per-request fee, #44]
#
# and `bytes_count` is the length of the answer the plane read back -- direction `Response`, which
# the declaration states and explains at length. The mock agent answers every call with a JSON task
# document of several hundred bytes, so `bytes_count > 0` is not an estimate: an exchange that moved
# no bytes did not happen.
#
# THREE THINGS MUST HOLD FOR THAT LINE TO MEAN ANYTHING, and this leg asks all three separately so a
# red says WHICH one fell:
#
#   (1) THE CARD MUST BE ABLE TO NAME THE CLASS. A billing-ON deployment of a plane that declares
#       `bytes` must be able to price `bytes`; if it cannot, `rate(bytes)` is not a number the
#       operator can set and the product Σ count × rate is unreachable for every operator, forever.
#   (2) THE PLANE MUST REPORT A COUNT. #71 gives the plane exactly one obligation and this is it:
#       emit the raw count under the declared class. A count of zero for an exchange that moved
#       bytes is not a price of zero, it is a MEASUREMENT THAT DID NOT HAPPEN.
#   (3) THE PRICE MUST BE THE PRODUCT. Given (1) and (2), the money surface must read
#       count × rate + fee and not the fee alone.
#
# Boot applies a nonzero rate before the call. The row must show one request and
# exactly its measured bytes times that rate plus the configured per-request fee.
# This retained scenario is not called by testing/conformance/a2a.sh; its legacy
# fixture and token-minter dependencies must exist before it can be run.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-class-price.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"
H2_RATE_CARD_YAML='  rate_card:
    agent:probe: { units: { bytes: 2 } }'

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

read -r call_status _ <<<"$(h2_call "$bound" "price")"
[ "$call_status" = "200" ] || { failures=$((failures+1)); detail="${detail}call_status=${call_status}(want 200); "; }
# The metering write is write-behind (`advanced.usage_flush_interval_ms`, 100ms by default), so the
# read waits one flush cadence with margin rather than racing it.
sleep 2

# ── THE CONTROL: billing is ON and the row is there ───────────────────────────────────────────────
row_requests="$(h2_meter_row_field "agent:probe" "a2a" requests)"
[ "$row_requests" = "1" ] || { failures=$((failures+1)); detail="${detail}metering row for (agent:probe, a2a) reports requests=${row_requests}(want 1 -- with no such row the rig is not reading a billing-ON node at all); "; }

# ── (1) THE CARD MUST BE ABLE TO NAME THE CLASS ───────────────────────────────────────────────────
# The rate above was applied by h2_boot before the measured call. Validation alone
# would not establish which card priced this row.

# ── (2) THE PLANE MUST REPORT A COUNT ─────────────────────────────────────────────────────────────
# Read this class alone; unrelated quantities cannot stand in for response bytes.
quantity="$(h2_meter_row_quantity "agent:probe" "a2a" bytes)"
# Asked through h2_int_is so ANY read that is not a positive integer -- `-` (no row), 0, empty,
# non-numeric -- is a failure. The old `[ "$quantity" -le 0 ] 2>/dev/null` errored silently on
# every shape but `-` and 0 and let the leg pass (a2a twin of mcp item 499).
if ! h2_int_is "$quantity" -gt 0; then
  failures=$((failures+1))
  detail="${detail}(2) the served exchange reported quantity=${quantity} under this plane's declared class 'bytes' (want > 0: the agent answered with a document, and an exchange that moved no bytes did not happen); "
fi

# ── (3) THE PRICE MUST BE THE PRODUCT ─────────────────────────────────────────────────────────────
# UnitRate config is micro-units per class unit; the fee is one cent = 10000 micro-units.
spend_micros="$(h2_meter_row_field "agent:probe" "a2a" spend_micros)"
if h2_int_is "$quantity" -gt 0; then
  expected_micros="$(python3 -c 'import sys; print(int(sys.argv[1]) * 2 + 10000)' "$quantity")"
  if [ "$spend_micros" != "$expected_micros" ]; then
    failures=$((failures+1))
    detail="${detail}(3) spend_micros=${spend_micros}, want ${expected_micros} = ${quantity} bytes * 2 micro-units/byte + 10000 micro-units/request; "
  fi
fi
if [ "$failures" -ne 0 ]; then
  detail="${detail}measured spend_micros=${spend_micros}; "
fi

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "one served message/send reported a non-zero count under the declared class 'bytes', a card can price it, and the row charged count × rate + fee"
else
  h2_verdict FAIL "$detail"
fi
