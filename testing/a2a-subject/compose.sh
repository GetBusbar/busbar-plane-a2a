#!/usr/bin/env bash
# THE SUBJECT'S COMPOSITION: which busbar package the `a2a` suite builds, with this checkout's plane in it.
#
#   compose.sh <busbar checkout> <this plane's crate dir> <stage dir>
#
# Prints the manifest path of the package to build (`cargo build --release --manifest-path <it>
# --bin busbar`, this plane patched in by a run-time --config). Held by
# testing/a2a-subject/compose-selftest.sh, which testing/conformance/a2a.sh runs before the subject build.
#
# The package is busbar's default distribution (dist/default): the root crate (crates/busbar) is core
# with no plugin linked, so it serves no A2A. The checkout is copied to <stage> and is never written.
# In the copy, the dist's two rows that name an item inside this plane are pointed at where THIS plane
# keeps it, the way busbar's dist names them once it pins this plane:
#   linked-entry    plane-a2a-door  the module the door is exported from (the crate root, when the
#                                   plane has no public module of the name the row gives: the pin
#                                   names `busbar_plane_a2a::agent_door`, private since a3e2089)
#   linked-declares plane-a2a-door  the plane's own declares.json, by path (the document its door's
#                                   Statement carries; the plane exports no `DECLARES`)
# Nothing else changes: busbar's code, its other rows and its lockfile are the pin's.
set -euo pipefail
checkout="${1:?busbar checkout}"; plane="${2:?plane crate dir}"; stage="${3:?stage dir}"
plane="$(cd "$plane" && pwd)"
rm -rf "$stage"; mkdir -p "$stage"
tar -C "$checkout" --exclude=./target --exclude=./.git -cf - . | tar -C "$stage" -xf -
"${PYTHON:-python3}" -I - "$stage/dist/default/Cargo.toml" "$plane" >&2 <<'PY'
import os, re, sys
manifest, plane = sys.argv[1:3]
text = open(manifest).read()
lib = open(os.path.join(plane, "src", "lib.rs")).read()

def set_row(table, key, value):
    global text
    sec = re.search(r"^\[" + re.escape(table) + r"\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not sec:
        sys.exit(f"compose: {manifest} has no [{table}]")
    body = sec.group(1)
    row = re.compile(r'^' + re.escape(key) + r'\s*=\s*"[^\n]*$', re.M)
    if not row.search(body):
        sys.exit(f"compose: [{table}] has no `{key}` row")
    new = row.sub(lambda _: f"{key} = {value}", body, count=1)
    text = text[: sec.start(1)] + new + text[sec.end(1):]
    print(f"compose: [{table}] {key} = {value}")

sec = re.search(r"^\[package\.metadata\.busbar\.linked-entry\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
entry = sec and re.search(r'^plane-a2a-door\s*=\s*"busbar_plane_a2a::(\w+)"', sec.group(1), re.M)
if entry and not re.search(r"^pub mod " + entry.group(1) + r"\b", lib, re.M):
    set_row("package.metadata.busbar.linked-entry", "plane-a2a-door", '"busbar_plane_a2a"')
if not re.search(r"^pub (const|static) DECLARES\b", lib, re.M):
    declares = os.path.join(plane, "declares.json")
    if not os.path.isfile(declares):
        sys.exit(f"compose: {declares} is missing")
    if any(c in declares for c in '"\\#\n'):
        sys.exit(f"compose: {declares}: a path busbar's row reader cannot carry")
    # A TOML multi-line basic string: busbar's row reader (linked_gen.rs, not a TOML parser) trims
    # the quotes and emits the rest as the row's Rust expression, `include_str!("<path>")`.
    set_row("package.metadata.busbar.linked-declares", "plane-a2a-door",
            '"""include_str!("' + declares + '")"""')
open(manifest, "w").write(text)
PY
printf '%s\n' "$stage/dist/default/Cargo.toml"
