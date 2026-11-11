#!/usr/bin/env bash
# THE SUBJECT'S COMPOSITION: which busbar package the `a2a` suite builds, with this checkout's plane in it.
#
#   compose.sh <busbar checkout> <this plane's crate dir> <stage dir>
#
# Copy the canonical host checkout without rewriting distribution metadata or scanning Rust.
# The pinned host's dist/default metadata owns the linked door and declaration expressions.
# The staged Cargo config shares the plane override with nested metadata commands.
set -euo pipefail
checkout="${1:?busbar checkout}"; plane="${2:?plane crate dir}"; stage="${3:?stage dir}"
plane="$(cd "$plane" && pwd)"
"${PYTHON:-python3}" -I - "$stage" "$checkout" "$plane" "$PWD" "$HOME" <<'SAFE_STAGE'
from pathlib import Path
import sys
stage = Path(sys.argv[1]).resolve()
protected = [Path(value).resolve() for value in sys.argv[2:]]
if any(stage == path or stage in path.parents for path in protected):
    sys.exit("composition stage would remove a checkout, home, or parent directory")
if stage.is_relative_to(protected[0]):
    sys.exit("composition stage must be outside the checkout it copies")
SAFE_STAGE
umask 077
rm -rf "$stage"; mkdir -p "$stage"
tar -C "$checkout" --exclude=./target --exclude=./.git -cf - . | tar -C "$stage" -xf -
python3 -I - "$stage" "$plane" <<'CARGO_PATCH'
import json
from pathlib import Path
import sys
import tomllib

stage, plane = sys.argv[1:]
config = Path(stage) / ".cargo/config.toml"
text = config.read_text() if config.exists() else ""
url = "https://github.com/GetBusbar/busbar-plane-a2a"
package = "busbar-plane-a2a"
existing = tomllib.loads(text).get("patch", {}).get(url, {}).get(package)
if existing is not None and existing != {"path": plane}:
    sys.exit("staged host already configures a different A2A source override")
if existing is None:
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(text + f'\n[patch.{json.dumps(url)}.{package}]\npath = {json.dumps(plane)}\n')
CARGO_PATCH
printf '%s\n' "$stage/dist/default/Cargo.toml"
