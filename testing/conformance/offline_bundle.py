#!/usr/bin/env python3
"""Public tool bundle packaging; never executes while collecting candidate credentials."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

MOUNT = "/opt/busbar-conformance/a2a-tools"
INPUTS = (
    "testing/conformance/a2a.sh",
    "testing/conformance/tools.sh",
    "testing/conformance/requirements-py.txt",
    "testing/conformance/requirements-tck.txt",
    "testing/a2a-harness/scripts/install-control.sh",
    "testing/a2a-tck/run-tck.sh",
    "testing/a2a-reference/go/go.mod",
    "testing/a2a-reference/go/go.sum",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat()
        if stat.S_ISDIR(mode.st_mode):
            continue
        if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1:
            raise ValueError(f"not a single-link regular file: {path}")
        result[path.relative_to(root).as_posix()] = {
            "sha256": digest(path), "executable": bool(mode.st_mode & 0o111)
        }
    return result


def copy_tree(source, target, omit_share=False):
    # Flatten only links to files/directories already inside this public source tree.
    for path in source.rglob("*"):
        if omit_share and path.relative_to(source).parts[0] == "share":
            continue
        if path.is_symlink() and not path.resolve(strict=True).is_relative_to(source.resolve()):
            raise ValueError(f"public tool link escapes its source: {path}")
    shutil.copytree(source, target, symlinks=False, ignore=lambda directory, names:
                    {"share"} if omit_share and Path(directory) == source else set())


def main():
    mode, bundle_arg, root_arg = sys.argv[1:4]
    bundle, root = Path(bundle_arg), Path(root_arg)
    inputs = {name: digest(root / name) for name in INPUTS}
    if mode == "check":
        if str(bundle) != MOUNT:
            raise ValueError("unexpected public tool mount")
        admitted = json.loads(Path(os.environ["BUSBAR_CONFORMANCE_INPUTS"]).read_text())
        if admitted["schema"] != "busbar.native-conformance-inputs/1" or "a2a-tools" not in admitted["bundles"]:
            raise ValueError("A2A tools were not admitted")
        metadata = json.loads((bundle / "bundle.json").read_text())
        if metadata["inputs"] != inputs:
            raise ValueError("offline tool inputs differ from the checkout pins")
        if metadata["machine"] != os.uname().machine:
            raise ValueError("offline tool architecture differs from this worker")
        return
    if mode != "pack":
        raise ValueError("expected pack or check")
    work, cache = map(Path, sys.argv[4:6])
    bundle.mkdir()
    for pattern, destination in (
        ("go1.26.10-linux-*/go", "go"),
        ("cpython-3.12.16-20261026-*/python", "python"),
        ("node-v22.23.3-linux-*", "node"),
    ):
        matches = [path for path in cache.glob(pattern) if path.is_dir()]
        if len(matches) != 1:
            raise ValueError(f"expected one pinned tool: {pattern}")
        copy_tree(matches[0], bundle / destination, omit_share=destination == "python")
    for source, destination in (
        (work / "tck/a2a-tck", "a2a-tck"),
        (work / "a2aht-src/a2a-python", "a2a-python"),
        (work / "gopath/pkg/mod", "gomodcache"),
        (work / "tck/venv", "venv-tck"),
        (work / "a2aht-src/venv", "venv-python"),
    ):
        copy_tree(source, bundle / destination)
    (bundle / "bin").mkdir()
    shutil.copy2(work / "bin/a2a", bundle / "bin/a2a")
    # --copies venvs retain the installed hash-locked packages. Their interpreter home
    # and console scripts must reference the fixed read-only mount, never staging paths.
    for name, old in (("venv-tck", work / "tck/venv"), ("venv-python", work / "a2aht-src/venv")):
        venv = bundle / name
        (venv / "pyvenv.cfg").write_text(
            f"home = {MOUNT}/python/bin\ninclude-system-site-packages = false\nversion = 3.12.16\n"
        )
        for script in (venv / "bin").iterdir():
            if script.read_bytes().startswith(b"#!"):
                script.write_bytes(script.read_bytes().replace(str(old).encode(), f"{MOUNT}/{name}".encode()))
    archives = []
    for path in sorted(cache.glob("*.tar.gz")):
        name = path.name
        if name.startswith("go"):
            uri = "https://go.dev/dl/" + name
        elif name.startswith("node-"):
            uri = "https://nodejs.org/dist/v22.23.3/" + name
        elif name.startswith("cpython-"):
            arch = "aarch64" if os.uname().machine == "aarch64" else "x86_64"
            uri = ("https://github.com/astral-sh/python-build-standalone/releases/download/20261026/"
                   f"cpython-3.12.16%2B20261026-{arch}-unknown-linux-gnu-install_only.tar.gz")
        else:
            raise ValueError(f"unexpected tool archive: {name}")
        archives.append({"uri": uri, "sha256": digest(path)})
    revisions = {}
    for name in ("a2a-tck", "a2a-python"):
        revisions[name] = subprocess.check_output(
            ["git", "-C", str(bundle / name), "rev-parse", "HEAD"], text=True
        ).strip()
    (bundle / "bundle.json").write_text(json.dumps({
        "schema": "busbar.a2a-offline-tools/1", "machine": os.uname().machine, "inputs": inputs,
        "provenance": archives, "revisions": revisions,
    }, indent=2) + "\n")
    # The controller must replace path if it copies the bundle before admission.
    manifest = {"schema": "busbar.native-conformance-inputs/1", "bundles": {
        "a2a-tools": {"path": str(bundle.resolve()), "files": inventory(bundle), "provenance": archives}
    }}
    bundle.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
