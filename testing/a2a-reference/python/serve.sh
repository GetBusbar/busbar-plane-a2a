#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${A2A_REFERENCE_PYTHON:-${A2AHT_CONTROL_SRC:-}/venv/bin/python}
if [ ! -x "$python" ]; then
    echo 'Set A2A_REFERENCE_PYTHON to an interpreter with a2a-sdk==1.1.2' >&2
    exit 2
fi
"$python" -c 'from importlib.metadata import version; import sys; v=version("a2a-sdk"); sys.exit(0 if v == "1.1.2" else "Expected a2a-sdk==1.1.2, got " + v)'
exec "$python" "$here/scenario_agent.py" --port "$1"
