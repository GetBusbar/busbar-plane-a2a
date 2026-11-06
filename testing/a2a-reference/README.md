# Declared reference fixtures

These are fixture adapters around pinned `a2a-go/v2 v2.4.0` and
`a2a-sdk==1.1.2`. They are not the unmodified upstream CLI echo server or Python
hello-world sample. Their local source and corrections are included alongside
each adapter. Upstream oracle checkouts, original reports, historical baselines,
and known-deviation files remain immutable.

The Go fixture exposes one selected HTTP+JSON or JSONRPC interface per process;
the Python fixture exposes JSONRPC. Their cards describe the interfaces and
capabilities actually served. Each fixture battery control explicitly measures the
server role, and its role audit records client and seam roles as unmeasured.
The Go SDK server plus CLI client control selects `--roles server client` and
preserves both role sets. The client-only profile has only nine asserted rows,
below the unchanged absolute floor of ten, so it cannot independently establish
a green verdict. No assertion or coverage floor is reduced. These
controls do not establish Python gRPC, Python client, or SDK relay conformance.

Control verdicts come directly from the current, unwaived TCK/battery assertions.
An old baseline mismatch neither excuses a new failure nor rejects a newly fixed
requirement. Historical reports remain available for diagnosing changes.

## Run

Set `A2A_REFERENCE_OUT` to a new evidence directory. Reuse the provisioned
`A2A_TCK_WORK`, `A2AHT_CONTROL_SRC`, and `A2AHT_CONTROL_BIN` caches. Python uses
`A2A_REFERENCE_PYTHON` when set, otherwise the control cache's `venv/bin/python`;
its installed SDK version must be exactly 1.1.2.

Run `testing/a2a-reference/run-controls.sh` once for each of:

- `tck-go-rest`
- `tck-go-jsonrpc`
- `battery-go-rest`
- `battery-go-jsonrpc`
- `battery-python`
- `battery-go-client`

TCK legs sharing a work directory must run sequentially: the unchanged oracle
owns one reports directory. `A2A_REFERENCE_PORT` changes the battery listener
port. The non-UTC test timezone is retained; the Go executor creates UTC
timestamps explicitly.

## Correlated relay coverage

The separate generic `--relay-drive` contract is documented in
`../a2a-harness/RELAY-DRIVE.md`. It lets the harness observe both sides of a real
relay using fresh request and response challenges. Merely passing the local
positive/negative harness controls proves no SDK or product relay behavior.
Actual client and seam coverage requires configured drivers and an actual full
role run; an absent driver remains an explicit red coverage gap.

Run the bounded harness controls with:

```sh
python3 testing/a2a-harness/scripts/relay-drive-selftest.py -v
```
