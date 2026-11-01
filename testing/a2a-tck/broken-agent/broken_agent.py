#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""A DELIBERATELY BROKEN A2A agent: the negative control for the TCK leg.

It is the honest TCK scenario agent (../scenario-agent) behind a relay that corrupts what the
scenario agent says. The card, and every GET, pass through unchanged, so the TCK reaches the peer,
fetches a usable card and runs its tests; every POST answer is damaged in three ways the
specification forbids:

  * task states are renamed to a state the protocol does not define (TASK_STATE_MADE_UP);
  * the JSON-RPC envelope's `jsonrpc` member says "1.0";
  * a wrong id is echoed (the request id with a suffix).

`testing/conformance/a2a.sh` requires failed MUST diagnostics to name the injected state and
version violations on requirements that pass against the honest peer. This TCK pin checks
only id presence, so wrong-id rejection is asserted by the independent harness rather than
claimed as TCK coverage. An unrelated failure count cannot satisfy the negative leg.

The optional mode isolates a single violation so an invalid JSON-RPC envelope
does not prevent the TCK from reaching TaskState schema validation.

usage: broken_agent.py <listen-port> <upstream-port> [all|state|version|id]
"""
import http.client
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN, UPSTREAM = int(sys.argv[1]), int(sys.argv[2])
MODE = sys.argv[3] if len(sys.argv) > 3 else "all"
if MODE not in {"all", "state", "version", "id"}:
    raise SystemExit("unknown negative-control mode: " + MODE)
STATE = re.compile(rb'TASK_STATE_(SUBMITTED|WORKING|COMPLETED|FAILED|CANCELED|CANCELLED|INPUT_REQUIRED|REJECTED|AUTH_REQUIRED)')
VERSION = re.compile(rb'"jsonrpc"\s*:\s*"2\.0"')
ID = re.compile(rb'"id"\s*:\s*(\d+)')


def damage(chunk: bytes) -> bytes:
    if MODE in {"all", "state"}:
        chunk = STATE.sub(b'TASK_STATE_MADE_UP', chunk)
    if MODE in {"all", "version"}:
        chunk = VERSION.sub(b'"jsonrpc":"1.0"', chunk)
    if MODE in {"all", "id"}:
        chunk = ID.sub(lambda m: b'"id":' + m.group(1) + b'9', chunk)
    return chunk


class Relay(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"      # close-delimited bodies: streams and plain answers alike

    def log_message(self, *args):
        pass

    def _relay(self, damaged: bool):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection("127.0.0.1", UPSTREAM, timeout=60)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        conn.request(self.command, self.path, body=body, headers=headers)
        resp = conn.getresponse()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                self.send_header(k, v)
        self.send_header("connection", "close")
        self.end_headers()
        while True:
            line = resp.readline() if resp.getheader("content-type", "").startswith("text/event-stream") else resp.read(65536)
            if not line:
                break
            self.wfile.write(damage(line) if damaged else line)
            self.wfile.flush()
        conn.close()

    def do_GET(self):
        self._relay(False)

    def do_POST(self):
        self._relay(True)

    do_DELETE = do_POST
    do_PUT = do_POST


ThreadingHTTPServer(("127.0.0.1", LISTEN), Relay).serve_forever()
