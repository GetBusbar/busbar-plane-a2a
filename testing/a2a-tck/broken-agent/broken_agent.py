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

A suite that cannot tell this peer from the honest agent it relays cannot be trusted to judge
anything, so `testing/conformance/a2a.sh` requires the TCK to report strictly more failed MUSTs
against this peer than against the honest agent, run the same way.

usage: broken_agent.py <listen-port> <upstream-port>
"""
import http.client
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN, UPSTREAM = int(sys.argv[1]), int(sys.argv[2])
STATE = re.compile(rb'TASK_STATE_(SUBMITTED|WORKING|COMPLETED|FAILED|CANCELED|CANCELLED|INPUT_REQUIRED|REJECTED|AUTH_REQUIRED)')
VERSION = re.compile(rb'"jsonrpc"\s*:\s*"2\.0"')
ID = re.compile(rb'"id"\s*:\s*(\d+)')


def damage(chunk: bytes) -> bytes:
    chunk = STATE.sub(b'TASK_STATE_MADE_UP', chunk)
    chunk = VERSION.sub(b'"jsonrpc":"1.0"', chunk)
    return ID.sub(lambda m: b'"id":' + m.group(1) + b'9', chunk)


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
            line = resp.fp.readline() if resp.getheader("content-type", "").startswith("text/event-stream") else resp.read(65536)
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
