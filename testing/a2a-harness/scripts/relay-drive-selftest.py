"""Targeted wire controls for RELAY-DRIVE.md, not SDK conformance evidence."""

import copy
import json
import multiprocessing
import shlex
import sys
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from a2aht.fakes import FakePeer, honest_card
from a2aht.model import Context, NotConfigured, Violation
from a2aht.target import Target

from a2aht import transport
from a2aht.relay import correlated_relay
from a2aht.tests_client import test_seam_relay


class RelayFixture:
    """Deliberately transparent relay; defects exercise refusal paths over HTTP."""

    def __init__(self, defect=None, binding="HTTP+JSON"):
        self.defect = defect
        self.binding = binding
        self.downstream = None
        self.drip_started = threading.Event()
        self.drip_stopped = threading.Event()
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, value):
                body = json.dumps(value).encode()
                if relay.defect == "duplicate_json" and "task" in value:
                    body = b'{"task":null,' + body[1:]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                self.reply(honest_card(relay.url, binding=relay.binding))

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/configure":
                    relay.downstream = body["url"]
                    if relay.defect == "setup_traffic":
                        transport.request(
                            "POST",
                            relay.downstream + "/message:send",
                            body={"message": {"parts": [{"text": "early"}]}},
                        )
                    self.reply({"configured": True})
                    return
                if relay.defect == "drip":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "1000000")
                    self.end_headers()
                    relay.drip_started.set()
                    try:
                        for _ in range(100):
                            self.wfile.write(b" ")
                            self.wfile.flush()
                            time.sleep(0.03)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        relay.drip_stopped.set()
                    return
                if relay.defect == "timeout":
                    time.sleep(0.15)
                    self.reply({})
                    return
                params = body.get("params", body)
                if relay.defect == "request_mismatch":
                    params = copy.deepcopy(params)
                    params["message"]["parts"] = [{"text": "unrelated"}]
                task = {
                    "id": uuid.uuid4().hex,
                    "contextId": uuid.uuid4().hex,
                    "status": {"state": "TASK_STATE_COMPLETED"},
                    "artifacts": [
                        {
                            "artifactId": uuid.uuid4().hex,
                            "parts": [{"text": "unrelated"}],
                        }
                    ],
                }
                if relay.defect == "request_leak":
                    params = copy.deepcopy(params)
                    params["message"]["contextId"] = task["contextId"]
                if relay.defect != "no_downstream":
                    response = transport.request(
                        "POST", relay.downstream + "/message:send", body=params
                    )
                    downstream = response.json()["task"]
                    task["artifacts"] = downstream["artifacts"]
                    if relay.defect == "duplicate_send":
                        transport.request(
                            "POST", relay.downstream + "/message:send", body=params
                        )
                    if relay.defect == "task_leak":
                        task["id"] = downstream["id"]
                    if relay.defect == "context_leak":
                        task["contextId"] = downstream["contextId"]
                if relay.defect == "response_mismatch":
                    task["artifacts"] = []
                payload = {"task": task}
                if relay.binding == "JSONRPC":
                    payload = {"jsonrpc": "2.0", "id": body["id"], "result": payload}
                    if relay.defect == "rpc_mismatch":
                        payload["id"] = "wrong-id"
                self.reply(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def context(self):
        command = shlex.join(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "configure",
                "{endpoint}",
                "{url}",
            ]
        )
        return Context(Target(endpoint=self.url), {"relay_drive": command})


class RelayControls(unittest.TestCase):
    def test_positive_both_bindings(self):
        for binding in ("HTTP+JSON", "JSONRPC"):
            with self.subTest(binding=binding), RelayFixture(binding=binding) as relay:
                context = relay.context()
                test_seam_relay(context)
                self.assertEqual(context.assertions, 3)
                self.assertTrue(
                    context.observations["relay_correlation"][
                        "response_challenge_matched"
                    ]
                )

    def test_wire_evidence_refusals(self):
        for defect, reason in (
            ("setup_traffic", "before the upstream call"),
            ("no_downstream", "exactly one downstream"),
            ("request_mismatch", "upstream challenge"),
            ("response_mismatch", "response challenge"),
            ("duplicate_send", "exactly one downstream"),
            ("duplicate_json", "duplicate JSON member"),
        ):
            with (
                self.subTest(defect=defect),
                RelayFixture(defect) as relay,
                self.assertRaisesRegex(NotConfigured, reason),
            ):
                test_seam_relay(relay.context())

    def test_wrong_rpc_response_id(self):
        with (
            RelayFixture("rpc_mismatch", binding="JSONRPC") as relay,
            self.assertRaisesRegex(NotConfigured, "does not match"),
        ):
            test_seam_relay(relay.context())

    def test_identifier_leaks_fail(self):
        for defect in ("task_leak", "context_leak", "request_leak"):
            with (
                self.subTest(defect=defect),
                RelayFixture(defect) as relay,
                self.assertRaises(Violation),
            ):
                test_seam_relay(relay.context())

    def test_missing_driver_refuses(self):
        with (
            FakePeer() as peer,
            self.assertRaisesRegex(NotConfigured, "no --relay-drive"),
        ):
            correlated_relay(Context(Target(endpoint=peer.base_url), {}), peer)

    def test_driver_failure_refuses(self):
        with FakePeer() as peer:
            ctx = Context(
                Target(endpoint=peer.base_url),
                {
                    "relay_drive": shlex.join(
                        [sys.executable, "-c", "raise SystemExit(7)"]
                    )
                },
            )
            with self.assertRaisesRegex(NotConfigured, "returned 7"):
                correlated_relay(ctx, peer)

    def test_driver_timeout_refuses(self):
        with FakePeer() as peer:
            ctx = Context(
                Target(endpoint=peer.base_url),
                {
                    "relay_drive": shlex.join(
                        [sys.executable, "-c", "import time; time.sleep(2)"]
                    )
                },
            )
            with self.assertRaisesRegex(NotConfigured, "command timed out"):
                correlated_relay(ctx, peer, timeout=0.05)

    def test_upstream_timeout_refuses(self):
        with RelayFixture("timeout") as relay, FakePeer() as peer:
            ctx = relay.context()
            # Preconfigure this fixture so process startup cannot consume the
            # deliberately tiny network deadline used by this negative control.
            relay.downstream = peer.base_url
            ctx.config["relay_drive"] = shlex.join([sys.executable, "-c", "pass"])
            with self.assertRaisesRegex(NotConfigured, "deadline|HTTP 599"):
                correlated_relay(ctx, peer, timeout=0.1)

    def test_trickling_response_hard_deadline(self):
        with RelayFixture("drip") as relay, FakePeer() as peer:
            ctx = relay.context()
            relay.downstream = peer.base_url
            ctx.config["relay_drive"] = shlex.join([sys.executable, "-c", "pass"])
            # Prime discovery; measure the actual upstream operation only.
            ctx.target.pick_interface()
            children_before = {child.pid for child in multiprocessing.active_children()}
            started = time.monotonic()
            with self.assertRaisesRegex(NotConfigured, "hard deadline"):
                correlated_relay(ctx, peer, timeout=0.7)
            elapsed = time.monotonic() - started
            self.assertTrue(
                relay.drip_started.is_set(), "must reach real drip response"
            )
            self.assertLess(elapsed, 1.5, "must stop before the 3-second drip ends")
            self.assertTrue(
                relay.drip_stopped.wait(0.5), "worker socket must be closed"
            )
            self.assertEqual(
                {child.pid for child in multiprocessing.active_children()},
                children_before,
            )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "configure":
        response = transport.request(
            "POST", sys.argv[2] + "/configure", body={"url": sys.argv[3]}
        )
        sys.exit(0 if response.status == 200 else 1)
    unittest.main()
