#!/usr/bin/env python3
"""Exercise the negative-control relay against an actual chunked SSE origin."""
import http.client
import json
from pathlib import Path
import select
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class RelayRegressions(unittest.TestCase):
    def _chunked_reply(self, mode=None):
        class Origin(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                event = b'data: {"jsonrpc":"2.0","id":7,"result":{"task":{"status":{"state":"TASK_STATE_COMPLETED"}}}}\n\n'
                for chunk in (event[:22], event[22:68], event[68:]):
                    self.wfile.write(("%x\r\n" % len(chunk)).encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        command = [sys.executable, str(Path(__file__).with_name("broken_agent.py")),
                   "0", str(origin.server_port)]
        if mode is not None:
            command.append(mode)
        child = subprocess.Popen(command,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        connection = None
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "relay never listened")
            relay_port = int(child.stdout.readline())
            connection = http.client.HTTPConnection("127.0.0.1", relay_port, timeout=3)
            connection.request("POST", "/", body=b"")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read().decode()
            self.assertTrue(body.startswith("data: "), body)
            payload = json.loads(body.removeprefix("data: ").strip())
            return payload
        finally:
            if connection is not None:
                connection.close()
            child.terminate()
            child.communicate(timeout=5)
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=5)

    def test_chunked_sse_is_decoded_before_damage(self):
        payload = self._chunked_reply()
        self.assertEqual(payload["jsonrpc"], "1.0")
        self.assertEqual(payload["id"], 79)
        self.assertEqual(payload["result"]["task"]["status"]["state"], "TASK_STATE_MADE_UP")

    def test_state_probe_keeps_valid_envelope_so_schema_is_reached(self):
        payload = self._chunked_reply("state")
        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertEqual(payload["id"], 7)
        self.assertEqual(payload["result"]["task"]["status"]["state"], "TASK_STATE_MADE_UP")

    def test_version_probe_preserves_payload_state_and_request_id(self):
        payload = self._chunked_reply("version")
        self.assertEqual(payload["jsonrpc"], "1.0")
        self.assertEqual(payload["id"], 7)
        self.assertEqual(payload["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED")

    def test_independent_harness_rejects_wrong_id_on_the_wire(self):
        from types import SimpleNamespace
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "a2a-harness"))
        from a2aht.fakes import Behaviour, FakePeer
        from a2aht.model import Context, Violation
        from a2aht.tests_adversarial import test_jsonrpc_envelope
        with FakePeer(Behaviour(wrong_jsonrpc_id=True), binding="JSONRPC") as peer:
            target = SimpleNamespace(insecure=False,
                                     pick_interface=lambda: {"url": peer.base_url,
                                                             "protocolBinding": "JSONRPC"},
                                     request_headers=lambda *args, **kwargs: {})
            with self.assertRaisesRegex(Violation, "response id"):
                test_jsonrpc_envelope(Context(target, {}))


if __name__ == "__main__":
    unittest.main()
