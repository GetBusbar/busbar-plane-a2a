#!/usr/bin/env python3
"""Regression controls for byte framing and the harness's actual wire probes."""
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from a2aht import jcs, tests_adversarial, tests_client, transport


class Context:
    config = {"nesting_depth": 2000}

    def observe(self, *_):
        pass

    def assert_must(self, condition, *detail):
        if not condition:
            raise AssertionError(detail)


class ProtocolRegressions(unittest.TestCase):
    def test_sse_split_crlf_and_multiline_data(self):
        for newline in (b"\r\n", b"\n", b"\r"):
            wire = newline.join([b'data: {"a":', b'data: 1}', b'', b'data:  two spaces', b'', b''])
            response = io.BytesIO(wire)
            response.status = 200
            response.headers = {"Content-Type": "text/event-stream"}
            opener = SimpleNamespace(open=lambda *a, **k: response)
            with patch.object(transport, "_opener", return_value=opener):
                result = transport.sse_events("http://example.invalid/")
            self.assertIsNone(result.error)
            self.assertEqual(result.events, [{"a": 1}, {"_unparsed": " two spaces"}])

    def test_jcs_number_boundaries(self):
        for value, expected in [(1e-6, "0.000001"), (1e-7, "1e-7"),
                                (1e20, "100000000000000000000"), (1e21, "1e+21"),
                                (-0.0, "0"), (1.0000000000000001e18, "1000000000000000100")]:
            self.assertEqual(jcs.canonicalize(value), expected)
        self.assertEqual(jcs.canonicalize({"\u0100": 1, "\u00ff": 2}), '{"ÿ":2,"Ā":1}')

    def test_version_header_on_every_operation(self):
        class Peer:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            requests = [{"path": "/.well-known/agent-card.json", "headers": {"a2a-version": "1.0"}}]
            def a2a_requests(self):
                return operations
        run = dict(returncode=0, timed_out=False, stdout="", stderr="")
        for operations in ([{"path": "/a2a", "headers": {}}],
                           [{"path": "/a2a", "headers": {"a2a-version": "1.0"}},
                            {"path": "/a2a", "headers": {}}]):
            with patch.object(tests_client, "FakePeer", Peer), patch.object(tests_client, "drive", return_value=run):
                with self.assertRaises(AssertionError):
                    tests_client.test_client_version_header(Context())
        operations = [{"path": "/a2a?A2A-Version=1.0", "headers": {}}]
        with patch.object(tests_client, "FakePeer", Peer), patch.object(tests_client, "drive", return_value=run):
            tests_client.test_client_version_header(Context())

    def test_stall_probe_calls_healthy_peer_before_close(self):
        events = []
        class Socket:
            def sendall(self, data):
                events.append(data)
            def settimeout(self, _):
                pass
            def recv(self, _):
                return b""
            def close(self):
                events.append("closed")
        def healthy(*_):
            self.assertIn(b"{", events)
            self.assertNotIn("closed", events)
            events.append("healthy")
            return SimpleNamespace(error=None, http=None)
        ctx = Context()
        ctx.target = SimpleNamespace(insecure=False, call=healthy)
        with patch.object(transport, "_connect", return_value=(Socket(), "localhost", "/")), \
             patch.object(tests_adversarial, "_endpoint", return_value="http://localhost/"), \
             patch.object(tests_adversarial, "_binding", return_value="JSONRPC"):
            tests_adversarial.test_connect_and_stall(ctx)
        self.assertLess(events.index("healthy"), events.index("closed"))

    def test_deep_nesting_reaches_transport_at_default_recursion_limit(self):
        captured = []
        ctx = Context()
        ctx.target = SimpleNamespace(call=lambda *a: SimpleNamespace(error=None, http=None))
        def post(_, body):
            captured.append(body)
            return SimpleNamespace(status=400)
        with patch.object(tests_adversarial, "_post_raw", post), \
             patch.object(tests_adversarial, "_binding", return_value="JSONRPC"), \
             patch.object(tests_adversarial, "_survived"):
            tests_adversarial.test_deep_nesting(ctx)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].count('{"n":'), 2000)


if __name__ == "__main__":
    unittest.main()
