#!/usr/bin/env python3
"""Regression controls for conformance checks that previously passed failed probes."""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from a2asup import checks_bind, checks_ver, verifier_probe
from a2asup.model import Verdict
from a2asup.target import Interface, Target
from a2asup.transport import Reply
from selftest import FakeBinding, _two_binding_target


class ProbeRegressions(unittest.TestCase):
    def paired(self, a, b):
        return _two_binding_target({
            "jsonrpc": FakeBinding("jsonrpc", {"send_message": a}),
            "http_json": FakeBinding("http_json", {"send_message": b}),
        })

    def test_failed_operations_cannot_be_equivalent(self):
        target = self.paired(Reply(ok=False, http_status=401, code=401),
                             Reply(ok=False, http_status=500, code=500))
        self.assertEqual(checks_bind.check_bind_equiv_002(target).verdict, Verdict.FAIL)
        class Failed:
            def call(self, *args, **kwargs):
                return Reply(ok=False, code=500, http_status=500)
        target = _two_binding_target({n: Failed() for n in ("jsonrpc", "http_json")})
        self.assertNotEqual(checks_bind.check_bind_equiv_001(target).verdict, Verdict.PASS)

    def test_user_data_ids_names_and_timestamps_are_semantic(self):
        for key in ("id", "name", "timestamp"):
            def reply(value):
                return Reply(ok=True, payload={"task": {"artifacts": [
                    {"parts": [{"data": {key: value}}]}]}}, http_status=200)
            self.assertEqual(checks_bind.check_bind_equiv_002(self.paired(reply("a"), reply("b"))).verdict,
                             Verdict.FAIL)
            self.assertEqual(checks_bind.check_bind_equiv_002(self.paired(reply("a"), reply("a"))).verdict,
                             Verdict.PASS)
        self.assertNotEqual(checks_bind._shape([{"a": 1}, {"b": 2}]),
                            checks_bind._shape([{"a": 1}, {"c": 2}]))

    def test_every_binding_accepting_forgery_is_not_auth_equivalence(self):
        target = _two_binding_target({n: FakeBinding(n, {}) for n in ("jsonrpc", "http_json")})
        self.assertEqual(checks_bind.check_bind_equiv_004(target).verdict, Verdict.FAIL)
        class Protected:
            def call(self, op, params, *, token=None, **kwargs):
                return (Reply(ok=True, payload={"task": {"id": "x"}}, http_status=200)
                        if token == "tok" else Reply(ok=False, http_status=401, code=401))
        target = _two_binding_target({n: Protected() for n in ("jsonrpc", "http_json")})
        self.assertEqual(checks_bind.check_bind_equiv_004(target).verdict, Verdict.PASS)

    def test_version_positive_control_must_succeed(self):
        class Broken:
            def call(self, *args, **kwargs):
                return Reply(ok=False, http_status=500, code=500)
        target = Target("broken", "http://example.invalid/card", token="tok")
        target.interfaces = [Interface("http://example.invalid/", "jsonrpc", "1.0")]
        target.bindings = lambda: {"jsonrpc": Broken()}
        self.assertEqual(checks_ver.check_ver_server_001(target).verdict, Verdict.FAIL)
        self.assertEqual(checks_ver.check_ver_client_002(target).verdict, Verdict.FAIL)
        class Versioned:
            def call(self, op, params, *, version="1.0", method_override=None, **kwargs):
                if version == "1.0" and method_override == "message/send":
                    return Reply(ok=False, http_status=400, code=-32601)
                return Reply(ok=True, http_status=200, payload={"task": {"id": "x"}})
        target.bindings = lambda: {"jsonrpc": Versioned()}
        self.assertEqual(checks_ver.check_ver_server_001(target).verdict, Verdict.PASS)
        self.assertEqual(checks_ver.check_ver_client_002(target).verdict, Verdict.PASS)

    def test_bad_registration_is_an_error_not_a_signature_refusal(self):
        good_put = SimpleNamespace(status_code=200, text="{}")
        bad_put = SimpleNamespace(status_code=500, text="registration failed")
        good_connect = SimpleNamespace(status_code=200, text='{"fingerprint":"good"}',
                                       json=lambda: {"fingerprint": "good"})
        with patch.dict(os.environ, {"A2ASUP_RIGHT_ISSUER_KEY": "right"}), \
             patch.object(verifier_probe, "_wrong_key", return_value="wrong"), \
             patch.object(verifier_probe, "_put_agent", side_effect=[good_put, bad_put]), \
             patch.object(verifier_probe, "_connect", return_value=good_connect) as connect, \
             patch.object(verifier_probe, "_delete_agent") as delete:
            result = verifier_probe._run(SimpleNamespace(id="CARD-SIGN-004"), "http://admin", "token", "http://agent")
        self.assertEqual(result.verdict, Verdict.ERROR)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(delete.call_count, 2)

    def test_grpc_target_preserves_transport_security(self):
        grpc = SimpleNamespace(secure_channel=Mock(), insecure_channel=Mock(),
                               ssl_channel_credentials=Mock(return_value="roots"))
        with patch.dict(sys.modules, {"grpc": grpc}):
            for scheme, port in (("https", 443), ("http", 80)):
                target = Target("grpc", "http://card")
                target.interfaces = [Interface(f"{scheme}://example.invalid/a2a", "grpc", "1.0")]
                target.bindings()["grpc"]._connect()
        grpc.secure_channel.assert_called_once_with("example.invalid:443", "roots")
        grpc.insecure_channel.assert_called_once_with("example.invalid:80")


if __name__ == "__main__":
    unittest.main()
