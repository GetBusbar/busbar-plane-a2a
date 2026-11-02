#!/usr/bin/env python3
"""Regression controls for conformance checks that previously passed failed probes."""
import os
import copy
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from a2asup import checks_auth, checks_bind, checks_ver, verifier_probe, runner
from a2asup.model import Result, Verdict
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

    def test_rest_route_404_does_not_prove_an_operation_exists(self):
        not_found = {"error": {"code": 404, "status": "NOT_FOUND", "details": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo", "domain": "a2a-protocol.org",
            "reason": "TASK_NOT_FOUND"}]}}
        resource = Reply(ok=False, code=404, http_status=404, raw=not_found)
        jsonrpc = FakeBinding("jsonrpc", {"cancel_task": Reply(ok=False, code=-32001, http_status=200)})
        target = _two_binding_target({"jsonrpc": jsonrpc,
            "http_json": FakeBinding("http_json", {"cancel_task": resource})})
        self.assertEqual(checks_bind.check_bind_equiv_001(target).verdict, Verdict.PASS)
        for raw in (None, "no route", {"message": "not found"}, {"error": {"code": 404}},
                    {"error": {"details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                     "domain": "router.invalid", "reason": "TASK_NOT_FOUND"}]}}):
            target.bindings = lambda: {"jsonrpc": jsonrpc,
                "http_json": FakeBinding("http_json", {"cancel_task": Reply(
                    ok=False, code=404, http_status=404, raw=raw)})}
            self.assertEqual(checks_bind.check_bind_equiv_001(target).verdict, Verdict.ERROR)

    def test_shared_security_declaration_and_every_binding_enforcement_are_reported(self):
        seen = []
        class Protected:
            def __init__(self, name, broken=False):
                self.name, self.broken = name, broken
            def call(self, op, params, *, token=None, **kwargs):
                seen.append((self.name, token))
                return (Reply(ok=True, payload={"task": {"id": "x"}}, http_status=200)
                        if token == "tok" or self.broken else Reply(ok=False, code=401, http_status=401))
        target = _two_binding_target({name: Protected(name) for name in ("jsonrpc", "http_json")})
        target.card["securitySchemes"] = {"operator_oauth": {"type": "oauth2"}}
        target.card["securityRequirements"] = [{"operator_oauth": ["tasks:read"]}]
        result = checks_bind.check_bind_equiv_004(target)
        self.assertEqual(result.verdict, Verdict.PASS)
        self.assertTrue(any("operator_oauth" in line for line in result.evidence))
        self.assertTrue(any("tasks:read" in line for line in result.evidence))
        for name in ("jsonrpc", "http_json"):
            self.assertIn((name, "tok"), seen)
            self.assertIn((name, None), seen)
            self.assertIn((name, checks_auth.FORGED_BEARER), seen)
        target.bindings = lambda: {"jsonrpc": Protected("jsonrpc"), "http_json": Protected("http_json", True)}
        self.assertEqual(checks_bind.check_bind_equiv_004(target).verdict, Verdict.FAIL)

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

    def test_undeclared_legacy_version_can_be_refused(self):
        class OneVersion:
            def call(self, op, params, *, version="1.0", method_override=None, **kwargs):
                if version in (None, ""):
                    return Reply(ok=False, code=-32009, http_status=400)
                if method_override == "message/send":
                    return Reply(ok=False, code=-32601, http_status=400)
                return Reply(ok=True, payload={"task": {"id": "t"}}, http_status=200)
        target = Target("one", "http://example.invalid/card", token="tok")
        target.interfaces = [Interface("http://example.invalid/", "jsonrpc", "1.0")]
        target.bindings = lambda: {"jsonrpc": OneVersion()}
        self.assertEqual(checks_ver.check_ver_server_001(target).verdict, Verdict.PASS)
        target.interfaces.append(Interface("http://example.invalid/", "jsonrpc", "0.3"))
        self.assertEqual(checks_ver.check_ver_server_001(target).verdict, Verdict.FAIL)

    def test_scope_requires_authenticated_success(self):
        class RefusesEverybody:
            def call(self, *args, **kwargs):
                return Reply(ok=False, code=401, http_status=401)
        target = _two_binding_target({name: RefusesEverybody() for name in ("jsonrpc", "http_json")})
        self.assertEqual(checks_auth.check_auth_scope_001(target).verdict, Verdict.FAIL)
        class Protected:
            def call(self, op, params, *, token=None, **kwargs):
                return (Reply(ok=True, payload={"task": {"id": "t"}}, http_status=200)
                        if token == "tok" else Reply(ok=False, code=401, http_status=401))
        target = _two_binding_target({name: Protected() for name in ("jsonrpc", "http_json")})
        self.assertEqual(checks_auth.check_auth_scope_001(target).verdict, Verdict.PASS)

    def test_scope_checks_every_binding_and_only_normalizes_the_requested_id(self):
        class Scoped:
            def __init__(self, leak=False, disclose=False, list_error=None):
                self.leak, self.disclose, self.list_error = leak, disclose, list_error
            def call(self, op, params, *, token=None, **kwargs):
                own = "task-" + token
                if op == "send_message":
                    return Reply(ok=True, payload={"task": {"id": own}}, http_status=200)
                if op == "list_tasks":
                    if self.list_error:
                        return Reply(ok=False, code=self.list_error, http_status=self.list_error)
                    ids = ["task-tok", "task-other"] if self.leak else [own]
                    return Reply(ok=True, payload={"tasks": [{"id": value} for value in ids]}, http_status=200)
                requested = params["id"]
                if requested == own or self.leak:
                    return Reply(ok=True, payload={"id": requested}, http_status=200)
                message = ("not yours: " if self.disclose and requested == "task-tok" else "not found: ") + requested
                return Reply(ok=False, code=-32001, message=message, http_status=404)
        target = _two_binding_target({name: Scoped() for name in ("jsonrpc", "http_json")})
        target.token_b = "other"
        self.assertEqual(checks_auth.check_auth_scope_002(target).verdict, Verdict.PASS)
        self.assertEqual(checks_auth.check_auth_scope_003(target).verdict, Verdict.PASS)
        for faulty in (Scoped(leak=True), Scoped(disclose=True)):
            target.bindings = lambda: {"jsonrpc": Scoped(), "http_json": faulty}
            self.assertEqual(checks_auth.check_auth_scope_003(target).verdict, Verdict.FAIL)
        target.bindings = lambda: {"jsonrpc": Scoped(), "http_json": Scoped(leak=True)}
        self.assertEqual(checks_auth.check_auth_scope_002(target).verdict, Verdict.FAIL)
        for code in (400, 404):
            target.bindings = lambda: {"http_json": Scoped(list_error=code)}
            self.assertEqual(checks_auth.check_auth_scope_002(target).verdict, Verdict.FAIL)

    def test_authorization_checks_do_not_pass_a_fixture_that_never_ran(self):
        for payload in ({"message": {"parts": [{"text": "ordinary message"}]}},
                        {"task": {"id": "t", "status": {"state": "TASK_STATE_COMPLETED",
                         "message": {"parts": [{"text": "done"}]}}}}):
            target = self.paired(Reply(ok=True, payload=payload, http_status=200),
                                 Reply(ok=True, payload=payload, http_status=200))
            self.assertEqual(checks_auth.check_auth_intask_001(target).verdict, Verdict.NOT_APPLICABLE)
            self.assertEqual(checks_auth.check_auth_intask_003(target).verdict, Verdict.NOT_APPLICABLE)
        payload = {"task": {"id": "t", "status": {"state": "TASK_STATE_AUTH_REQUIRED",
                   "message": {"parts": [{"text": "authorize the operation"}]}}}}
        target = self.paired(Reply(ok=True, payload=payload, http_status=200),
                             Reply(ok=True, payload=payload, http_status=200))
        self.assertEqual(checks_auth.check_auth_intask_001(target).verdict, Verdict.PASS)
        self.assertEqual(checks_auth.check_auth_intask_003(target).verdict, Verdict.PASS)
        del payload["task"]["id"]
        self.assertEqual(checks_auth.check_auth_intask_001(target).verdict, Verdict.FAIL)

    def test_in_task_authorization_checks_every_declared_binding(self):
        good = {"task": {"id": "t", "status": {"state": "TASK_STATE_AUTH_REQUIRED",
                "message": {"parts": [{"text": "authorize the operation"}]}}}}
        seen = []
        class Authorization:
            def __init__(self, name, payload):
                self.name, self.payload = name, payload
            def call(self, op, params, **kwargs):
                seen.append(self.name)
                return Reply(ok=True, payload=self.payload, http_status=200)
        checks = (checks_auth.check_auth_intask_001, checks_auth.check_auth_intask_002,
                  checks_auth.check_auth_intask_003)
        target = _two_binding_target({name: Authorization(name, good) for name in ("jsonrpc", "http_json")})
        for check in checks:
            seen.clear()
            self.assertEqual(check(target).verdict, Verdict.PASS)
            self.assertEqual(seen, ["jsonrpc", "http_json"])
        mutations = [copy.deepcopy(good) for _ in checks]
        del mutations[0]["task"]["id"]
        mutations[1]["task"]["status"]["state"] = "TASK_STATE_COMPLETED"
        del mutations[2]["task"]["status"]["message"]
        for check, broken in zip(checks, mutations):
            target.bindings = lambda: {"jsonrpc": Authorization("jsonrpc", good),
                                       "http_json": Authorization("http_json", broken)}
            self.assertEqual(check(target).verdict, Verdict.FAIL)
        target.bindings = lambda: {"jsonrpc": Authorization("jsonrpc", good),
            "http_json": Authorization("http_json", {"message": {"parts": [{"text": "ordinary"}]}})}
        for check in checks:
            self.assertEqual(check(target).verdict, Verdict.NOT_APPLICABLE)

    def test_report_does_not_call_an_unmeasured_suite_successful(self):
        target = self.paired(Reply(ok=True, payload={}), Reply(ok=True, payload={}))
        with patch("builtins.print"):
            self.assertEqual(runner.report(target, [Result("AUTH-TLS-001", Verdict.NOT_APPLICABLE,
                                                          "no applicable fixture", [])], None), 3)
            self.assertEqual(runner.report(target, [Result("AUTH-TLS-001", Verdict.PASS,
                                                          "observed", [])], None), 0)
            self.assertEqual(runner.report(target, [Result("AUTH-TLS-001", Verdict.FAIL,
                                                          "refused", [])], None), 1)

    def test_target_runner_preserves_all_suite_exit_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            here = root / "testing/a2a-supplement"
            here.mkdir(parents=True)
            shutil.copyfile(Path(__file__).with_name("run-supplement.sh"), here / "run-supplement.sh")
            # Exercise the real wrapper with its real sourced dependency, as
            # the installed testing tree does; an absent source exits before
            # the fake suite can supply the exit class being tested.
            scripts = root / "testing/a2a-harness/scripts"
            scripts.mkdir(parents=True)
            shutil.copyfile(Path(__file__).resolve().parents[1] /
                            "a2a-harness/scripts/process-fixture.sh",
                            scripts / "process-fixture.sh")
            tck = root / "testing/a2a-tck"
            tck.mkdir()
            interpreter = root / "suite-python"
            interpreter.write_text('#!/bin/sh\nexit "$FAKE_SUITE_RC"\n')
            interpreter.chmod(0o700)
            prepare = tck / "run-tck.sh"
            prepare.write_text('#!/bin/sh\nprintf "A2A_TCK_DIR=%s\\nA2A_TCK_PYTHON=%s\\n" "$FAKE_ROOT" "$FAKE_ROOT/suite-python"\n')
            prepare.chmod(0o700)
            env = dict(os.environ, FAKE_ROOT=str(root), A2A_TCK_WORK=str(root / "work"))
            for code in (0, 1, 3):
                env["FAKE_SUITE_RC"] = str(code)
                completed = subprocess.run(["bash", str(here / "run-supplement.sh"), "target",
                                            "https://subject.invalid/card"], env=env,
                                           capture_output=True, text=True)
                self.assertEqual(completed.returncode, code, completed.stderr)

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
