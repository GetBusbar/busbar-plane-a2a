#!/usr/bin/env python3
"""Regression controls for byte framing and the harness's actual wire probes."""
import io
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from a2aht import cli, jcs, runner, spec, tests_adversarial, tests_card, tests_client, tests_core, tests_hostile, transport
from a2aht.model import NotConfigured
from a2aht.target import Call, Target
from a2aht.fakes import FakePeer


class Context:
    config = {"nesting_depth": 2000}

    def observe(self, *_):
        pass

    def note(self, *_):
        pass

    def assert_must(self, condition, *detail):
        if not condition:
            raise AssertionError(detail)


class ProtocolRegressions(unittest.TestCase):
    def test_failed_discovery_does_not_break_report_metadata(self):
        target = Target(endpoint="http://fixture.invalid")
        target._card = []  # reachable JSON, but not a usable AgentCard
        row = {"id": "card.served", "outcome": "ERROR", "assertions": 0,
               "role": "server", "clause": "fixture", "defect": "fixture",
               "detail": "malformed card", "observations": {}, "notes": []}
        result = SimpleNamespace(outcome="ERROR", to_dict=lambda: row)
        test = SimpleNamespace(role="server", tier="every-commit")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(cli, "build_target", return_value=target), \
             patch.object(cli, "_preflight", return_value=None), \
             patch.object(runner, "load_tests", return_value=[test]), \
             patch.object(runner, "run_battery", return_value=[result]):
            path = Path(directory) / "report.json"
            with patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                self.assertEqual(cli.main(["run", "--endpoint", target.endpoint,
                                           "--json", str(path)]), 1)
            report = json.loads(path.read_text())
            self.assertEqual(report["results"][0]["outcome"], "ERROR")
            self.assertIsNone(report["meta"]["selected_interface"])

    def test_binding_coverage_reports_unselected_interfaces_even_when_drivable(self):
        ctx = Context()
        selected = {"url": "http://one/a2a", "protocolBinding": "JSONRPC"}
        second = {"url": "http://two/a2a", "protocolBinding": "HTTP+JSON"}
        observed = {}
        calls = []
        ctx.observe = lambda key, value, *rest: observed.__setitem__(key, value)
        def call(method, params, iface):
            calls.append(iface)
            return SimpleNamespace(ok=True)
        ctx.target = SimpleNamespace(interfaces=lambda: [selected],
                                     pick_interface=lambda: selected, call=call)
        tests_card.test_all_bindings_driven(ctx)
        self.assertEqual(observed["interfaces_not_exercised"], [])
        self.assertEqual(calls, [selected])
        for other in (second, dict(second, protocolBinding="JSONRPC"),
                      dict(second, protocolBinding="GRPC")):
            ctx.target.interfaces = lambda: [selected, other]
            ctx.config = {"allow_undriven_bindings": "HTTP+JSON,JSONRPC,GRPC"}
            with self.assertRaises(NotConfigured):
                tests_card.test_all_bindings_driven(ctx)
            self.assertEqual(observed["interfaces_not_exercised"][0]["url"], other["url"])
            self.assertEqual(observed["selected_interface_operation"]["ok"], True)
        ctx.target.interfaces = lambda: [selected]
        ctx.target.call = lambda *a, **k: SimpleNamespace(ok=False)
        with self.assertRaises(AssertionError):
            tests_card.test_all_bindings_driven(ctx)
        ctx.target.interfaces = lambda: []
        with self.assertRaises(NotConfigured):
            tests_card.test_all_bindings_driven(ctx)

    def test_differential_requires_complete_asserted_subject_evidence(self):
        def report():
            return {"target": "fixture", "spec": {"tag": "v1.0.1"}, "results": [
                {"id": "fixture.%d" % i, "outcome": "PASS", "assertions": 1,
                 "observations": {}, "clause": "fixture", "defect": "fixture",
                 "detail": ""} for i in range(10)]}
        control = report()
        def fails(subject, ctl=control):
            diff = runner.differential(ctl, subject)
            output = io.StringIO()
            self.assertGreater(runner.print_differential(diff, output), 0)
            self.assertNotIn("NO DEFECTS", output.getvalue())
            return diff
        self.assertEqual(runner.print_differential(
            runner.differential(control, report()), io.StringIO()), 0)
        subject = report()
        subject["results"] = []
        fails(subject)
        for outcome in ("NOT_CONFIGURED", "DEVIATION_CHANGED", "DEVIATION_FIXED"):
            subject = report()
            subject["results"][0]["outcome"] = outcome
            fails(subject)
        subject = report()
        subject["results"][0].update(id="core.get_task_roundtrip", outcome="INAPPLICABLE")
        fails(subject)
        subject = report()
        subject["results"].append(dict(subject["results"][0]))
        fails(subject)
        subject = report()
        subject["spec"]["tag"] = "different"
        fails(subject)
        subject = report()
        for row in subject["results"]:
            row["assertions"] = 0
        fails(subject)
        subject = report()
        subject["results"][0].update(id="missing.from.control", outcome="FAIL")
        self.assertEqual(len(fails(subject)["defects"]), 1)
        red_control = report()
        red_control["results"][0]["outcome"] = "FAIL"
        self.assertEqual(fails(report(), red_control)["defects"], [])
        for label in ("control", "subject"):
            unknown = report()
            unknown["results"][0]["outcome"] = "UNKNOWN"
            fails(unknown if label == "subject" else report(),
                  unknown if label == "control" else control)

    def test_discovery_query_is_not_counted_as_an_operation(self):
        import urllib.request
        with FakePeer() as peer:
            with urllib.request.urlopen(peer.base_url + spec.WELL_KNOWN_CARD_PATH + "?A2A-Version=1.0") as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(peer.card_fetches, 1)
            self.assertEqual(peer.a2a_requests(), [])

    def test_noop_drive_cannot_pass_a_client_probe(self):
        ctx = Context()
        ctx.config = {"client_drive": "client --agent {url}"}
        peer = SimpleNamespace(base_url="http://fixture.invalid", requests=[])
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with patch.object(tests_client.subprocess, "run", return_value=completed):
            with self.assertRaises(NotConfigured):
                tests_client.drive(ctx, peer)
        def traffic(*args, **kwargs):
            peer.requests.append({"path": "/a2a"})
            return completed
        with patch.object(tests_client.subprocess, "run", side_effect=traffic):
            self.assertEqual(tests_client.drive(ctx, peer)["returncode"], 0)

    def test_verifier_rejects_critical_extensions_and_algorithm_confusion(self):
        tests_hostile.test_jws_self_check(Context())
        payload = jcs.canonicalize({"name": "probe"})
        key = {"kid": "k", "kty": "EC", "crv": "P-256", "alg": "ES256"}
        header = {"kid": "k", "alg": "ES256"}
        with patch.object(jcs, "_verify", return_value=True) as verify:
            self.assertTrue(jcs.verify_jws(jcs.make_signature(header, payload), payload, [key])["verified"])
            header["crit"] = ["unknown"]
            self.assertFalse(jcs.verify_jws(jcs.make_signature(header, payload), payload, [key])["verified"])
            self.assertEqual(verify.call_count, 1)

    def test_operator_key_verifies_a_real_ed25519_signature(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        private = Ed25519PrivateKey.generate()
        key = {"kid": "operator", "kty": "OKP", "crv": "Ed25519",
               "x": jcs.b64url_encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}
        payload = jcs.canonicalize({"name": "real signature"})
        signature = jcs.make_signature({"kid": "operator", "alg": "EdDSA"}, payload)
        message = signature["protected"] + "." + jcs.b64url_encode(payload.encode())
        signature["signature"] = jcs.b64url_encode(private.sign(message.encode()))
        self.assertTrue(jcs.verify_jws(signature, payload, [key])["verified"])
        self.assertFalse(jcs.verify_jws(signature, payload + " ", [key])["verified"])

    def test_silent_stream_socket_timeout_is_reported_as_timeout(self):
        class Silent:
            status = 200
            headers = {"Content-Type": "text/event-stream"}
            def read(self, size):
                raise TimeoutError("timed out")
            def close(self):
                pass
        with patch.object(transport, "_opener", return_value=SimpleNamespace(open=lambda *a, **k: Silent())):
            result = transport.sse_events("http://example.invalid/")
        self.assertEqual(result.error, "timeout")
        self.assertFalse(result.closed_cleanly)

    def test_version_and_stream_probes_refuse_errors_as_success(self):
        ctx = Context()
        call = SimpleNamespace(error={"code": -32603}, error_code=-32603,
                               error_name=None, binding="JSONRPC", http=SimpleNamespace(status=200))
        ctx.target = SimpleNamespace(interfaces=lambda: [{"protocolVersion": "1.0"}],
                                     call=lambda *a, **k: call)
        with self.assertRaises(AssertionError):
            tests_core.test_version_negotiation(ctx)
        with self.assertRaises(AssertionError):
            tests_core.test_absent_version_header(ctx)
        call.error_code = -32009
        tests_core.test_version_negotiation(ctx)
        tests_core.test_absent_version_header(ctx)
        response = SimpleNamespace(events=[{"error": {"code": -32004}}], error=None,
                                   status=200, content_type="text/event-stream")
        ctx.target = SimpleNamespace(capability=lambda name: True, stream=lambda *a, **k: response)
        with self.assertRaises(AssertionError):
            tests_core.test_streaming_capability(ctx)
        ctx.target.capability = lambda name: False
        tests_core.test_streaming_capability(ctx)
        for events, error, status in (([], "timeout", None), ([], "http-error", 500),
                                      ([], "ConnectionResetError: reset", None),
                                      ([{"error": {"code": -32603}}], None, 200),
                                      ([{"error": {"code": -32004}}], "timeout", 200),
                                      ([{"error": {"code": -32004}}], "http-error", 500)):
            response.events, response.error, response.status = events, error, status
            with self.subTest(events=events, error=error, status=status):
                with self.assertRaises(AssertionError):
                    tests_core.test_streaming_capability(ctx)
        response.events = [{"error": {"code": 400, "details": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo", "domain": "a2a-protocol.org",
            "reason": "UNSUPPORTED_OPERATION"}]}}]
        response.error, response.status = "http-error", 400
        tests_core.test_streaming_capability(ctx)
        response.error, response.status = None, 200
        response.events = [{"message": {"parts": [{"text": "ok"}]}}]
        with self.assertRaises(AssertionError):
            tests_core.test_streaming_capability(ctx)
        ctx.target.capability = lambda name: True
        tests_core.test_streaming_capability(ctx)

    def test_battery_credential_reaches_headers_only_when_present(self):
        source_root = Path(__file__).resolve().parents[3]
        boot = source_root / "testing/a2a-subject/boot.sh"
        definitions, separator, _ = boot.read_text().rpartition('\ncase "${1:-}" in\n')
        self.assertTrue(separator, "boot command dispatcher was not found")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = root / "testing/a2a-subject"
            subject.mkdir(parents=True)
            (root / "testing/a2a-harness").mkdir()
            script = subject / "boot.sh"
            script.write_text(definitions + '''
boot_busbar_a2a_subject() {
  SUBJECT_URL="http://fixture.invalid/a2a"
  SUBJECT_AGENT_URL="$SUBJECT_URL"
  SUBJECT_TOKEN="$FIXTURE_TOKEN"
}
if [ "${FAIL_BATTERY_CD:-}" = 1 ]; then
  cd() { return 9; }
fi
leg_battery
''')
            shim_dir = root / "bin"
            shim_dir.mkdir()
            shim = shim_dir / "python3"
            shim.write_text("#!" + sys.executable + "\n" + '''
import argparse, json, os, sys
from pathlib import Path
''' + "sys.path.insert(0, %r)\n" % str(source_root / "testing/a2a-harness") + '''
from a2aht import cli
parser = argparse.ArgumentParser()
cli._target_args(parser)
args, _ = parser.parse_known_args(sys.argv[1:])
target = cli.build_target(args)
Path(os.environ["HEADER_CAPTURE"]).write_text(json.dumps({
    "headers": target._headers(), "argv": sys.argv[1:]}))
''')
            shim.chmod(0o700)
            capture = root / "headers.json"
            for token in ("", "fixture-credential"):
                env = dict(os.environ, PATH=str(shim_dir) + os.pathsep + os.environ["PATH"],
                           HEADER_CAPTURE=str(capture), FIXTURE_TOKEN=token,
                           A2A_SUBJECT_BUSBAR_BIN="fixture" if token else "",
                           BUSBAR_A2A_ENDPOINT="http://fixture.invalid/a2a")
                completed = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                observed = json.loads(capture.read_text())
                authorization = {key.lower(): value for key, value in observed["headers"].items()}.get("authorization")
                self.assertEqual(authorization, "Bearer " + token if token else None)
                self.assertEqual("--auth-file" in observed["argv"], bool(token))
                if token:
                    self.assertNotIn(token, " ".join(observed["argv"]))
            capture.unlink()
            env["FAIL_BATTERY_CD"] = "1"
            completed = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(capture.exists(), "a failed working-directory change must not invoke the battery")

    def test_history_limit_is_checked_against_a_long_transcript(self):
        ctx = Context()
        class History:
            def __init__(self, ignore=False, reject_zero=False, short=False):
                self.ignore, self.reject_zero, self.short = ignore, reject_zero, short
                self.messages = []
                self.requests = []
            def call(self, method, params):
                self.requests.append((method, params))
                if method == "SendMessage":
                    self.messages.append(params["message"])
                history = copy.deepcopy(self.messages[:1] if self.short else self.messages)
                if params.get("historyLength") == 0:
                    if self.reject_zero:
                        return SimpleNamespace(error={"code": -32602}, result=None)
                    history = []
                elif params.get("historyLength") == 1 and not self.ignore:
                    history = history[-1:]
                return SimpleNamespace(error=None, result={"task": {"id": "t", "status": {
                    "state": "TASK_STATE_INPUT_REQUIRED"}}} if method == "SendMessage" else
                    {"id": "t", "history": history})
        good = History()
        ctx.target = good
        tests_core.test_history_length(ctx)
        continued = [params["message"] for method, params in good.requests if method == "SendMessage"]
        self.assertEqual(len(continued), 2)
        self.assertEqual(continued[1]["taskId"], "t")
        for target in (History(ignore=True), History(reject_zero=True)):
            ctx.target = target
            with self.assertRaises(AssertionError):
                tests_core.test_history_length(ctx)
        from a2aht.model import Inapplicable
        ctx.target = History(short=True)
        with self.assertRaises(Inapplicable):
            tests_core.test_history_length(ctx)

    def test_ghost_resources_require_the_defined_not_found_error(self):
        ctx = Context()
        seen = []
        def call(method, params):
            seen.append(method)
            return Call(SimpleNamespace(status=200), method, params,
                        error={"code": -32001}, binding="JSONRPC")
        ctx.target = SimpleNamespace(call=call, capability=lambda name: True)
        tests_adversarial.test_response_to_nothing(ctx)
        self.assertIn("ListTaskPushNotificationConfigs", seen)
        for code in (-32603, -32003, 401):
            ctx.target.call = lambda method, params: Call(SimpleNamespace(status=500), method, params,
                                                         error={"code": code}, binding="JSONRPC")
            with self.assertRaises(AssertionError):
                tests_adversarial.test_response_to_nothing(ctx)
        ctx.target.call = call
        ctx.target.capability = lambda name: False
        seen.clear()
        tests_adversarial.test_response_to_nothing(ctx)
        self.assertEqual(seen, ["CancelTask", "GetTask"])
        ctx.target.capability = lambda name: True
        for reason in ("TASK_NOT_FOUND", "PUSH_NOTIFICATION_NOT_SUPPORTED", None):
            error = {"code": 404, "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                      "domain": "a2a-protocol.org", "reason": reason}]}
            ctx.target.call = lambda method, params: Call(SimpleNamespace(status=404), method, params,
                                                         error=error, binding="HTTP+JSON")
            if reason == "TASK_NOT_FOUND":
                tests_adversarial.test_response_to_nothing(ctx)
            else:
                with self.assertRaises(AssertionError):
                    tests_adversarial.test_response_to_nothing(ctx)

    def test_card_parser_self_check_requires_acceptance_and_independent_mutations(self):
        from a2aht import validate
        card = {"name": "control", "description": "valid", "version": "1.0", "capabilities": {},
                "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
                "supportedInterfaces": [{"url": "https://agent.invalid", "protocolBinding": "JSONRPC",
                                         "protocolVersion": "1.0"}],
                "skills": [{"id": "echo", "name": "Echo", "description": "echo", "tags": ["echo"]}]}
        ctx = Context()
        ctx.target = SimpleNamespace(card=lambda: card)
        tests_card.test_validator_self_check(ctx)
        with patch.object(validate, "validate_agent_card", return_value=(False, ["rejected"])):
            with self.assertRaises(AssertionError):
                tests_card.test_validator_self_check(ctx)
        with patch.object(spec, "AGENT_CARD_REQUIRED", tuple(
                field for field in spec.AGENT_CARD_REQUIRED if field != "description")):
            with self.assertRaises(AssertionError):
                tests_card.test_validator_self_check(ctx)
        with patch.object(spec, "AGENT_INTERFACE_REQUIRED", ("url", "protocolBinding")):
            with self.assertRaises(AssertionError):
                tests_card.test_validator_self_check(ctx)

    def test_liveness_probe_requires_successful_operation(self):
        ctx = Context()
        ctx.target = SimpleNamespace(call=lambda *a: SimpleNamespace(error={"code": -32603},
                                                                     http=SimpleNamespace(status=200)))
        with patch.object(tests_adversarial, "_post_raw", return_value=SimpleNamespace(status=400)), \
             patch.object(tests_adversarial, "_binding", return_value="JSONRPC"), \
             patch.object(tests_adversarial, "_survived"):
            with self.assertRaises(AssertionError):
                tests_adversarial.test_deep_nesting(ctx)

    def test_required_card_fields_are_set_and_recommended_version_shape_is_not_a_must(self):
        ctx = Context()
        card = {name: "set" for name in spec.AGENT_CARD_REQUIRED}
        ctx.target = SimpleNamespace(card=lambda: card,
                                     interfaces=lambda: [{"protocolVersion": "1.0.1"}])
        tests_card.test_card_required_fields(ctx)
        for value in (None, ""):
            card["name"] = value
            with self.assertRaises(AssertionError):
                tests_card.test_card_required_fields(ctx)
        tests_card.test_card_version_shape(ctx)

    def test_signature_attack_cards_address_the_peer_that_is_still_running(self):
        observed = {}
        ctx = Context()
        ctx.observe = lambda name, value, *rest: observed.__setitem__(name, value)
        class Peer:
            count = 0
            def __init__(self, behaviour=None):
                Peer.count += 1
                self.base_url = "http://peer-%d.test" % Peer.count
                self.behaviour = behaviour or SimpleNamespace(card_body_override=None)
                self.running = False
                self.calls = 0
            def __enter__(self):
                self.running = True
                return self
            def __exit__(self, *_):
                self.running = False
            def card(self):
                return self.behaviour.card_body_override or {
                    "supportedInterfaces": [{"url": self.base_url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}
            def a2a_requests(self):
                return [{}] * self.calls
        def drive(ctx, peer, **kwargs):
            self.assertTrue(peer.running)
            self.assertEqual(peer.card()["supportedInterfaces"][0]["url"], peer.base_url)
            peer.calls += 1
            return dict(returncode=0, timed_out=False, stdout="", stderr="")
        with patch.object(tests_hostile, "FakePeer", Peer), patch.object(tests_hostile, "drive", drive):
            tests_hostile.test_card_signature_attacks(ctx)
            tests_hostile.test_signature_downgrade(ctx)
        self.assertEqual(observed["calls_against_badly_signed_card"], 1)
        self.assertEqual(observed["calls_against_unsigned_card"], 1)

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
            body = json.loads(events[1])
            self.assertEqual(body["method"], "SendMessage")
            self.assertIn("message", body["params"])
            self.assertIn(b"authorization: Bearer fixture\r\n", events[0])
            self.assertIn(b"A2A-Version: 1.0\r\n", events[0])
            self.assertIn(b"Content-Type: application/a2a+json\r\n", events[0])
            self.assertNotIn("closed", events)
            events.append("healthy")
            return SimpleNamespace(error=None, http=None)
        ctx = Context()
        ctx.target = SimpleNamespace(insecure=False, call=healthy,
            request_headers=lambda extra: dict(extra, **{
                "authorization": "Bearer fixture", "A2A-Version": "1.0"}))
        with patch.object(transport, "_connect", return_value=(Socket(), "localhost", "/")), \
             patch.object(tests_adversarial, "_endpoint", return_value="http://localhost/"), \
             patch.object(tests_adversarial, "_binding", return_value="JSONRPC"):
            tests_adversarial.test_connect_and_stall(ctx)
        self.assertLess(events.index("healthy"), events.index("closed"))

    def test_truncated_probe_preserves_auth_version_and_binding_envelope(self):
        ctx = Context()
        ctx.target = SimpleNamespace(insecure=False,
            call=lambda *a: SimpleNamespace(error=None, http=None),
            request_headers=lambda extra: dict(extra, **{
                "authorization": "Bearer fixture", "A2A-Version": "1.0"}))
        for binding in ("JSONRPC", "HTTP+JSON"):
            with patch.object(tests_adversarial, "_endpoint", return_value="http://fixture/a2a"), \
                 patch.object(tests_adversarial, "_binding", return_value=binding), \
                 patch.object(transport, "raw_send", return_value=b"") as send:
                tests_adversarial.test_truncated_body(ctx)
            args, kwargs = send.call_args
            body = json.loads(args[2])
            self.assertEqual(kwargs["headers"]["authorization"], "Bearer fixture")
            self.assertEqual(kwargs["headers"]["A2A-Version"], "1.0")
            self.assertGreater(kwargs["declared_length"], len(args[2]))
            self.assertLess(kwargs["send_bytes"], len(args[2]))
            if binding == "JSONRPC":
                self.assertEqual(body["jsonrpc"], "2.0")
                self.assertEqual(body["method"], "SendMessage")
                self.assertIn("message", body["params"])
            else:
                self.assertTrue(args[0].endswith("/message:send"))
                self.assertIn("message", body)

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
