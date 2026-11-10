"""The thing under test.

A Target is described entirely by configuration. There are no per-implementation
branches anywhere in this harness, and there must never be one. If a subject
needs special handling to be testable, that is a finding about the protocol
being underspecified, and it belongs in the report, not in an if-statement.

A target is given as either:

  --endpoint URL          an already-running agent
  --launch "CMD"          a command the harness starts and stops, plus
                          --port to know when it is up

Everything else the harness needs, it learns from the agent card, exactly as
any other client would.
"""

import json
import os
import shlex
import signal
import subprocess
import tempfile
import time
import urllib.parse

from . import spec, transport
from .process_fixture import owns_listener


class TargetError(Exception):
    pass


class Target:
    def __init__(self, endpoint=None, launch=None, port=None, host="127.0.0.1",
                 card_url=None, auth_header=None, ca_file=None,
                 launch_ready_seconds=45.0, label="target", cwd=None,
                 env=None):
        self.label = label
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.launch = launch
        self.port = port
        self.host = host
        self.card_url_override = card_url
        self.auth_header = auth_header
        self.ca_file = ca_file
        self.launch_ready_seconds = launch_ready_seconds
        self.cwd = cwd
        self.env = env
        self._proc = None
        self._log = None
        self._card = None
        self._card_response = None
        self._interface = None

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        if not self.launch:
            if not self.endpoint:
                raise TargetError(
                    "target '%s' has neither --endpoint nor --launch" % self.label
                )
            return
        if not self.port:
            raise TargetError(
                "target '%s' uses --launch so it must also give --port, "
                "otherwise the harness cannot tell when it is ready without "
                "sleeping, and sleeping is not a synchronisation primitive"
                % self.label
            )
        env = dict(os.environ)
        env.update(self.env or {})
        # The child's output goes to an unlinked temporary file, never a pipe:
        # nobody reads a pipe while the battery runs, so a target that logs
        # per request would fill the pipe buffer and block in its logger.
        self._log = tempfile.TemporaryFile()
        try:
            self._proc = subprocess.Popen(
                self.launch if isinstance(self.launch, list) else shlex.split(self.launch),
                cwd=self.cwd, env=env,
                stdout=self._log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except BaseException:
            self._log.close()
            self._log = None
            raise
        deadline = time.monotonic() + self.launch_ready_seconds
        ready = False
        # Observe exit without reaping: the reserved child PID also protects
        # its session/group identity until stop has finished signaling it.
        while time.monotonic() < deadline:
            if os.waitid(os.P_PID, self._proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                break
            if owns_listener(self._proc.pid, self.port, self.host):
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            out = self._drain()
            self.stop()
            raise TargetError(
                "target '%s' did not own a listener at %s:%s within %.0fs.\n"
                "launch command: %s\nprocess output:\n%s"
                % (self.label, self.host, self.port, self.launch_ready_seconds,
                   self.launch, out)
            )
        if not self.endpoint:
            self.endpoint = "http://%s:%s" % (self.host, self.port)

    def _drain(self):
        if not self._log:
            return "(no output captured)"
        try:
            self._log.seek(0, os.SEEK_END)
            self._log.seek(max(0, self._log.tell() - 65536))
            return (self._log.read(65536) or b"").decode("utf-8", "replace")
        except Exception:
            return "(output unavailable)"

    def stop(self):
        proc = self._proc
        if not proc:
            return
        # Keep the child unreaped while signaling its session. WNOWAIT reserves
        # the PID even if the leader exited; a recycled foreign group can never
        # inherit the numeric group id before our last signal.
        try:
            try:
                exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                # An outside caller already reaped it; numeric group custody
                # is gone, so do not signal that historical group id.
                exited = True
            else:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 10
                while not exited and time.monotonic() < deadline:
                    time.sleep(0.1)
                    exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
        finally:
            if self._log:
                self._log.close()
                self._log = None
            self._proc = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- discovery ---------------------------------------------------------

    def card_candidates(self):
        """Both readings of SPEC 8.2 for where the card lives.

        See spec.AMBIGUITIES['CARD_AT_INTERFACE_URL'].
        """
        if self.card_url_override:
            return [self.card_url_override]
        parts = urllib.parse.urlsplit(self.endpoint)
        origin = "%s://%s" % (parts.scheme, parts.netloc)
        out = [origin + spec.WELL_KNOWN_CARD_PATH]
        path = parts.path.rstrip("/")
        if path:
            out.append(origin + path + spec.WELL_KNOWN_CARD_PATH)
        return out

    def fetch_card_response(self, force=False, headers=None):
        if self._card_response is not None and not force and headers is None:
            return self._card_response
        last = None
        for url in self.card_candidates():
            resp = transport.request("GET", url, headers=self._headers(headers),
                                     ca_file=self.ca_file)
            last = resp
            if resp.status == 200 and resp.json_or_none() is not None:
                resp.card_url = url
                if headers is None:
                    self._card_response = resp
                return resp
        if last is not None:
            last.card_url = self.card_candidates()[0]
        return last

    def card(self, force=False):
        if self._card is not None and not force:
            return self._card
        resp = self.fetch_card_response(force=force)
        if resp is None or resp.status != 200:
            raise TargetError(
                "no agent card at any of %s (last status %s). SPEC 8.1: "
                "'A2A Servers MUST make an Agent Card available.'"
                % (self.card_candidates(), resp.status if resp else "no-response")
            )
        card = resp.json_or_none()
        if card is None:
            raise TargetError("agent card at %s is not JSON" % resp.card_url)
        self._card = card
        return card

    # -- binding selection -------------------------------------------------

    def interfaces(self):
        card = self.card()
        ifaces = card.get("supportedInterfaces")
        if not isinstance(ifaces, list):
            return []
        return [i for i in ifaces if isinstance(i, dict)]

    def pick_interface(self, binding=None):
        """SPEC 8.3.2: select the first supported transport, preferring
        earlier entries."""
        if self._interface and not binding:
            return self._interface
        for iface in self.interfaces():
            pb = iface.get("protocolBinding")
            if binding and pb != binding:
                continue
            if pb in ("JSONRPC", "HTTP+JSON"):
                if not binding:
                    self._interface = iface
                return iface
        if binding:
            return None
        # No usable interface declared. Fall back to the endpoint we were
        # given so that card-level tests can still report something useful.
        fallback = {"url": self.endpoint, "protocolBinding": "JSONRPC",
                    "protocolVersion": spec.PROTOCOL_VERSION,
                    "_synthesised_by_harness": True}
        self._interface = fallback
        return fallback

    def selection_metadata(self):
        """Report only an already-selected interface, without discovering again.

        Report writing happens after stop(), including when discovery or the
        battery failed. It must neither fetch a card nor hide those results
        behind a fresh selection exception.
        """
        return dict(self._interface) if isinstance(self._interface, dict) else None

    def _headers(self, extra=None, version=spec.PROTOCOL_VERSION):
        h = {}
        if version:
            # SPEC 3.6.1: "Clients MUST send the A2A-Version header with each
            # request". The harness is a client, so the harness complies.
            h[spec.VERSION_HEADER] = version
        if self.auth_header:
            name, _, value = self.auth_header.partition(":")
            h[name.strip()] = value.strip()
        h.update(extra or {})
        return h

    def request_headers(self, extra=None, version=spec.PROTOCOL_VERSION):
        """The headers a CLIENT OF THIS TARGET sends on any request.

        Public because several tests post raw bytes past `call()` -- a
        truncated body, a request with no `jsonrpc` member -- and those are
        still requests from the same client. Built by hand they arrived
        anonymously, and a target that requires authentication answers an
        anonymous request from its auth layer, before its parser has seen a
        byte. The test then reports on the wrong component: not "the agent
        faulted on malformed input" but "the agent asked who I was", which is
        a different question and one `tests_auth` asks on purpose.

        Nothing here decides WHETHER to authenticate. It attaches the
        credential the harness was given (`--auth`) and nothing else, so a
        target that needs none is unaffected.
        """
        return self._headers(extra, version)

    # -- calling -----------------------------------------------------------

    def call(self, method, params=None, iface=None, headers=None,
             version=spec.PROTOCOL_VERSION, raw=False):
        """Invoke an A2A operation over whichever binding the card declares.

        Returns a Call with .ok, .result, .error_code, .error_name, .http.
        """
        iface = iface or self.pick_interface()
        binding = iface.get("protocolBinding")
        if binding == "JSONRPC":
            return self._call_jsonrpc(iface, method, params, headers, version)
        if binding == "HTTP+JSON":
            return self._call_rest(iface, method, params, headers, version)
        raise TargetError(
            "binding %r is not drivable by this harness (only JSONRPC and "
            "HTTP+JSON are). GRPC targets are reported as untested." % binding
        )

    def _call_jsonrpc(self, iface, method, params, headers, version):
        body = {"jsonrpc": "2.0", "id": _next_id(), "method": method}
        if params is not None:
            body["params"] = params
        resp = transport.request(
            "POST", iface["url"], body=body,
            headers=self._headers(headers, version),
            ca_file=self.ca_file)
        return Call.from_jsonrpc(resp, method, body)

    def _call_rest(self, iface, method, params, headers, version):
        params = params or {}
        verb, template = spec.REST_ROUTES[method]
        path = template
        query = {}
        body = None
        if method in ("SendMessage", "SendStreamingMessage"):
            body = params
        elif method == "GetTask":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("id", ""))))
            if params.get("historyLength") is not None:
                query["historyLength"] = params["historyLength"]
        elif method == "CancelTask":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("id", ""))))
            body = {k: v for k, v in params.items() if k != "id"}
        elif method == "ListTasks":
            query = {k: v for k, v in params.items() if v is not None}
        elif method in ("CreateTaskPushNotificationConfig",):
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
            body = params
        elif method in ("GetTaskPushNotificationConfig",
                        "DeleteTaskPushNotificationConfig"):
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
            path = path.replace("{configId}", urllib.parse.quote(str(params.get("id", ""))))
        elif method == "ListTaskPushNotificationConfigs":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
        url = iface["url"].rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        hdrs = self._headers(headers, version)
        if body is not None:
            hdrs.setdefault("Content-Type", spec.MEDIA_TYPE_A2A_JSON)
        resp = transport.request(verb, url, body=body, headers=hdrs,
                                 ca_file=self.ca_file)
        return Call.from_rest(resp, method, body)

    def stream(self, method, params=None, iface=None, headers=None,
               version=spec.PROTOCOL_VERSION, **kw):
        iface = iface or self.pick_interface()
        binding = iface.get("protocolBinding")
        hdrs = self._headers(headers, version)
        if binding == "JSONRPC":
            rid = _next_id()
            body = {"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}}
            # SPEC 9.4.2 shows each SSE frame under the JSON-RPC binding as a
            # full JSON-RPC envelope wrapping a StreamResponse in `result`:
            #   data: {"jsonrpc": "2.0", "id": 1, "result": {...}}
            # so `stop_after` and the tests must see the unwrapped payload.
            inner_stop = kw.pop("stop_after", None)
            if inner_stop:
                kw["stop_after"] = lambda ev: inner_stop(_unwrap_rpc(ev))
            res = transport.sse_events(iface["url"], body=body, headers=hdrs,
                                       ca_file=self.ca_file, **kw)
            res.envelopes = list(res.events)
            res.envelope_problems = _envelope_problems(res.envelopes, rid)
            res.events = [_unwrap_rpc(ev) for ev in res.events]
            return res
        if binding == "HTTP+JSON":
            if method == "SendStreamingMessage":
                url = iface["url"].rstrip("/") + "/message:stream"
                return transport.sse_events(url, body=params or {},
                                            headers=hdrs,
                                            ca_file=self.ca_file, **kw)
            if method == "SubscribeToTask":
                # Both readings of the verb. See AMBIGUITIES.
                url = (iface["url"].rstrip("/") + "/tasks/"
                       + urllib.parse.quote(str((params or {}).get("id", "")))
                       + ":subscribe")
                res = transport.sse_events(url, body=None, headers=hdrs,
                                           method="GET",
                                           ca_file=self.ca_file, **kw)
                if res.status in (404, 405, 501):
                    res2 = transport.sse_events(url, body={}, headers=hdrs,
                                                method="POST",
                                                ca_file=self.ca_file, **kw)
                    res2.verb_used = "POST"
                    return res2
                res.verb_used = "GET"
                return res
        raise TargetError("binding %r not drivable for streaming" % binding)

    def capability(self, name):
        caps = self.card().get("capabilities") or {}
        return bool(caps.get(name))


_counter = [0]


def _next_id():
    _counter[0] += 1
    return _counter[0]


def _unwrap_rpc(event):
    """Strip the JSON-RPC envelope from an SSE frame, per SPEC 9.4.2.

    An error frame is passed through untouched so tests can see it; only a
    `result` member is unwrapped.
    """
    if isinstance(event, dict) and event.get("jsonrpc") == "2.0":
        if "result" in event:
            return event["result"]
    return event


def _envelope_problems(envelopes, request_id):
    """Check the JSON-RPC framing of a stream, which SPEC 9.4.2 fixes."""
    problems = []
    for i, ev in enumerate(envelopes):
        if not isinstance(ev, dict):
            problems.append("frame %d is not a JSON object" % i)
            continue
        if ev.get("jsonrpc") != "2.0":
            problems.append(
                "frame %d has jsonrpc=%r, expected '2.0' (SPEC 9.4.2)"
                % (i, ev.get("jsonrpc")))
        if "result" not in ev and "error" not in ev:
            problems.append(
                "frame %d carries neither result nor error (SPEC 9.4.2)" % i)
        if "error" not in ev and ev.get("id") != request_id:
            problems.append(
                "frame %d has id=%r but the request id was %r; a client "
                "cannot correlate the stream (JSON-RPC 2.0)"
                % (i, ev.get("id"), request_id))
    return problems


class Call:
    def __init__(self, http, method, request_body, result=None, error=None,
                 binding=None):
        self.http = http
        self.method = method
        self.request_body = request_body
        self.result = result
        self.error = error
        self.binding = binding

    @property
    def ok(self):
        return self.error is None and self.result is not None

    @property
    def error_code(self):
        if not self.error:
            return None
        return self.error.get("code")

    @property
    def error_name(self):
        """Best-effort A2A error name, from whichever channel carries it."""
        if not self.error:
            return None
        code = self.error.get("code")
        if code in spec.JSONRPC_CODE_TO_ERROR:
            return spec.JSONRPC_CODE_TO_ERROR[code]
        if code in spec.JSONRPC_STANDARD_ERRORS:
            return spec.JSONRPC_STANDARD_ERRORS[code]
        for detail in self.error_details():
            if detail.get("@type", "").endswith("google.rpc.ErrorInfo"):
                reason = detail.get("reason")
                if reason:
                    return reason
        return None

    def error_details(self):
        if not self.error:
            return []
        for key in ("data", "details"):
            value = self.error.get(key)
            if isinstance(value, list):
                return [d for d in value if isinstance(d, dict)]
        return []

    @classmethod
    def from_jsonrpc(cls, resp, method, body):
        payload = resp.json_or_none()
        if not isinstance(payload, dict) or ("result" not in payload
                                             and "error" not in payload):
            # No JSON-RPC response object (a refused connection's synthetic
            # 599, an HTML or empty 4xx/5xx) is never a success: report the
            # HTTP status as the error, as from_rest does.
            return cls(resp, method, body, binding="JSONRPC",
                       error={"code": resp.status,
                              "message": "no JSON-RPC response object "
                                         "(HTTP %s)" % resp.status})
        return cls(resp, method, body, result=payload.get("result"),
                   error=payload.get("error"), binding="JSONRPC")

    @classmethod
    def from_rest(cls, resp, method, body):
        payload = resp.json_or_none()
        if resp.status >= 400:
            err = None
            if isinstance(payload, dict):
                err = payload.get("error") if isinstance(payload.get("error"), dict) else payload
            return cls(resp, method, body, error=err or {"code": resp.status},
                       binding="HTTP+JSON")
        return cls(resp, method, body, result=payload, binding="HTTP+JSON")


def user_message(text, message_id=None, task_id=None, context_id=None):
    """A minimally valid Message per PROTO Message required fields."""
    import uuid
    msg = {
        "messageId": message_id or str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"text": text}],
    }
    if task_id:
        msg["taskId"] = task_id
    if context_id:
        msg["contextId"] = context_id
    return msg


def send_params(text=None, message=None, **config):
    params = {"message": message if message is not None else user_message(text or "ping")}
    if config:
        params["configuration"] = {k: v for k, v in config.items() if v is not None}
    return params
