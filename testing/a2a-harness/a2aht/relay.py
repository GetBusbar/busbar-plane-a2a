"""Harness-owned causal relay observation; adapters only configure delegation.

See RELAY-DRIVE.md. This bounded, unary profile refuses to infer a seam from
independent client traffic or adapter-reported responses.
"""

import json
import multiprocessing
import os
import shlex
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import spec, transport
from .model import NotConfigured
from .target import send_params
from .validate import validate_task


def _require(condition, message):
    if not condition:
        raise NotConfigured("correlated relay evidence refused: " + message)


def _send_requests(peer):
    return [
        request
        for request in peer.a2a_requests()
        if request["method"] == "POST"
        and (
            urlsplit(request["path"]).path.endswith("/message:send")
            or (
                isinstance(request["body"], dict)
                and request["body"].get("method") == "SendMessage"
            )
        )
    ]


def _text(parts):
    return "".join(
        part.get("text", "")
        for part in parts or []
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _upstream_worker(result_path, url, body, headers, timeout, ca_file):
    """Only this disposable process can block on the upstream socket."""
    response = transport.request(
        "POST", url, body=body, headers=headers, timeout=timeout, ca_file=ca_file
    )
    Path(result_path).write_text(
        json.dumps({"status": response.status, "text": response.text})
    )


def _bounded_upstream(url, body, headers, timeout, ca_file):
    # A private result file avoids a pipe's partial-message recv blocking after
    # poll(), or a full pipe deadlocking a worker joined before it is drained.
    with tempfile.TemporaryDirectory(prefix="a2aht-relay-") as directory:
        result_path = str(Path(directory) / "response.json")
        process = multiprocessing.get_context("spawn").Process(
            target=_upstream_worker,
            args=(result_path, url, body, headers, timeout, ca_file),
            daemon=True,
        )
        started = time.monotonic()
        process.start()
        try:
            process.join(max(0.0, timeout - (time.monotonic() - started)))
            elapsed = time.monotonic() - started
            _require(
                not process.is_alive() and elapsed < timeout,
                "upstream response exceeded the hard deadline",
            )
            _require(process.exitcode == 0, "upstream request worker failed")
            try:
                result = json.loads(Path(result_path).read_text())
            except (OSError, ValueError) as exc:
                raise NotConfigured(
                    "upstream worker produced no valid response"
                ) from exc
            return result["status"], result["text"], elapsed
        finally:
            if process.is_alive():
                process.terminate()
                process.join(1.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
            _require(not process.is_alive(), "upstream worker could not be reaped")
            process.close()


def correlated_relay(ctx, peer, timeout=20.0):
    """Configure target, then independently observe both sides of one call.

    A failed evidence precondition is NOT_CONFIGURED, not an invented protocol
    violation. Once correlated, the caller asserts actual identifier isolation.
    """
    template = ctx.config.get("relay_drive")
    _require(template, "no --relay-drive configuration command was supplied")
    # Split before substitution so substituted values remain single arguments.
    replacements = {
        "{url}": peer.base_url,
        "{card_url}": peer.base_url + spec.WELL_KNOWN_CARD_PATH,
        "{endpoint}": ctx.target.endpoint,
    }
    command = []
    for argument in shlex.split(template):
        for placeholder, value in replacements.items():
            argument = argument.replace(placeholder, value)
        command.append(argument)
    _require(command, "empty relay configuration command")
    env = dict(os.environ)
    env.update(ctx.config.get("env") or {})
    try:
        # No stdout report is accepted as evidence. Temporary file output is
        # unnecessary; discard it to bound even a verbose adapter's memory use.
        run = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            cwd=ctx.config.get("cwd"),
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise NotConfigured("relay configuration command timed out") from None
    except OSError as exc:
        raise NotConfigured(f"relay configuration command failed: {exc}") from exc
    _require(run.returncode == 0, f"configuration command returned {run.returncode}")
    _require(
        not peer.a2a_requests() and not peer.tasks,
        "configuration command generated operation traffic before the upstream call",
    )

    # Neither challenge is available to the adapter before it has exited.
    request_challenge = "relay-request-" + uuid.uuid4().hex
    response_challenge = "relay-response-" + uuid.uuid4().hex
    peer.behaviour.prompt_injection_text = response_challenge
    params = send_params(request_challenge, blocking=True)
    interface = ctx.target.pick_interface()
    binding = interface.get("protocolBinding")
    rpc_id = uuid.uuid4().hex
    if binding == "JSONRPC":
        url = interface["url"]
        body = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "SendMessage",
            "params": params,
        }
    elif binding == "HTTP+JSON":
        url = interface["url"].rstrip("/") + "/message:send"
        body = params
    else:
        raise NotConfigured("correlated relay supports HTTP+JSON and JSONRPC only")
    status, response_text, elapsed = _bounded_upstream(
        url, body, ctx.target.request_headers(), timeout, ctx.target.ca_file
    )
    _require(
        200 <= status < 300,
        f"upstream returned HTTP {status} (including transport timeout/failure)",
    )
    try:
        payload = json.loads(response_text, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as exc:
        raise NotConfigured(f"invalid upstream response JSON: {exc}") from exc
    _require(isinstance(payload, dict), "upstream response is not an object")
    if binding == "JSONRPC":
        _require(
            payload.get("jsonrpc") == "2.0"
            and payload.get("id") == rpc_id
            and "result" in payload
            and "error" not in payload,
            "upstream JSON-RPC response does not match its request",
        )
        payload = payload["result"]
    _require(isinstance(payload, dict), "upstream result is not an object")
    upstream = payload.get("task")
    try:
        valid, problems = validate_task(upstream)
    except (TypeError, AttributeError) as exc:
        raise NotConfigured(f"malformed upstream task: {exc}") from exc
    _require(valid, f"upstream task is malformed: {problems}")
    _require(
        upstream["status"]["state"] == "TASK_STATE_COMPLETED",
        "unary profile requires a completed upstream task",
    )

    sends = _send_requests(peer)
    _require(
        len(sends) == 1 and len(peer.tasks) == 1,
        f"expected exactly one downstream send and task, observed {len(sends)}/{len(peer.tasks)}",
    )
    request = sends[0]["body"]
    _require(isinstance(request, dict), "downstream request is not an object")
    downstream_params = request.get("params") if request.get("jsonrpc") else request
    _require(isinstance(downstream_params, dict), "downstream params are not an object")
    message = downstream_params.get("message")
    _require(isinstance(message, dict), "downstream request has no message")
    _require(
        request_challenge in _text(message.get("parts")),
        "downstream request does not carry the upstream challenge",
    )
    output = "".join(
        _text(artifact.get("parts"))
        for artifact in upstream.get("artifacts") or []
        if isinstance(artifact, dict)
    )
    _require(
        response_challenge in output,
        "upstream artifacts do not contain the downstream-only response challenge",
    )
    downstream = next(iter(peer.tasks.values()))
    ctx.observe(
        "relay_correlation",
        {
            "driver_returncode": run.returncode,
            "upstream_binding": binding,
            "downstream_sends": len(sends),
            "downstream_tasks_created": len(peer.tasks),
            "request_challenge_matched": True,
            "response_challenge_matched": True,
            "upstream_elapsed_seconds": elapsed,
        },
    )
    return upstream, downstream, message
