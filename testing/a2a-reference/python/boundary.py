"""Explicit local JSON-RPC boundary repairs; no oracle-dependent dispatch."""

import json
import re


def validate_message(body):
    """Reject malformed message shapes before protobuf coercion or execution."""
    if not isinstance(body, dict):
        raise TypeError("params must be an object")
    message = body.get("message")
    if not isinstance(message, dict):
        raise TypeError("message must be an object")
    for field in ("messageId", "taskId", "contextId"):
        if field in message and not isinstance(message[field], str):
            raise ValueError(field + " must be a string")
    if not message.get("messageId"):
        raise ValueError("messageId is required")
    role = message.get("role")
    if type(role) not in (str, int) or role not in ("ROLE_USER", "ROLE_AGENT", 1, 2):
        raise ValueError("role must be a defined user or agent role")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise ValueError("parts must be a non-empty array")
    for part in parts:
        if not isinstance(part, dict):
            raise TypeError("each part must be an object")
        for field in ("text", "raw", "url", "mediaType", "filename"):
            if field in part and not isinstance(part[field], str):
                raise ValueError(field + " must be a string")
        if sum(field in part for field in ("text", "raw", "url", "data")) != 1:
            raise ValueError("each part requires exactly one content field")


class StrictBoundary:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        chunks = []
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            chunks.append(event.get("body", b""))
            if not event.get("more_body"):
                break
        raw = b"".join(chunks)
        request_id = None
        code = None
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise TypeError("JSON-RPC request must be an object")
            request_id = body.get("id")
            version = (
                dict(scope["headers"]).get(b"a2a-version", b"").decode("ascii") or "0.3"
            )
            if not re.fullmatch(r"1\.0(?:\.\d+)?", version):
                code = -32009
                raise ValueError(
                    "A2A version " + version + " is unsupported; expected 1.0"
                )
            if body.get("method") in ("SendMessage", "SendStreamingMessage"):
                validate_message(body.get("params"))
        except (ValueError, TypeError, UnicodeError) as error:
            if code is None:
                code = (
                    -32700
                    if isinstance(error, (json.JSONDecodeError, UnicodeError))
                    else -32602
                )
            payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": code, "message": str(error)},
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": raw, "more_body": False}

        await self.app(scope, replay, send)
