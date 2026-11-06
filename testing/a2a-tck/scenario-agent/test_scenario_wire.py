"""Bounded direct-wire diagnostic of unchanged scenario fixture and SDK 1.1.2."""

import json
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

source = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).with_name("scenario_agent.py")
)
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
url = f"http://127.0.0.1:{port}/"
proc = subprocess.Popen(
    [sys.executable, str(source), "--port", str(port)],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
client = httpx.Client(timeout=10)
headers = {"A2A-Version": "1.0"}


def message(prefix="ordinary"):
    return {
        "messageId": prefix + "-" + str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"text": "hello"}],
    }


def call(method, params):
    return client.post(
        url,
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    ).json()


results = {"source": str(source), "stream_disconnect": [], "immediate_cancel": []}
try:
    for _ in range(100):
        try:
            if client.get(url + ".well-known/agent-card.json").status_code == 200:
                break
        except httpx.TransportError:
            if proc.poll() is not None:
                raise RuntimeError("fixture startup failure")
        time.sleep(0.05)
    for _ in range(20):
        with client.stream(
            "POST",
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "SendStreamingMessage",
                "params": {"message": message()},
            },
        ) as response:
            for line in response.iter_lines():
                if line.startswith("data:"):
                    event = json.loads(line[5:])
                    task = event.get("result", {}).get("task")
                    assert task, event
                    task_id = task["id"]
                    break
        got = call("GetTask", {"id": task_id})
        results["stream_disconnect"].append({"first_task": task_id, "get": got})
        assert "result" in got, got
    for _ in range(20):
        sent = call(
            "SendMessage",
            {"message": message(), "configuration": {"returnImmediately": True}},
        )
        task = sent["result"]["task"]
        got = call("GetTask", {"id": task["id"]})
        cancel = call("CancelTask", {"id": task["id"]})
        results["immediate_cancel"].append(
            {"initial": task, "get": got, "cancel": cancel}
        )
        assert "result" in got, got
        assert "result" in cancel or cancel["error"]["code"] == -32002, cancel
    live = call("SendMessage", {"message": message("tck-input-required")})["result"][
        "task"
    ]
    assert live["status"]["state"] == "TASK_STATE_INPUT_REQUIRED", live
    results["live_cancel"] = call("CancelTask", {"id": live["id"]})
    assert (
        results["live_cancel"]["result"]["status"]["state"] == "TASK_STATE_CANCELED"
    ), results["live_cancel"]
    with client.stream(
        "POST",
        url,
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendStreamingMessage",
            "params": {"message": message("test-resubscribe-message-id")},
        },
    ) as response:
        for line in response.iter_lines():
            if line.startswith("data:"):
                held = json.loads(line[5:])["result"]["task"]
                break
    results["held_stream_get"] = call("GetTask", {"id": held["id"]})
    assert "result" in results["held_stream_get"], results["held_stream_get"]
    results["held_stream_cancel"] = call("CancelTask", {"id": held["id"]})
    assert (
        results["held_stream_cancel"]["result"]["status"]["state"]
        == "TASK_STATE_CANCELED"
    ), results["held_stream_cancel"]
    sent = call("SendMessage", {"message": message()})["result"]["task"]
    again = message()
    again.update(taskId=sent["id"], contextId=sent["contextId"])
    results["terminal_send"] = call("SendMessage", {"message": again})
    print(json.dumps(results, indent=2))
    assert results["terminal_send"]["error"]["code"] == -32004, results["terminal_send"]
finally:
    client.close()
    proc.terminate()
    proc.wait(timeout=5)
