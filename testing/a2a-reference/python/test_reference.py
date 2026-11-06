"""Targeted runtime regression checks for the explicitly repaired boundary."""

import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from a2a.types import Artifact
from google.protobuf.json_format import ParseDict


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.url = f"http://127.0.0.1:{port}/"
        cls.proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("scenario_agent.py")),
                "--port",
                str(port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                with urlopen(cls.url + ".well-known/agent-card.json") as response:
                    cls.card = json.load(response)
                return
            except OSError:
                if cls.proc.poll() is not None:
                    raise RuntimeError("fixture failed to start")
                time.sleep(0.05)
        raise RuntimeError("fixture startup timed out")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)

    def call(self, params, method="SendMessage", version="1.0"):
        headers = {"Content-Type": "application/json"}
        if version is not None:
            headers["A2A-Version"] = version
        request = Request(
            self.url,
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
            headers,
        )
        with urlopen(request, timeout=5) as response:
            return json.load(response)

    def message(self):
        return {
            "messageId": "ordinary-message",
            "role": "ROLE_USER",
            "parts": [{"text": "hello"}],
        }

    def test_single_interface(self):
        self.assertEqual(len(self.card["supportedInterfaces"]), 1)
        self.assertEqual(
            self.card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC"
        )

    def test_version_defaults(self):
        for version in (None, "", "0.3", "1.1", "99.0"):
            with self.subTest(version=version):
                self.assertEqual(
                    self.call({"message": self.message()}, version=version)["error"][
                        "code"
                    ],
                    -32009,
                )

    def test_wrong_types(self):
        messages = [
            {"messageId": "x", "role": "ROLE_USER", "parts": "bad"},
            {"messageId": "x", "role": 7, "parts": [{"text": "hi"}]},
            [1, 2],
            {"messageId": "x", "role": "ROLE_USER", "parts": [None]},
        ]
        for message in messages:
            with self.subTest(message=message):
                self.assertEqual(
                    self.call({"message": message})["error"]["code"], -32602
                )

    def test_list_artifact_projection_preserves_store(self):
        message = self.message()
        message["messageId"] = "tck-artifact-text-list-projection"
        result = self.call({"message": message})["result"]
        task = result.get("task", result)
        original = self.call({"id": task["id"]}, "GetTask")["result"]
        self.assertTrue(original["artifacts"])
        for params in ({}, {"includeArtifacts": False}):
            listed = self.call(params, "ListTasks")["result"]
            self.assertIn("nextPageToken", listed)
            matches = [item for item in listed["tasks"] if item["id"] == task["id"]]
            self.assertEqual(len(matches), 1)
            self.assertNotIn("artifacts", matches[0])
        listed = self.call({"includeArtifacts": True}, "ListTasks")["result"]
        match = next(item for item in listed["tasks"] if item["id"] == task["id"])
        self.assertEqual(
            [ParseDict(item, Artifact()) for item in match["artifacts"]],
            [ParseDict(item, Artifact()) for item in original["artifacts"]],
        )
        self.assertEqual(self.call({"id": task["id"]}, "GetTask")["result"], original)

    def test_terminal_immutable(self):
        result = self.call({"message": self.message()})["result"]
        task = result.get("task", result)
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")
        before = self.call({"id": task["id"]}, "GetTask")["result"]
        message = self.message()
        message.update(taskId=task["id"], contextId=task["contextId"])
        reply = self.call({"message": message})
        self.assertEqual(reply["error"]["code"], -32004, reply)
        self.assertEqual(self.call({"id": task["id"]}, "GetTask")["result"], before)


if __name__ == "__main__":
    unittest.main()
