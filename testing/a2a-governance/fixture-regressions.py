#!/usr/bin/env python3
"""Governance observations need relevant traffic, not cumulative process counts."""
import json
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

from a2agov import cli  # Set up the existing harness library import path.
from a2agov import tests_governance as governance
from a2aht.fakes import Behaviour, FakePeer
from a2aht.model import Context, NotConfigured
from a2aht import spec


class TrafficPeer:
    def __init__(self, requests):
        self.requests = requests
        self.card_fetches = sum(r["path"] == spec.WELL_KNOWN_CARD_PATH for r in requests)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def a2a_requests(self):
        return [r for r in self.requests if r["path"] != spec.WELL_KNOWN_CARD_PATH]


def request(path, at):
    return {"path": path, "at": at}


class GovernanceFixtureRegressions(unittest.TestCase):
    def cadence(self, requests):
        ctx = Context(None, {"reverify_ttl_seconds": 5.0})
        result = {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}
        with patch.object(governance, "FakePeer", return_value=TrafficPeer(requests)), \
                patch.object(governance, "drive", return_value=result):
            governance.test_reverification_cadence(ctx)
        return ctx.observations

    def refetched(self, observed):
        # The old probe exposes only its across-rounds inference. Keep this
        # regression runnable against that API, so it fails on the observation.
        return observed.get("card_refetched_before_call_after_ttl",
                            observed.get("card_refetched_across_rounds"))

    def test_single_delegation_cannot_establish_cadence(self):
        with self.assertRaises(NotConfigured):
            self.cadence([request(spec.WELL_KNOWN_CARD_PATH, 0), request("/message:send", 1)])

    def test_repeated_calls_without_refetch_are_observed_as_such(self):
        observed = self.cadence([request(spec.WELL_KNOWN_CARD_PATH, 0),
                                 request("/message:send", 1), request("/message:send", 7)])
        self.assertIs(self.refetched(observed), False)

    def test_refetch_after_later_call_does_not_establish_verification_before_delegation(self):
        observed = self.cadence([request(spec.WELL_KNOWN_CARD_PATH, 0),
                                 request("/message:send", 1), request("/message:send", 7),
                                 request(spec.WELL_KNOWN_CARD_PATH, 8)])
        self.assertIs(self.refetched(observed), False)

    def test_refetch_before_call_after_configured_ttl_is_observed(self):
        observed = self.cadence([request(spec.WELL_KNOWN_CARD_PATH, 0),
                                 request("/message:send", 1),
                                 request(spec.WELL_KNOWN_CARD_PATH, 6), request("/message:send", 7)])
        self.assertIs(self.refetched(observed), True)

    def test_input_required_peer_keeps_task_identity_across_continuation(self):
        with FakePeer(Behaviour(input_required=True)) as peer:
            def send(message):
                wire = json.dumps({"message": message}).encode()
                with urlopen(Request(peer.base_url + "/message:send", wire,
                                     {"Content-Type": spec.MEDIA_TYPE_A2A_JSON})) as response:
                    return json.load(response)["task"]
            first = send({"messageId": "first", "role": "ROLE_USER", "parts": [{"text": "start"}]})
            resumed = send({"messageId": "next", "role": "ROLE_USER", "taskId": first["id"],
                            "contextId": first["contextId"], "parts": [{"text": "continue"}]})
        self.assertEqual(first["status"]["state"], "TASK_STATE_INPUT_REQUIRED")
        self.assertEqual(resumed["status"]["state"], "TASK_STATE_INPUT_REQUIRED")
        self.assertEqual(resumed["id"], first["id"])
        self.assertEqual(resumed["contextId"], first["contextId"])


if __name__ == "__main__":
    unittest.main()
