#!/usr/bin/env python3
"""Behavior controls for the existing Target launch/stop API, using real sockets."""
import signal
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from a2aht.target import Target, TargetError


class ProcessRegressions(unittest.TestCase):
    def test_foreign_listener_cannot_ready_a_live_child_that_never_binds(self):
        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", 0))
            foreign.listen()
            target = Target(
                launch=[sys.executable, "-c", "import time; time.sleep(30)"],
                port=foreign.getsockname()[1], launch_ready_seconds=0.2,
            )
            try:
                with self.assertRaises(TargetError):
                    target.start()
            finally:
                target.stop()
            self.assertEqual(foreign.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)

    def test_foreign_listener_cannot_ready_a_child_that_exits(self):
        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", 0))
            foreign.listen()
            target = Target(launch=[sys.executable, "-c", "pass"],
                            port=foreign.getsockname()[1], launch_ready_seconds=0.2)
            try:
                with self.assertRaises(TargetError):
                    target.start()
            finally:
                target.stop()

    def test_owned_listener_is_ready_and_stop_reaps_a_term_ignoring_peer(self):
        # This is a candidate, never a reservation. Target must still prove its
        # launched process actually bound it; a foreign occupant cannot pass.
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        code = (
            "import signal,socket,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "s=socket.socket(); s.bind(('127.0.0.1', int(sys.argv[1]))); "
            "s.listen(); time.sleep(60)"
        )
        target = Target(launch=[sys.executable, "-c", code, str(port)],
                        port=port, launch_ready_seconds=5)
        try:
            target.start()
            proc = target._proc
            self.assertIsNone(proc.poll())
            target.stop()
            self.assertEqual(proc.returncode, -signal.SIGKILL)
        finally:
            target.stop()


if __name__ == "__main__":
    unittest.main()
