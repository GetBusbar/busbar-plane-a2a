#!/usr/bin/env python3
"""Exercise existing signal_owned against Darwin's PID-version signal contract."""
import ctypes
import errno
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from a2aht import process_fixture


class DarwinSignalRegressions(unittest.TestCase):
    def library(self, start=(10, 20), queried_version=7, kernel_version=7, refusal=0):
        def info(pid, flavor, argument, output, size):
            self.assertEqual(flavor, 18)
            # A single native BSD+unique record: start and version belong to
            # one process lookup, including a version changed by a legal exec.
            value = output._obj
            value.bsd.pid = pid
            value.bsd.status = 2
            value.bsd.start_sec, value.bsd.start_usec = start
            value.unique.idversion = queried_version
            return size

        def send(pointer, sig):
            token = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 8)).contents
            self.assertEqual(token[5], 1234)
            self.assertIn(sig, (9, 15))
            return errno.ESRCH if token[7] != kernel_version else refusal

        return SimpleNamespace(proc_pidinfo=Mock(side_effect=info),
                               proc_signal_with_audittoken=Mock(side_effect=send))

    def invoke(self, lib, sig=15):
        with patch.object(process_fixture.sys, "platform", "darwin"), \
                patch.object(process_fixture, "process_identity", return_value="10:20"), \
                patch("ctypes.CDLL", return_value=lib), \
                patch.object(process_fixture.os, "kill") as numeric:
            result = process_fixture.signal_owned(1234, "10:20", sig)
        self.assertEqual(numeric.call_count, 0, "a checked numeric PID must never be signaled")
        return result

    def test_recycled_pid_cannot_receive_term_or_kill(self):
        for sig in (15, 9):
            with self.subTest(signal=sig):
                lib = self.library(queried_version=7, kernel_version=8)
                self.assertFalse(self.invoke(lib, sig))
                self.assertEqual(lib.proc_signal_with_audittoken.call_count, 1)

    def test_matching_instance_uses_current_version_after_exec(self):
        lib = self.library(queried_version=9, kernel_version=9)
        self.assertTrue(self.invoke(lib))
        self.assertEqual(lib.proc_signal_with_audittoken.call_count, 1)

    def test_changed_start_is_refused_before_any_signal(self):
        lib = self.library(start=(11, 20))
        self.assertFalse(self.invoke(lib))
        self.assertEqual(lib.proc_signal_with_audittoken.call_count, 0)

    def test_permission_refusal_and_missing_api_never_fall_back_to_kill(self):
        self.assertFalse(self.invoke(self.library(refusal=errno.EPERM)))
        lib = self.library()
        del lib.proc_signal_with_audittoken
        self.assertFalse(self.invoke(lib))


if __name__ == "__main__":
    unittest.main()
