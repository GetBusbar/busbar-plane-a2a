"""Prove that a fixture process owns its listening socket, without reserving ports."""

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys


def _darwin_info(pid):
    import ctypes

    # Apple proc_info.h / proc_info_private.h: one query holds the process
    # while copying both its start identity and its current exec/PID version.
    class BsdInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
            "ruid", "rgid", "svuid", "svgid", "reserved")]
        _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
        _fields_ += [(name, ctypes.c_uint32) for name in (
            "nfiles", "pgid", "pjobc", "tdev", "tpgid", "nice")]
        _fields_ += [("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]

    class UniqueInfo(ctypes.Structure):
        _fields_ = [("uuid", ctypes.c_uint8 * 16),
                    ("uniqueid", ctypes.c_uint64), ("parent_uniqueid", ctypes.c_uint64),
                    ("idversion", ctypes.c_int32), ("parent_idversion", ctypes.c_int32),
                    ("reserved2", ctypes.c_uint64), ("reserved3", ctypes.c_uint64)]

    class BsdWithUnique(ctypes.Structure):
        _fields_ = [("bsd", BsdInfo), ("unique", UniqueInfo)]

    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    info = BsdWithUnique()
    size = ctypes.sizeof(info)
    if lib.proc_pidinfo(int(pid), 18, 0, ctypes.byref(info), size) != size:
        return None
    return lib, ctypes, info


def process_identity(pid):
    """A start identity survives exec and changes when a PID is reused."""
    try:
        if sys.platform.startswith("linux"):
            fields = Path("/proc/%d/stat" % int(pid)).read_text().rsplit(")", 1)[1].split()
            return fields[19] if fields[0] != "Z" else ""
        if sys.platform == "darwin":
            result = _darwin_info(pid)
            if result is not None:
                info = result[2].bsd
                if info.status != 5:
                    return "%d:%d" % (info.start_sec, info.start_usec)
    except (OSError, ValueError, IndexError, AttributeError):
        pass
    return ""


def signal_owned(pid, identity, sig):
    """Bind signals to a Linux pidfd or a Darwin audit token, never a stale PID."""
    if not identity:
        return False
    fd = None
    try:
        if sys.platform == "darwin":
            result = _darwin_info(pid)
            if result is None:
                return False
            lib, ctypes, info = result
            current = "%d:%d" % (info.bsd.start_sec, info.bsd.start_usec)
            if info.bsd.status == 5 or current != identity or info.bsd.pid != int(pid):
                return False
            # Only PID and PID/exec version select the target. The kernel uses
            # the caller's real credentials for permission checks, then holds
            # the matched process reference while sending the signal.
            # Match Apple's synthetic INVALID_AUDIT_TOKEN selector pattern.
            token = (ctypes.c_uint32 * 8)(*([0xFFFFFFFF] * 8))
            token[5] = int(pid)
            token[7] = info.unique.idversion
            lib.proc_signal_with_audittoken.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.proc_signal_with_audittoken.restype = ctypes.c_int
            return lib.proc_signal_with_audittoken(ctypes.byref(token), int(sig)) == 0
        if sys.platform.startswith("linux"):
            fd = os.pidfd_open(int(pid))
        else:
            return False
        if process_identity(pid) != identity:
            return False
        signal.pidfd_send_signal(fd, int(sig))
        return True
    except (OSError, AttributeError):
        return False
    finally:
        if fd is not None:
            os.close(fd)


def owns_listener(pid, port, host="127.0.0.1"):
    """Require every TCP listener on this port to belong to the exact child PID.

    Fixture launchers must exec their server. Liveness alone permits a slow or
    failed child to borrow another process's readiness response.
    """
    pid, port = int(pid), int(port)
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        if sys.platform.startswith("linux"):
            fds = Path("/proc/%d/fd" % pid)
            sockets = set()
            for fd in fds.iterdir():
                try:
                    target = os.readlink(fd)
                except FileNotFoundError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    sockets.add(target[8:-1])
            listeners = set()
            for name in ("tcp", "tcp6"):
                table = Path("/proc/net") / name
                if not table.exists() and name == "tcp6":
                    continue
                for line in table.read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port:
                        raw = fields[1].split(":")[0]
                        packed = b"".join(int(raw[i:i + 8], 16).to_bytes(4, sys.byteorder)
                                          for i in range(0, len(raw), 8))
                        address = socket.inet_ntop(socket.AF_INET if name == "tcp" else socket.AF_INET6, packed)
                        if address in addresses or address in ("0.0.0.0", "::"):
                            listeners.add(fields[9])
            return bool(listeners) and listeners <= sockets
        if sys.platform == "darwin":
            result = subprocess.run(
                ["lsof", "-nP", "-iTCP@%s:%d" % (host, port), "-sTCP:LISTEN", "-Fp"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
                text=True,
            )
            owners = {int(line[1:]) for line in result.stdout.splitlines()
                      if line.startswith("p")}
            return result.returncode == 0 and owners == {pid}
    except (OSError, ValueError, IndexError):
        return False
    return False


if __name__ == "__main__":
    if sys.argv[1] == "identity":
        print(process_identity(sys.argv[2]))
    elif sys.argv[1] == "signal":
        sys.exit(0 if signal_owned(sys.argv[2], sys.argv[3], sys.argv[4]) else 1)
    else:
        sys.exit(0 if owns_listener(sys.argv[1], sys.argv[2]) else 1)
