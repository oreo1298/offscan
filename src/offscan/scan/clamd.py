"""Private, on-demand clamd: configuration, process control and a small client.

clamd runs unprivileged (as the scanning user, or ``nobody``) and listens
only on a Unix socket inside the scan's private runtime directory.  Workers
pass it the file descriptor they already hold (``zFILDES``), which needs no
copy and no temporary file.  Debian/Ubuntu's AppArmor profile for clamd
re-checks passed descriptors against allowed paths and our mounts are not
among them, so when clamd refuses a descriptor the worker switches to
streaming the contents (``zINSTREAM``), which works under every MAC policy.

Everything lives under ``/tmp/<name>-scan-*`` because that is one of the
few places the distribution AppArmor profile lets clamd read and write.
ClamAV is GPL-2.0-only, so we never link it; we only talk to its daemon.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .. import tools
from .options import Limits

CHUNK = 1 << 20
SOCKET_NAME = "clamd.sock"
CONF_NAME = "clamd.conf"


def write_config(runtime: Path, limits: Limits, threads: int, detect_pua: bool = False) -> Path:
    """Write clamd.conf into the runtime dir (called by the client, as the user)."""
    db = runtime / "clamav"
    tmp = runtime / "tmp"
    tmp.mkdir(mode=0o700, exist_ok=True)
    lines = [
        f"LocalSocket {runtime / SOCKET_NAME}",
        "LocalSocketMode 600",
        f"DatabaseDirectory {db}",
        f"TemporaryDirectory {tmp}",
        f"LogFile {runtime / 'clamd.log'}",
        "LogTime yes",
        "Foreground yes",
        f"MaxThreads {max(1, threads)}",
        f"MaxQueue {max(50, threads * 8)}",
        "MaxConnectionQueueLength 64",
        f"StreamMaxLength {limits.max_file_size}",
        f"MaxFileSize {limits.max_file_size}",
        f"MaxScanSize {limits.max_scan_size}",
        f"MaxRecursion {limits.archive_depth}",
        f"MaxFiles {limits.max_archive_files}",
        f"MaxScanTime {limits.file_timeout * 1000}",
        "AlertExceedsMax no",
        "ConcurrentDatabaseReload no",
        "SelfCheck 0",
        "ExitOnOOM yes",
        "ReadTimeout 300",
        "CommandReadTimeout 30",
        "IdleTimeout 600",
        "FollowDirectorySymlinks no",
        "FollowFileSymlinks no",
        "ScanArchive yes",
        "ScanPE yes",
        "ScanELF yes",
        "ScanOLE2 yes",
        "ScanPDF yes",
        "ScanHTML yes",
        "ScanMail yes",
        "Bytecode yes",
        f"DetectPUA {'yes' if detect_pua else 'no'}",
        "HeuristicAlerts yes",
    ]
    path = runtime / CONF_NAME
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def clamd_binary() -> str | None:
    return tools.find("clamd")


def start(runtime: Path, uid: int | None, gid: int | None) -> subprocess.Popen[bytes]:
    """Start clamd (as ``uid``) in the foreground; the caller waits for readiness."""
    binary = clamd_binary()
    if binary is None:
        raise RuntimeError("clamd is not installed")
    kwargs = {}
    if uid is not None and os.geteuid() == 0:
        kwargs = {"user": uid, "group": gid, "extra_groups": []}
    log = open(os.devnull, "wb")
    return subprocess.Popen(
        [binary, "--foreground", f"--config-file={runtime / CONF_NAME}"],
        stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True,
        env=tools.safe_env(), cwd="/", **kwargs)


def stop(proc: subprocess.Popen[bytes], timeout: float = 30) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


class ClamdError(Exception):
    pass


@dataclass
class ClamdReply:
    status: str          # OK | FOUND | ERROR
    signature: str = ""
    message: str = ""


def parse_reply(raw: bytes) -> ClamdReply:
    text = raw.rstrip(b"\0\n").decode("utf-8", "replace")
    # "stream: Eicar-Test-Signature FOUND" / "stream: OK" / "INSTREAM size limit exceeded. ERROR"
    if text.endswith(" FOUND"):
        body = text[: -len(" FOUND")]
        sig = body.split(": ", 1)[1] if ": " in body else body
        return ClamdReply("FOUND", sig.strip())
    if text.endswith(" OK") or text == "OK":
        return ClamdReply("OK")
    if text.endswith(" ERROR"):
        return ClamdReply("ERROR", message=text[: -len(" ERROR")])
    return ClamdReply("ERROR", message=text or "empty reply")


class Client:
    """Synchronous clamd connection used by one worker process."""

    def __init__(self, socket_path: str, timeout: float = 300):
        self.socket_path = socket_path
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        return sock

    def command(self, cmd: bytes) -> bytes:
        with self._connect() as sock:
            sock.sendall(b"z" + cmd + b"\0")
            return _read_reply(sock)

    def ping(self) -> bool:
        try:
            return self.command(b"PING").rstrip(b"\0") == b"PONG"
        except OSError:
            return False

    def version(self) -> str:
        return self.command(b"VERSION").rstrip(b"\0").decode("utf-8", "replace")

    def wait_ready(self, timeout: float = 300, interval: float = 0.5,
                   alive: callable = lambda: True) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(self.socket_path) and self.ping():
                return True
            if not alive():
                return False
            time.sleep(interval)
        return False

    def open_stream(self) -> InStream:
        return InStream(self._connect())

    def scan_fd(self, fd: int) -> ClamdReply:
        """zFILDES: let clamd read our already open descriptor (no copy, no temp file).

        Refused under AppArmor profiles that re-check passed descriptors; the
        caller then falls back to :meth:`open_stream`.
        """
        with self._connect() as sock:
            sock.sendall(b"zFILDES\0")
            socket.send_fds(sock, [b"\0"], [fd])
            return parse_reply(_read_reply(sock))


class InStream:
    """One zINSTREAM exchange: feed chunks, then ``finish()`` for the verdict."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sock.sendall(b"zINSTREAM\0")
        self.closed = False

    def feed(self, data: bytes | memoryview) -> None:
        view = memoryview(data)
        for i in range(0, len(view), CHUNK):
            part = view[i:i + CHUNK]
            self.sock.sendall(struct.pack(">I", len(part)) + part.tobytes())

    def finish(self) -> ClamdReply:
        try:
            self.sock.sendall(struct.pack(">I", 0))
            return parse_reply(_read_reply(self.sock))
        finally:
            self.close()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.sock.close()


def _read_reply(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        if data.endswith(b"\0"):
            break
    if not chunks:
        raise ClamdError("clamd closed the connection")
    return b"".join(chunks)
