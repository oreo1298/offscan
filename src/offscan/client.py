"""Client side of the helper protocol (used by both the CLI and the GUI).

The helper is started on demand:

* already root: run it directly;
* installed: ``pkexec <libdir>/offscan-helper`` (polkit asks for the password);
* no polkit agent / pkexec missing: fall back to ``sudo`` when a terminal is
  available.

Responses and events are read on a background thread.  ``call`` blocks;
``call_async`` invokes a callback (the GUI marshals it to the UI thread).
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import threading
from collections.abc import Callable
from concurrent.futures import Future
from pathlib import Path
from typing import Any

from . import appinfo, log, protocol, tools
from .protocol import RemoteError

logger = log.get("client")

EventCallback = Callable[[str, Any, int | None], None]


class HelperStartError(Exception):
    pass


def _dev_checkout_python_path() -> str:
    return str(Path(__file__).resolve().parent.parent)


def helper_command(prefer_sudo: bool = False) -> tuple[list[str], dict[str, str] | None]:
    """Return (argv, extra env) used to start the helper."""
    override = os.environ.get(appinfo.env("HELPER_COMMAND"))
    if override:
        return shlex.split(override), None
    installed = os.path.isfile(appinfo.HELPER_PATH) and os.access(appinfo.HELPER_PATH, os.X_OK)
    if installed:
        base = [appinfo.HELPER_PATH]
        env = None
    else:
        # Running from a source checkout (development).
        base = [sys.executable, "-m", "offscan.helper"]
        env = {"PYTHONPATH": _dev_checkout_python_path()}
    if os.geteuid() == 0:
        return base, env
    pkexec = tools.find("pkexec")
    sudo = tools.find("sudo")
    if pkexec and not prefer_sudo:
        if env:
            return [pkexec, "/usr/bin/env", f"PYTHONPATH={env['PYTHONPATH']}", *base], None
        return [pkexec, *base], None
    if sudo and sys.stdin.isatty():
        if env:
            return [sudo, "/usr/bin/env", f"PYTHONPATH={env['PYTHONPATH']}", *base], None
        return [sudo, "--", *base], None
    raise HelperStartError(
        "cannot get administrator rights: neither pkexec (polkit) nor sudo is available")


class _Pending:
    def __init__(self, on_event: EventCallback | None):
        self.future: Future[Any] = Future()
        self.on_event = on_event


class HelperClient:
    def __init__(self, on_event: EventCallback | None = None,
                 command: list[str] | None = None, env: dict[str, str] | None = None):
        self.on_event = on_event
        self._command = command
        self._env = env
        self.proc: subprocess.Popen[bytes] | None = None
        self.hello: dict[str, Any] | None = None
        self._hello_event = threading.Event()
        self._pending: dict[int, _Pending] = {}
        self._lock = threading.Lock()
        self._next_id = 1
        self._closed = threading.Event()
        self.stderr_lines: list[str] = []

    # -------------------------------------------------------------- lifecycle

    def start(self, timeout: float | None = None, prefer_sudo: bool = False) -> dict[str, Any]:
        if self._command is None:
            self._command, self._env = helper_command(prefer_sudo)
        env = dict(os.environ)
        if self._env:
            env.update(self._env)
        try:
            self.proc = subprocess.Popen(self._command, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         close_fds=True, env=env)
        except OSError as exc:
            raise HelperStartError(f"cannot start the helper: {exc}") from exc
        threading.Thread(target=self._read_stdout, name="helper-out", daemon=True).start()
        threading.Thread(target=self._read_stderr, name="helper-err", daemon=True).start()
        if not self._hello_event.wait(timeout):
            self.close()
            raise HelperStartError("the helper did not start in time")
        if self.hello is None:
            raise HelperStartError(self._exit_message())
        if not self.hello.get("ready", True):
            msg = self.hello.get("error") or "the helper could not start"
            self.close()
            raise HelperStartError(msg)
        if self.hello.get("protocol") != protocol.PROTOCOL_VERSION:
            self.close()
            raise HelperStartError("the helper speaks a different protocol version; "
                                   "reinstall the application")
        return self.hello

    def _exit_message(self) -> str:
        code = self.proc.wait(timeout=10) if self.proc else None
        tail = " ".join(self.stderr_lines[-3:])
        if code == 126:
            return "authentication was cancelled"
        if code == 127:
            if "No authentication agent" in tail or "no authentication agent" in tail.lower():
                return ("no polkit authentication agent is running; start one, or run "
                        f"'sudo {appinfo.NAME} ...' from a terminal")
            return "not authorised to access drives"
        return f"the helper exited unexpectedly ({code}): {tail}"

    def close(self, timeout: float = 120) -> None:
        if self.proc is None or self._closed.is_set():
            return
        self._closed.set()
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.error("helper did not exit; terminating it")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __enter__(self) -> HelperClient:
        if self.proc is None:
            self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    # ------------------------------------------------------------------ I/O

    def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        buf = protocol.LineBuffer()
        fd = self.proc.stdout.fileno()
        try:
            while True:
                data = os.read(fd, 1 << 16)
                if not data:
                    break
                for msg in buf.feed(data):
                    self._handle(msg)
        except (OSError, protocol.ProtocolError) as exc:
            logger.error("helper connection failed: %s", exc)
        finally:
            self._hello_event.set()
            with self._lock:
                pending, self._pending = self._pending, {}
            for item in pending.values():
                if not item.future.done():
                    item.future.set_exception(RemoteError(protocol.FAILED, "the helper exited"))

    def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for raw in self.proc.stderr:
            line = raw.decode("utf-8", "replace").rstrip()
            if line:
                self.stderr_lines.append(line)
                del self.stderr_lines[:-200]
                logger.info("helper: %s", line)

    def _handle(self, msg: dict[str, Any]) -> None:
        mtype = msg["type"]
        if mtype == "hello":
            self.hello = msg
            self._hello_event.set()
        elif mtype == "res":
            with self._lock:
                item = self._pending.pop(msg["id"], None)
            if item is None:
                return
            if msg["ok"]:
                item.future.set_result(msg.get("result"))
            else:
                err = msg["error"]
                item.future.set_exception(RemoteError(err["code"], err["message"],
                                                      err.get("details")))
        elif mtype == "evt":
            job = msg.get("job")
            callback = None
            if job is not None:
                with self._lock:
                    item = self._pending.get(job)
                callback = item.on_event if item else None
            for cb in (callback, self.on_event):
                if cb is not None:
                    try:
                        cb(msg["event"], msg.get("data"), job)
                    except Exception:
                        logger.exception("event callback failed")

    # ------------------------------------------------------------- requests

    def submit(self, method: str, params: dict[str, Any] | None = None,
               on_event: EventCallback | None = None) -> tuple[int, Future[Any]]:
        if not self.running:
            raise RemoteError(protocol.FAILED, "the helper is not running")
        with self._lock:
            req_id = self._next_id
            self._next_id += 1
            item = _Pending(on_event)
            self._pending[req_id] = item
        data = protocol.encode(protocol.request(req_id, method, params or {}))
        try:
            assert self.proc and self.proc.stdin
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (OSError, ValueError) as exc:
            with self._lock:
                self._pending.pop(req_id, None)
            raise RemoteError(protocol.FAILED, f"cannot talk to the helper: {exc}") from exc
        return req_id, item.future

    def call(self, method: str, params: dict[str, Any] | None = None,
             timeout: float | None = None, on_event: EventCallback | None = None) -> Any:
        _, future = self.submit(method, params, on_event)
        return future.result(timeout)

    def call_async(self, method: str, params: dict[str, Any] | None,
                   callback: Callable[[Any, BaseException | None], None],
                   on_event: EventCallback | None = None) -> int:
        req_id, future = self.submit(method, params, on_event)

        def done(fut: Future[Any]) -> None:
            exc = fut.exception()
            callback(None if exc else fut.result(), exc)

        future.add_done_callback(done)
        return req_id

    def cancel(self, job: int) -> None:
        try:
            self.submit("job.cancel", {"job": job})
        except RemoteError:
            pass
