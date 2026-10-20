"""Helper-side pool of scan worker processes connected by socketpairs.

Files are handed to workers as open descriptors (SCM_RIGHTS), so workers
never resolve paths on the target and never need privileges.  A worker that
crashes or hangs on a hostile file is killed and replaced; the file is
reported as an error instead of stopping the scan.
"""

from __future__ import annotations

import json
import os
import selectors
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from .. import log, privdrop, sandbox
from . import worker as worker_mod

logger = log.get("scan.pool")
MAX_INFLIGHT = 2


@dataclass
class Pending:
    job_id: int
    item: Any
    sent: float


@dataclass
class Worker:
    proc: subprocess.Popen[bytes]
    sock: socket.socket
    ready: bool = False
    status: dict[str, Any] = field(default_factory=dict)
    inflight: dict[int, Pending] = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)


class WorkerPool:
    def __init__(self, size: int, config: dict[str, Any], identity: privdrop.Identity | None,
                 hard_timeout: float = 600):
        self.size = size
        self.config = config
        self.identity = identity
        self.hard_timeout = hard_timeout
        self.workers: list[Worker] = []
        self.selector = selectors.DefaultSelector()
        self.crashes = 0
        self.fatal: str | None = None

    # ---------------------------------------------------------------- spawn

    def _spawn(self) -> Worker:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        config = dict(self.config)
        kwargs: dict[str, Any] = {}
        if self.identity is not None and os.geteuid() == 0:
            kwargs = {"user": self.identity.uid, "group": self.identity.gid, "extra_groups": []}
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "HOME": self.identity.home if self.identity else "/"}
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-c", worker_mod.BOOT, json.dumps(sandbox._package_paths()),
                 str(child.fileno()), json.dumps(config)],
                pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL, env=env, cwd="/",
                close_fds=True, **kwargs)
        finally:
            child.close()
        parent.setblocking(False)
        worker = Worker(proc, parent)
        self.selector.register(parent, selectors.EVENT_READ, worker)
        self.workers.append(worker)
        return worker

    def start(self) -> None:
        for _ in range(self.size):
            self._spawn()

    def wait_ready(self, timeout: float, on_wait: Any = None) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(w.ready for w in self.workers) or self.fatal:
                break
            for result in self.poll(1.0):
                logger.warning("unexpected result before ready: %s", result)
            if on_wait:
                on_wait()
            if not any(w.proc.poll() is None for w in self.workers):
                break
        if self.fatal:
            raise RuntimeError(self.fatal)
        ready = [w for w in self.workers if w.ready]
        if not ready:
            raise RuntimeError(sandbox.import_problem(self.identity) or "no scan worker could start")
        return ready[0].status

    # ------------------------------------------------------------ dispatch

    def free_worker(self) -> Worker | None:
        candidates = [w for w in self.workers if w.ready and len(w.inflight) < MAX_INFLIGHT
                      and w.proc.poll() is None]
        if not candidates:
            return None
        return min(candidates, key=lambda w: len(w.inflight))

    def submit(self, worker: Worker, job_id: int, message: dict[str, Any], fd: int, item: Any) -> None:
        data = json.dumps({**message, "id": job_id}).encode()
        socket.send_fds(worker.sock, [data], [fd])
        worker.inflight[job_id] = Pending(job_id, item, time.monotonic())

    @property
    def inflight(self) -> int:
        return sum(len(w.inflight) for w in self.workers)

    def poll(self, timeout: float) -> list[dict[str, Any]]:
        """Collect results; replaces dead or hung workers."""
        results: list[dict[str, Any]] = []
        for key, _ in self.selector.select(timeout):
            worker: Worker = key.data
            while True:
                try:
                    data = worker.sock.recv(worker_mod.MAX_MSG)
                except BlockingIOError:
                    break
                except OSError:
                    data = b""
                if not data:
                    results.extend(self._replace(worker, "the scan engine process exited"))
                    break
                try:
                    msg = json.loads(data)
                except ValueError:
                    results.extend(self._replace(worker, "malformed reply from scan engine"))
                    break
                kind = msg.get("type")
                if kind == "ready":
                    worker.ready = True
                    worker.status = msg.get("status") or {}
                elif kind == "fatal":
                    self.fatal = str(msg.get("error"))
                elif kind == "result":
                    pending = worker.inflight.pop(msg.get("id"), None)
                    if pending is not None:
                        msg["item"] = pending.item
                        results.append(msg)
        now = time.monotonic()
        for worker in list(self.workers):
            stale = [p for p in worker.inflight.values() if now - p.sent > self.hard_timeout]
            if stale:
                results.extend(self._replace(worker, "scanning took too long; engine restarted"))
        return results

    def _replace(self, worker: Worker, reason: str) -> list[dict[str, Any]]:
        self.crashes += 1
        results = [{"type": "result", "id": p.job_id, "item": p.item, "detections": [],
                    "errors": [reason], "skipped": None, "bytes": 0, "sha256": None}
                   for p in worker.inflight.values()]
        worker.inflight.clear()
        self._kill(worker)
        if self.crashes <= 50 and not self.fatal:
            self._spawn()
        return results

    def _kill(self, worker: Worker) -> None:
        try:
            self.selector.unregister(worker.sock)
        except (KeyError, ValueError):
            pass
        worker.sock.close()
        if worker.proc.poll() is None:
            worker.proc.kill()
        try:
            worker.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if worker in self.workers:
            self.workers.remove(worker)

    def shutdown(self) -> None:
        for worker in list(self.workers):
            try:
                worker.sock.send(json.dumps({"type": "stop"}).encode())
            except OSError:
                pass
        deadline = time.monotonic() + 10
        for worker in list(self.workers):
            try:
                worker.proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            self._kill(worker)
        self.selector.close()
