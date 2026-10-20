"""Request dispatcher for the helper side of the JSON-lines protocol."""

from __future__ import annotations

import os
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, BinaryIO

from .. import appinfo, log, protocol
from ..protocol import Param, RemoteError, Schema

logger = log.get("helper.server")


class Context:
    """Per-request handle: emit events and observe cancellation."""

    def __init__(self, server: Server, req_id: int):
        self.server = server
        self.req_id = req_id
        self.cancelled = threading.Event()

    def emit(self, event: str, data: Any = None) -> None:
        self.server.send(protocol.event(event, data, job=self.req_id))

    def check_cancelled(self) -> None:
        if self.cancelled.is_set():
            raise RemoteError(protocol.CANCELLED, "cancelled")


Handler = Callable[[Context, dict[str, Any]], Any]


@dataclass
class Method:
    name: str
    schema: Schema
    func: Handler
    exclusive: bool = False      # serialise with other exclusive methods


class Server:
    def __init__(self, reader: BinaryIO, writer: BinaryIO, max_workers: int = 8):
        self.reader = reader
        self.writer = writer
        self.methods: dict[str, Method] = {}
        self._send_lock = threading.Lock()
        self._exclusive = threading.Lock()
        self._jobs: dict[int, Context] = {}
        self._jobs_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="req")
        self.closed = threading.Event()
        self.register("job.cancel", Schema({"job": Param(int)}), self._cancel)

    def register(self, name: str, schema: Schema, func: Handler, exclusive: bool = False) -> None:
        self.methods[name] = Method(name, schema, func, exclusive)

    def send(self, msg: dict[str, Any]) -> None:
        data = protocol.encode(msg)
        with self._send_lock:
            if self.closed.is_set():
                return
            try:
                self.writer.write(data)
                self.writer.flush()
            except (BrokenPipeError, OSError):
                self.closed.set()

    def serve(self, **hello_extra: Any) -> None:
        self.send(protocol.hello(appinfo.VERSION, os.getpid(), **hello_extra))
        buf = protocol.LineBuffer()
        fd = self.reader.fileno()
        while not self.closed.is_set():
            try:
                data = os.read(fd, 1 << 16)
            except InterruptedError:
                continue
            if not data:
                break
            try:
                messages = buf.feed(data)
            except protocol.ProtocolError as exc:
                logger.error("protocol violation from client, closing: %s", exc)
                break
            for msg in messages:
                self._dispatch(msg)
        self.shutdown()

    def shutdown(self) -> None:
        with self._jobs_lock:
            for ctx in self._jobs.values():
                ctx.cancelled.set()
        self._pool.shutdown(wait=True, cancel_futures=True)
        self.closed.set()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        if msg["type"] != "req":
            logger.warning("ignoring unexpected %s message", msg["type"])
            return
        req_id = msg["id"]
        method = self.methods.get(msg["method"])
        if method is None:
            self.send(protocol.response_error(req_id, protocol.UNKNOWN_METHOD,
                                              f"unknown method {msg['method']!r}"))
            return
        try:
            params = method.schema.validate(msg.get("params") or {})
        except RemoteError as exc:
            self.send(protocol.response_error(req_id, exc.code, exc.message))
            return
        ctx = Context(self, req_id)
        with self._jobs_lock:
            if req_id in self._jobs:
                self.send(protocol.response_error(req_id, protocol.INVALID_REQUEST,
                                                  "duplicate request id"))
                return
            self._jobs[req_id] = ctx
        self._pool.submit(self._run, method, ctx, params)

    def _run(self, method: Method, ctx: Context, params: dict[str, Any]) -> None:
        logger.debug("-> %s #%d", method.name, ctx.req_id)
        try:
            if method.exclusive:
                with self._exclusive:
                    result = method.func(ctx, params)
            else:
                result = method.func(ctx, params)
            self.send(protocol.response_ok(ctx.req_id, result))
        except RemoteError as exc:
            self.send(protocol.response_error(ctx.req_id, exc.code, exc.message, exc.details))
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code in protocol.ERROR_CODES:
                self.send(protocol.response_error(ctx.req_id, code, log.redact(str(exc)),
                                                  getattr(exc, "details", None)))
            else:
                logger.error("%s failed:\n%s", method.name, traceback.format_exc())
                self.send(protocol.response_error(ctx.req_id, protocol.INTERNAL,
                                                  f"internal error: {log.redact(str(exc))}"))
        finally:
            with self._jobs_lock:
                self._jobs.pop(ctx.req_id, None)

    def _cancel(self, ctx: Context, params: dict[str, Any]) -> bool:
        with self._jobs_lock:
            target = self._jobs.get(params["job"])
        if target is None:
            return False
        target.cancelled.set()
        return True
