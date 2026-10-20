"""Keep the GUI responsive: every helper call and long job runs off the GUI thread.

Results come back through queued Qt signals, so callbacks always run in the
GUI thread.  Nothing here blocks: starting the helper (which shows the
administrator password prompt), calls, scans and definition updates all
finish later.

After :meth:`Bridge.close` no thread emits a signal any more: a thread that
finishes while the window and the application are being destroyed would
otherwise post to deleted Qt objects and crash the process on exit.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from .. import log
from ..client import HelperClient, HelperStartError
from ..protocol import RemoteError
from .qt import QtCore, Signal

logger = log.get("gui.bridge")

Done = Callable[[Any, BaseException | None], None]


class Bridge(QtCore.QObject):
    connected = Signal(object)                    # helper.info result
    connection_failed = Signal(str)
    disconnected = Signal()
    helper_event = Signal(str, object, object)    # event, data, job
    _deliver = Signal(object, object, object)     # callback, result, error

    def __init__(self, client_factory: Callable[..., Any] | None = None,
                 parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self._factory = client_factory or (lambda on_event: HelperClient(on_event=on_event))
        self.client: Any = None
        self.info: dict[str, Any] | None = None
        self._connecting = False
        self._closed = False
        self._lock = threading.Lock()
        self._threads: set[threading.Thread] = set()
        self._deliver.connect(self._on_deliver, QtCore.Qt.ConnectionType.QueuedConnection)

    # ------------------------------------------------------------ plumbing

    def _on_deliver(self, callback: Any, result: Any, error: Any) -> None:
        try:
            callback(result, error)
        except Exception:
            logger.exception("GUI callback failed")

    def _emit(self, signal: Any, *args: Any) -> None:
        """Emit from any thread, unless the bridge is closed."""
        with self._lock:
            if not self._closed:
                signal.emit(*args)

    def deliver(self, callback: Done, result: Any = None, error: BaseException | None = None) -> None:
        """Run ``callback(result, error)`` in the GUI thread (safe from any thread)."""
        self._emit(self._deliver, callback, result, error)

    def run_in_thread(self, work: Callable[[], Any], done: Done, name: str = "gui-work") -> threading.Thread:
        def target() -> None:
            try:
                result = work()
            except BaseException as exc:
                self.deliver(done, None, exc)
            else:
                self.deliver(done, result, None)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())
        thread = threading.Thread(target=target, name=name, daemon=True)
        with self._lock:
            self._threads.add(thread)
        thread.start()
        return thread

    @property
    def busy(self) -> bool:
        """A thread started by :meth:`run_in_thread` is still running."""
        with self._lock:
            return any(thread.is_alive() for thread in self._threads)

    # ------------------------------------------------------------- helper

    @property
    def is_connected(self) -> bool:
        return self.client is not None and getattr(self.client, "running", False)

    def connect_helper(self, prefer_sudo: bool = False) -> None:
        if self.is_connected or self._connecting:
            return
        self._connecting = True

        def on_event(event: str, data: Any, job: int | None) -> None:
            self._emit(self.helper_event, event, data, job)

        def work() -> dict[str, Any]:
            client = self._factory(on_event)
            client.start(prefer_sudo=prefer_sudo)
            self.client = client
            return client.call("helper.info", timeout=60)

        def done(info: Any, error: BaseException | None) -> None:
            self._connecting = False
            if error is not None:
                self.client = None
                message = str(error) if isinstance(error, (HelperStartError, RemoteError)) else \
                    f"{type(error).__name__}: {error}"
                self.connection_failed.emit(message)
                return
            self.info = info
            self.connected.emit(info)

        self.run_in_thread(work, done, "helper-start")

    def call(self, method: str, params: dict[str, Any] | None, done: Done,
             on_event: Callable[[str, Any, int | None], None] | None = None) -> int | None:
        if not self.is_connected:
            self.deliver(done, None, RemoteError("failed", "not connected to the helper"))
            return None

        def callback(result: Any, error: BaseException | None) -> None:
            self.deliver(done, result, error)
            if error is not None and not self.is_connected:
                self._emit(self.disconnected)

        relay = None
        if on_event is not None:
            def relay(event: str, data: Any, job: int | None) -> None:
                self.deliver(lambda _r, _e: on_event(event, data, job))
        try:
            return self.client.call_async(method, params or {}, callback, relay)
        except RemoteError as exc:
            self.deliver(done, None, exc)
            self.disconnected.emit()
            return None

    def close(self, wait: float = 2.0) -> None:
        """Stop emitting, close the helper, and give running threads ``wait`` seconds to end."""
        with self._lock:
            self._closed = True
            threads = list(self._threads)
        client, self.client = self.client, None
        if client is not None:
            try:
                client.close()
            except Exception:
                logger.exception("closing the helper failed")
        deadline = time.monotonic() + wait
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
