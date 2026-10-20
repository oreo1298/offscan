"""Client-side scan session (shared by the CLI and the GUI)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import log
from .client import HelperClient
from .defs import layout, store
from .history import History
from .protocol import RemoteError
from .scan import runtime
from .scan.options import ScanOptions
from .scan.results import Detection

logger = log.get("scanning")

EventHandler = Callable[[str, Any], None]


class ScanSession:
    def __init__(self, client: HelperClient, options: ScanOptions, set_dir: Path | None = None,
                 on_event: EventHandler | None = None, history: History | None = None):
        self.client = client
        self.options = options
        self.set_dir = set_dir
        self.on_event = on_event
        self.history = history
        self.detections: list[Detection] = []
        self.summary: dict[str, Any] | None = None
        self.scan_id: int | None = None
        self.job: int | None = None
        self.runtime: Path | None = None
        self.targets: list[dict[str, Any]] = []
        self.definitions: dict[str, Any] = {}
        self._done = threading.Event()
        self.error: BaseException | None = None

    def _event(self, event: str, data: Any, job: int | None) -> None:
        if event == "scan.detection" and isinstance(data, dict):
            try:
                det = Detection.from_dict(data)
            except TypeError:
                return
            if self.history is not None and self.history.is_false_positive(det):
                det.details["false_positive"] = True
            self.detections.append(det)
        if self.on_event is not None:
            self.on_event(event, data)

    def prepare(self) -> None:
        set_dir = self.set_dir or store.active_set()
        if set_dir is None:
            raise RemoteError("not_found", "no definitions are installed yet; update definitions first")
        manifest = layout.load_manifest(set_dir)
        self.definitions = {"set": manifest.get("id"), "created": manifest.get("created"),
                            "sources": {k: v.get("version") for k, v in manifest.get("sources", {}).items()}}
        info = self.client.call("helper.info", timeout=60)
        self.runtime = runtime.prepare(set_dir, self.options, int(info["scan_uid"]), int(info["scan_gid"]))
        self.options.runtime_dir = str(self.runtime)

    def _describe_targets(self) -> None:
        try:
            disks = self.client.call("drives.list", {"probe": "cached"}, timeout=120)["disks"]
        except RemoteError:
            return
        wanted = set(self.options.volumes)

        def visit(vols: list[dict[str, Any]], disk: dict[str, Any]) -> None:
            for vol in vols:
                if vol["id"] in wanted:
                    self.targets.append({"volume": vol["id"], "device": vol["device"],
                                         "label": vol.get("label"), "fstype": vol.get("fstype"),
                                         "os": vol.get("os"), "disk": disk.get("model")})
                visit(vol.get("children", []), disk)
        for disk in disks:
            visit(disk["volumes"], disk)

    def run(self) -> dict[str, Any]:
        """Blocking run (CLI)."""
        try:
            self.prepare()
            self._describe_targets()
            self.job, future = self.client.submit("scan.start", {"options": self.options.to_dict()},
                                                  on_event=self._event)
            self.summary = future.result()
        finally:
            self._finish()
        return self.summary

    def start(self, done: Callable[[dict[str, Any] | None, BaseException | None], None]) -> None:
        """Non-blocking run (GUI); ``done`` is called from a background thread."""
        def worker() -> None:
            try:
                self.run()
                done(self.summary, None)
            except BaseException as exc:
                self.error = exc
                done(None, exc)
        threading.Thread(target=worker, name="scan-session", daemon=True).start()

    def _finish(self) -> None:
        if self.runtime is not None:
            runtime.cleanup(self.runtime)
            self.runtime = None
        if self.history is not None and self.summary is not None:
            try:
                self.scan_id = self.history.add_scan(self.summary, self.options.to_dict(), self.targets,
                                                     self.detections, self.definitions)
            except Exception as exc:
                logger.error("could not record scan history: %s", exc)
        self._done.set()

    def cancel(self) -> None:
        if self.job is not None:
            self.client.cancel(self.job)

    def pause(self) -> None:
        if self.job is not None:
            self.client.call("scan.pause", {"job": self.job}, timeout=30)

    def resume(self) -> None:
        if self.job is not None:
            self.client.call("scan.resume", {"job": self.job}, timeout=30)
