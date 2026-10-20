"""A scan job, run inside the helper.

Phases: validate the client-prepared runtime directory -> mount volumes
(read-only) -> start the private clamd and the worker pool -> walk and
dispatch -> collect results -> summary.  Progress, detections and status
are streamed as protocol events; pause/resume/cancel are honoured between
files.
"""

from __future__ import annotations

import os
import queue
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import log, names, privdrop
from ..safefs import RootFS
from . import clamd, walker
from .options import ScanOptions
from .pool import WorkerPool
from .results import Detection, ScanSummary

logger = log.get("scan.job")

Emit = Callable[[str, Any], None]
PROGRESS_INTERVAL = 0.5
QUEUE_SIZE = 256


class ScanError(Exception):
    def __init__(self, message: str, code: str = "failed"):
        super().__init__(message)
        self.code = code


def validate_runtime(path: str, identity: privdrop.Identity | None) -> Path:
    """The runtime dir is prepared by the (unprivileged) client; check it is safe to use.

    The helper never reads or writes inside it; it only passes the path to
    processes that run as the scan identity.
    """
    if not path or not os.path.isabs(path) or "\0" in path:
        raise ScanError("invalid runtime directory", "invalid_params")
    real = os.path.realpath(path)
    if real != os.path.normpath(path) or not real.startswith("/tmp/"):
        raise ScanError("runtime directory must be a real directory under /tmp", "invalid_params")
    st = os.lstat(real)
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        raise ScanError("runtime directory must be a private (0700) directory", "invalid_params")
    expected = identity.uid if identity is not None else os.geteuid()
    if st.st_uid != expected:
        raise ScanError("runtime directory is not owned by the scanning user", "not_permitted")
    return Path(real)


class ScanJob:
    def __init__(self, job_id: int, options: ScanOptions, mounts: dict[str, str], emit: Emit,
                 cancelled: threading.Event, identity: privdrop.Identity | None):
        self.job_id = job_id
        self.options = options
        self.mounts = mounts                 # volume id -> mount point
        self.emit = emit
        self.cancelled = cancelled
        self.paused = threading.Event()
        self.identity = identity
        self.summary = ScanSummary(job_id, "running", time.time(), 0.0)
        self.totals = {"files": None, "bytes": None}
        self._last_progress = 0.0
        self._current = ""
        self._rates: list[tuple[float, int, int]] = []
        self.seen_detections: set[tuple[str, str, str, str]] = set()

    # ------------------------------------------------------------- helpers

    def status(self, phase: str, message: str) -> None:
        self.emit("scan.status", {"phase": phase, "message": message})

    def _starts(self) -> list[bytes]:
        if self.options.mode == "custom":
            return [os.fsencode(p if p.startswith("/") else "/" + p) for p in self.options.paths]
        return [b"/"]

    # ----------------------------------------------------------- estimator

    def _estimate(self) -> None:
        files = size = 0
        try:
            for mountpoint in self.mounts.values():
                with RootFS(mountpoint) as root:
                    def partial(f: int, b: int, base_f: int = files, base_b: int = size) -> None:
                        self.totals["partial"] = (base_f + f, base_b + b)
                    f, b = walker.estimate(root, self._starts(), self.options.mode, self.cancelled,
                                           partial)
                    files += f
                    size += b
            self.totals["files"], self.totals["bytes"] = files, size
        except Exception as exc:
            logger.warning("estimate failed: %s", exc)

    # ------------------------------------------------------------- walker

    def _produce(self, out: queue.Queue, stats: walker.WalkStats) -> None:
        try:
            for volume, mountpoint in self.mounts.items():
                with RootFS(mountpoint) as root:
                    for start in self._starts():
                        for item in walker.walk(root, start, self.options.mode, self.cancelled, stats):
                            while not self.cancelled.is_set():
                                try:
                                    out.put((volume, item), timeout=0.5)
                                    break
                                except queue.Full:
                                    continue
                            else:
                                os.close(item.fd)
                                return
        except Exception as exc:
            logger.error("walker failed: %s", exc)
            stats.error(b"/", f"walker failed: {exc}")
        finally:
            out.put(None)

    # --------------------------------------------------------------- run

    def run(self) -> ScanSummary:
        opts = self.options
        runtime = Path(opts.runtime_dir)
        clamd_proc = None
        pool = None
        stats = walker.WalkStats()
        try:
            want_clamav = "clamav" in opts.engines and (runtime / "clamav").is_dir() \
                and clamd.clamd_binary() is not None
            if "clamav" in opts.engines and not want_clamav:
                self.summary.engines["clamav"] = {
                    "error": "ClamAV (clamd) or its signatures are not available"}
            if want_clamav:
                self.status("loading", "Starting ClamAV and loading signatures…")
                uid = self.identity.uid if self.identity else None
                gid = self.identity.gid if self.identity else None
                clamd_proc = clamd.start(runtime, uid, gid)
            workers = opts.worker_count()
            config = {
                "runtime": str(runtime), "engines": opts.engines, "mode": opts.mode,
                "limits": vars(opts.limits), "clamd": want_clamav,
                "clamd_wait": 900,
                "drop_to": None,
            }
            pool = WorkerPool(workers, config, self.identity,
                              hard_timeout=opts.limits.file_timeout * 3 + 60)
            pool.start()
            threading.Thread(target=self._estimate, name="estimate", daemon=True).start()
            self.status("loading", "Loading definitions…")

            def waiting() -> None:
                if clamd_proc is not None and clamd_proc.poll() is not None:
                    raise ScanError("clamd exited while loading signatures (out of memory?)")
                if self.cancelled.is_set():
                    raise ScanError("cancelled", "cancelled")
                self._progress(force=False)
            status = pool.wait_ready(timeout=1200, on_wait=waiting)
            self.summary.engines.update({k: v for k, v in status.items()})
            self.emit("scan.engines", self.summary.engines)
            self.status("scanning", "Scanning…")
            items: queue.Queue = queue.Queue(maxsize=QUEUE_SIZE)
            producer = threading.Thread(target=self._produce, args=(items, stats), name="walk",
                                        daemon=True)
            producer.start()
            self._dispatch(pool, items, stats)
            producer.join(timeout=30)
            self.summary.state = "cancelled" if self.cancelled.is_set() else "finished"
        except ScanError as exc:
            self.summary.state = "cancelled" if exc.code == "cancelled" else "failed"
            self.summary.message = str(exc)
        except Exception as exc:
            logger.exception("scan failed")
            self.summary.state = "failed"
            self.summary.message = f"{type(exc).__name__}: {exc}"
        finally:
            if pool is not None:
                pool.shutdown()
            if clamd_proc is not None:
                clamd.stop(clamd_proc)
        self.summary.errors += stats.error_count
        for path, message in stats.errors[:50]:
            self._sample_error(path, message)
        self.summary.finished = time.time()
        self._progress(force=True)
        return self.summary

    def _dispatch(self, pool: WorkerPool, items: queue.Queue, stats: walker.WalkStats) -> None:
        next_id = 0
        producer_done = False
        pending_item = None
        while True:
            if self.cancelled.is_set():
                break
            # Hand out work while workers have capacity.
            while not self.paused.is_set() and not producer_done:
                worker = pool.free_worker()
                if worker is None:
                    break
                if pending_item is None:
                    try:
                        pending_item = items.get(timeout=0.05)
                    except queue.Empty:
                        break
                if pending_item is None:
                    producer_done = True
                    break
                volume, item = pending_item
                pending_item = None
                next_id += 1
                path = names.to_wire(item.relpath)
                self._current = f"{volume}:{path}"
                try:
                    pool.submit(worker, next_id, {"path": path, "mode": self.options.mode}, item.fd,
                                (volume, path, item.size))
                except OSError as exc:
                    self.summary.errors += 1
                    self._sample_error(item.relpath, f"could not hand file to engine: {exc}")
                finally:
                    os.close(item.fd)
            for result in pool.poll(0.1):
                self._handle_result(result)
            self._progress(force=False)
            if producer_done and pool.inflight == 0:
                break
        # Cancelled: close fds still queued.
        while True:
            try:
                entry = items.get_nowait()
            except queue.Empty:
                break
            if entry is not None:
                os.close(entry[1].fd)

    def _handle_result(self, result: dict[str, Any]) -> None:
        volume, path, size = result["item"]
        if result.get("skipped"):
            self.summary.files_skipped += 1
        else:
            self.summary.files_scanned += 1
            self.summary.bytes_scanned += int(result.get("bytes") or 0)
        for message in result.get("errors") or []:
            if "only hash-checked" in message:
                continue
            self.summary.errors += 1
            self._sample_error(os.fsencode(path), message)
        for raw in result.get("detections") or []:
            if not isinstance(raw, dict):
                continue
            det = Detection(volume=volume, path=path, engine=str(raw.get("engine", "?")),
                            signature=str(raw.get("signature", "?"))[:500],
                            severity=str(raw.get("severity", "high")),
                            sha256=result.get("sha256"), size=size,
                            source=raw.get("source"), category=raw.get("category"),
                            details=raw.get("details") if isinstance(raw.get("details"), dict) else {})
            if result.get("known_good"):
                det.details["known_good"] = True
            if det.key in self.seen_detections:
                continue
            self.seen_detections.add(det.key)
            self.summary.detections += 1
            self.emit("scan.detection", det.to_dict())

    def _sample_error(self, path: bytes, message: str) -> None:
        if len(self.summary.error_samples) < 200:
            self.summary.error_samples.append({"path": names.to_wire(path), "message": message})

    def _progress(self, force: bool) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress < PROGRESS_INTERVAL:
            return
        self._last_progress = now
        s = self.summary
        done_files = s.files_scanned + s.files_skipped
        self._rates.append((now, done_files, s.bytes_scanned))
        self._rates = [r for r in self._rates if now - r[0] <= 10]
        t0, f0, b0 = self._rates[0]
        span = max(now - t0, 1e-6)
        rate_files = (done_files - f0) / span if len(self._rates) > 1 else 0.0
        rate_bytes = (s.bytes_scanned - b0) / span if len(self._rates) > 1 else 0.0
        total_files, total_bytes = self.totals.get("files"), self.totals.get("bytes")
        eta = None
        if total_files and rate_files > 0:
            eta = max(0.0, (total_files - done_files) / rate_files)
        partial = self.totals.get("partial")
        self.emit("scan.progress", {
            "files_done": done_files, "files_scanned": s.files_scanned, "files_skipped": s.files_skipped,
            "bytes_done": s.bytes_scanned, "files_total": total_files, "bytes_total": total_bytes,
            "files_counted": partial[0] if partial else None,
            "rate_files": round(rate_files, 1), "rate_bytes": round(rate_bytes),
            "eta": None if eta is None else round(eta), "current": self._current,
            "errors": s.errors, "detections": s.detections, "paused": self.paused.is_set(),
            "elapsed": round(time.time() - s.started, 1)})
