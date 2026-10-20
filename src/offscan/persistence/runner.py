"""Run persistence, integrity and optional tool checks for a scan (inside the helper).

For every selected volume the runner finds the installations on it (a
Windows system, Linux roots, including btrfs subvolumes such as ``/@``, or
a separate home volume), collects their files, has the sandbox parse them
and turns the results into :class:`~offscan.scan.results.Detection`
objects with engine ``persistence``, ``integrity`` or ``tool``.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import log, names, privdrop, sandbox
from ..drives import osdetect
from ..safefs import RootFS
from ..scan.results import Detection
from . import external, linux, packages, windows

logger = log.get("persistence.runner")

SUBVOLUME_NAMES = (b"@", b"@root", b"@rootfs", b"root", b"rootfs")
HOME_SUBVOLUMES = (b"@home", b"home")


@dataclass
class OSRoot:
    volume: str
    mountpoint: str
    prefix: bytes                  # where the installation lives inside the volume (b"" or b"/@")
    kind: str                      # windows | linux | linux_home
    name: str

    def open(self) -> RootFS:
        root = RootFS(self.mountpoint)
        if not self.prefix:
            return root
        try:
            return root.subroot(self.prefix)
        finally:
            root.close()

    def to_volume(self, path: str | None) -> str | None:
        """OS-root path (wire form) -> volume-relative path (wire form)."""
        if not path or not path.startswith("/"):
            return None
        return names.to_wire(self.prefix + names.from_wire(path)) if self.prefix else path


def find_roots(volume: str, mountpoint: str) -> list[OSRoot]:
    roots: list[OSRoot] = []
    with RootFS(mountpoint) as root:
        if osdetect.windows_hive(root) is not None:
            return [OSRoot(volume, mountpoint, b"", "windows", "Windows")]
        try:
            top = root.listdir(b"/")
        except OSError:
            top = []
        candidates = [b""] + [b"/" + n for n in top if n in SUBVOLUME_NAMES]
        for prefix in candidates:
            try:
                sub = root.subroot(prefix) if prefix else None
            except OSError:
                continue
            try:
                info = osdetect.detect_linux(sub or root)
            finally:
                if sub is not None:
                    sub.close()
            if info is not None and info.family == "linux":
                roots.append(OSRoot(volume, mountpoint, prefix, "linux", info.name))
        subvolume_homes = [b"/" + n for n in top if n in HOME_SUBVOLUMES]
        if not roots:
            homes = [b"", *subvolume_homes]           # a separate /home volume
        elif all(r.prefix for r in roots):
            homes = subvolume_homes                   # btrfs layout: /@ and /@home
        else:
            homes = []                                # /home is inside the root and checked with it
        for prefix in homes:
            try:
                sub = root.subroot(prefix) if prefix else None
            except OSError:
                continue
            try:
                if linux.looks_like_home_volume(sub or root):
                    roots.append(OSRoot(volume, mountpoint, prefix, "linux_home", "Home folders"))
                    break
            finally:
                if sub is not None:
                    sub.close()
    return roots


def fingerprint(finding: dict[str, Any]) -> str:
    extra = finding.get("extra") or {}
    text = "\0".join(str(x) for x in (finding.get("check"), finding.get("location"), finding.get("value"),
                                      extra.get("actual", "")))
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def to_detection(osroot: OSRoot, finding: dict[str, Any], engine: str, source: str) -> Detection:
    file = osroot.to_volume(finding.get("file")) or ""
    target = osroot.to_volume(finding.get("target"))
    details: dict[str, Any] = {
        "check": finding.get("check"), "location": finding.get("location"), "value": finding.get("value"),
        "reasons": finding.get("reasons") or [], "mitre": finding.get("mitre"), "user": finding.get("user"),
        "target": target, "installation": osroot.name, "fingerprint": fingerprint(finding),
        **(finding.get("extra") or {})}
    if osroot.prefix:
        details["root"] = names.to_wire(osroot.prefix)
    return Detection(volume=osroot.volume, path=file, engine=engine,
                     signature=str(finding.get("title"))[:500], severity=str(finding.get("severity", "info")),
                     source=source,
                     category=str(finding.get("check")), details=details)


Emit = Callable[[Detection], None]
Status = Callable[[str, str, dict[str, Any] | None], None]


@dataclass
class ChecksRunner:
    mounts: dict[str, str]
    mode: str
    tools: list[str]
    identity: privdrop.Identity | None
    emit: Emit
    status: Status
    cancelled: threading.Event
    roots: list[OSRoot] = field(default_factory=list)
    targets: dict[str, set[bytes]] = field(default_factory=dict)       # volume -> paths to scan first
    summary: dict[str, Any] = field(default_factory=dict)
    windows_volumes: set[str] = field(default_factory=set)

    def discover(self) -> None:
        for volume, mountpoint in self.mounts.items():
            try:
                found = find_roots(volume, mountpoint)
            except OSError as exc:
                logger.warning("cannot inspect %s: %s", volume, exc)
                continue
            self.roots.extend(found)
            for osroot in found:
                if osroot.kind == "windows":
                    self.windows_volumes.add(volume)
                self._info(osroot)["kind"] = osroot.kind

    def _info(self, osroot: OSRoot) -> dict[str, Any]:
        key = osroot.volume + (f":{names.to_wire(osroot.prefix)}" if osroot.prefix else "")
        return self.summary.setdefault(key, {"volume": osroot.volume, "installation": osroot.name,
                                             "root": names.to_wire(osroot.prefix) or "/"})

    # ---------------------------------------------------------------- phases

    def persistence(self) -> None:
        for osroot in self.roots:
            if self.cancelled.is_set():
                return
            info = self._info(osroot)
            started = time.monotonic()
            label = "Windows" if osroot.kind == "windows" else osroot.name
            self.status("persistence", f"Checking autostart entries of {label}…", None)
            try:
                with osroot.open() as root:
                    if osroot.kind == "windows":
                        args, fds = windows.collect(root)
                        task = "windows.persistence"
                    else:
                        args, fds = linux.collect(root, home_volume=osroot.kind == "linux_home")
                        task = "linux.persistence"
                try:
                    result = sandbox.run(task, args, fds, timeout=1800)
                finally:
                    for fd in fds:
                        os.close(fd)
            except (sandbox.SandboxError, OSError) as exc:
                info["persistence"] = {"error": str(exc)[:500]}
                logger.warning("persistence checks failed for %s: %s", osroot.volume, exc)
                continue
            found = result.get("findings", [])
            for finding in found:
                self.emit(to_detection(osroot, finding, "persistence", "persistence"))
            wanted = self.targets.setdefault(osroot.volume, set())
            for target in result.get("targets", [])[:5000]:
                path = osroot.to_volume(target)
                if path:
                    wanted.add(names.from_wire(path))
            info["persistence"] = {"findings": len(found), "errors": result.get("errors", [])[:50],
                                   "info": result.get("info", {}),
                                   "seconds": round(time.monotonic() - started, 1)}

    def integrity(self, setid: dict[str, list[dict[str, Any]]]) -> None:
        for osroot in self.roots:
            if self.cancelled.is_set() or osroot.kind != "linux":
                continue
            info = self._info(osroot)
            started = time.monotonic()
            try:
                with osroot.open() as root:
                    db = packages.detect(root)
                    if db is None:
                        # Without a package list only SUID files in odd places can be judged.
                        info["integrity"] = {"error": "no package database found"}
                        empty = packages.PackageIndex("none", [], [])
                        odd = [f for f in packages.unowned(root, empty, self._setid_for(osroot, setid))
                               if f.check == "integrity.setid" and f.severity == "high"]
                        self._emit_all(osroot, odd, "integrity", "integrity")
                        continue
                    self.status("integrity", f"Reading the {db['manager']} package database…", None)
                    args, fds = packages.collect(root, db)
                    try:
                        result = sandbox.run("packages.list", args, fds, timeout=1800)
                    finally:
                        for fd in fds:
                            os.close(fd)
                    index = packages.PackageIndex.from_result(result)
                    wanted = self.targets.get(osroot.volume, set())
                    extra = [names.to_wire(osroot_path(osroot, p)) for p in wanted]

                    def progress(done: int, total: int) -> None:
                        self.status("integrity", "Verifying installed packages…",
                                    {"done": done, "total": total})

                    scope = "full" if self.mode == "full" else "quick"
                    findings, counters = packages.verify(root, index, scope, extra, self.cancelled, progress)
                    findings += packages.unowned(root, index, self._setid_for(osroot, setid), self.cancelled)
            except (sandbox.SandboxError, OSError, KeyError, ValueError) as exc:
                info["integrity"] = {"error": str(exc)[:500]}
                logger.warning("integrity checks failed for %s: %s", osroot.volume, exc)
                continue
            self._emit_all(osroot, findings, "integrity", db["manager"])
            info["integrity"] = {"manager": db["manager"], "packages": len(index.packages), **counters,
                                 "scope": scope, "errors": index.errors[:50],
                                 "seconds": round(time.monotonic() - started, 1)}

    def run_tools(self) -> None:
        for osroot in self.roots:
            if self.cancelled.is_set():
                return
            info = self._info(osroot)
            results: dict[str, Any] = {}
            if osroot.kind == "linux" and "chkrootkit" in self.tools:
                self.status("tools", f"Running chkrootkit on {osroot.name}…", None)
                path = os.path.join(osroot.mountpoint, os.fsdecode(osroot.prefix.lstrip(b"/")))
                results["chkrootkit"] = self._tool(osroot, external.run_chkrootkit, path, self.identity)
            if osroot.kind == "windows" and {"hayabusa", "chainsaw"} & set(self.tools):
                with osroot.open() as root:
                    logs = root.find_ci("Windows/System32/winevt/Logs")
                if logs is None:
                    results["event_logs"] = {"error": "no event logs found"}
                else:
                    evtx = os.path.join(osroot.mountpoint, os.fsdecode(logs.lstrip(b"/")))
                    for name, func in (("hayabusa", external.run_hayabusa),
                                       ("chainsaw", external.run_chainsaw)):
                        if name in self.tools and not self.cancelled.is_set():
                            self.status("tools", f"Running {name.capitalize()} on the event logs…", None)
                            results[name] = self._tool(osroot, func, evtx, self.identity)
            if results:
                info["tools"] = results

    def _tool(self, osroot: OSRoot, func: Callable[..., Any], *args: Any) -> dict[str, Any]:
        try:
            findings, meta = func(*args)
        except Exception as exc:          # a broken optional tool must not fail the scan
            return {"error": f"{type(exc).__name__}: {exc}"[:500]}
        self._emit_all(osroot, findings, "tool", findings[0].check.split(".", 1)[1] if findings else "tool")
        return {**meta, "findings": len(findings)}

    def _emit_all(self, osroot: OSRoot, findings: list[Any], engine: str, source: str) -> None:
        for finding in findings:
            self.emit(to_detection(osroot, finding.to_dict(), engine, source))

    @staticmethod
    def _setid_for(osroot: OSRoot, setid: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        out = []
        for item in setid.get(osroot.volume, []):
            path: bytes = item["path"]
            if osroot.prefix:
                if not path.startswith(osroot.prefix + b"/"):
                    continue
                path = path[len(osroot.prefix):]
            out.append({**item, "path": names.to_wire(path)})
        return out


def osroot_path(osroot: OSRoot, volume_path: bytes) -> bytes:
    """Volume-relative path -> path inside the installation."""
    if osroot.prefix and volume_path.startswith(osroot.prefix + b"/"):
        return volume_path[len(osroot.prefix):]
    return volume_path
