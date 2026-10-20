"""Update definitions: fetch due sources, build a new set, validate, activate.

Store layout (under :func:`offscan.defs.store.store_dir`)::

    sources/<id>/state.json          version, timestamps, ETags, cool-down, last error
    sources/<id>/v<timestamp>/       immutable verified material (+ material.json)
    sets/<set-id>/                   built definition sets (see layout.py)
    active, previous                 symlinks (atomic swap; rollback)

Nothing replaces the active set unless the new set was built completely and
passed the smoke test; a failed source keeps its previous version.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import log, paths
from ..scan import hashdb
from ..settings import Settings
from . import build, layout, net, store, testset, verify
from .sources import Source, all_sources
from .sources.base import FetchContext, SourceError, Unchanged, iter_digest_file, load_material, read_digests

logger = log.get("defs.updater")
Progress = Callable[[str, str], None]          # (source id, message)


class UpdateError(Exception):
    pass


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


class Updater:
    def __init__(self, base: Path | None = None, settings: Settings | None = None,
                 session: net.Session | None = None, sources: list[Source] | None = None):
        self.base = base or store.store_dir()
        self.settings = settings or Settings()
        self.session = session or net.Session()
        self.sources = sources if sources is not None else all_sources(self.settings)
        self._lock_fd: int | None = None

    # ------------------------------------------------------------------ state

    def source_dir(self, sid: str) -> Path:
        return self.base / "sources" / sid

    def load_state(self, sid: str) -> dict[str, Any]:
        try:
            return json.loads((self.source_dir(sid) / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save_state(self, sid: str, state: dict[str, Any]) -> None:
        directory = self.source_dir(sid)
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / "state.json.tmp"
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(directory / "state.json")

    def current_dir(self, sid: str, state: dict[str, Any] | None = None) -> Path | None:
        state = state if state is not None else self.load_state(sid)
        name = state.get("dir")
        if not name:
            return None
        path = self.source_dir(sid) / name
        return path if (path / "material.json").exists() else None

    def _acquire(self) -> None:
        paths.ensure_dir(self.base, 0o755)
        fd = os.open(self.base / "update.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise UpdateError("another definitions update is already running") from exc
        self._lock_fd = fd

    def _release(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    # --------------------------------------------------------------- update

    def due(self, source: Source, state: dict[str, Any], force: bool, now: float) -> tuple[bool, str]:
        cooldown = float(state.get("cooldown_until", 0))
        if cooldown > now:
            until = time.strftime("%Y-%m-%d %H:%M", time.localtime(cooldown))
            return False, f"rate limited by the server until {until}"
        last = float(state.get("last_check", 0))
        if not force and last and now - last < source.min_interval() and self.current_dir(source.id, state):
            return False, "checked recently"
        # Even forced, never hammer the official ClamAV CDN.
        if force and source.id == "clamav" and last and now - last < 3600:
            return False, "ClamAV allows at most one check per hour"
        return True, ""

    def update(self, only: list[str] | None = None, force: bool = False,
               progress: Progress | None = None, cancel: threading.Event | None = None,
               rebuild: bool = False) -> dict[str, Any]:
        progress = progress or (lambda sid, msg: None)
        cancel = cancel or threading.Event()
        report: dict[str, Any] = {"sources": {}, "set": None}
        self._acquire()
        try:
            updated = False
            for source in self.sources:
                if only and source.id not in only:
                    continue
                if not source.enabled():
                    continue
                if cancel.is_set():
                    break
                result = self._update_one(source, force, progress, cancel)
                report["sources"][source.id] = result
                updated |= result["result"] == "updated"
            if updated or rebuild or store.active_set(self.base) is None:
                progress("", "Building and testing the new definition set…")
                report["set"] = self.build_and_activate()
            self.gc()
        finally:
            self._release()
        return report

    def _update_one(self, source: Source, force: bool, progress: Progress,
                    cancel: threading.Event) -> dict[str, Any]:
        sid = source.id
        state = self.load_state(sid)
        now = time.time()
        ok, why = source.configured()
        if not ok:
            return {"result": "skipped", "message": why}
        due, why = self.due(source, state, force, now)
        if not due:
            return {"result": "skipped", "message": why}
        directory = self.source_dir(sid)
        directory.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=directory))
        work_state = json.loads(json.dumps(state))
        ctx = FetchContext(session=self.session, settings=self.settings, staging=staging,
                           previous=self.current_dir(sid, state), state=work_state, cancel=cancel,
                           progress=lambda msg: progress(sid, msg), now=now, store=self.base)
        progress(sid, f"Checking {source.info.name}…")
        try:
            material = source.fetch(ctx)
            version_dir = directory / f"v{int(now)}"
            if version_dir.exists():
                version_dir = directory / f"v{int(now)}-{os.getpid()}"
            os.replace(staging, version_dir)
            work_state.update({"version": str(material.get("version", "?")), "dir": version_dir.name,
                               "updated": now, "last_check": now, "error": None,
                               "size": _dir_size(version_dir), "verified": material.get("verified"),
                               "count": material.get("count") or material.get("rules")})
            self.save_state(sid, work_state)
            return {"result": "updated", "version": work_state["version"]}
        except Unchanged:
            work_state.update({"last_check": now, "error": None})
            self.save_state(sid, work_state)
            return {"result": "unchanged", "version": state.get("version")}
        except net.RateLimited as exc:
            state.update({"cooldown_until": now + exc.retry_after, "last_check": now,
                          "error": str(exc)})
            self.save_state(sid, state)
            return {"result": "rate_limited", "message": str(exc)}
        except (SourceError, net.DownloadError, verify.VerificationError, hashdb.HashDBError,
                OSError, ValueError) as exc:
            state.update({"last_check": now, "error": log.redact(str(exc))[:500]})
            self.save_state(sid, state)
            logger.warning("%s: %s", sid, log.redact(str(exc)))
            return {"result": "failed", "message": log.redact(str(exc))}
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # ----------------------------------------------------------------- build

    def build_and_activate(self, set_id: str | None = None) -> dict[str, Any]:
        set_id = set_id or time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        out = store.sets_dir(self.base) / set_id
        if out.exists():
            out = out.with_name(f"{set_id}-{os.getpid()}")
        clamav_files: dict[str, Path | bytes] = dict(testset.clamav_signatures())
        clamav_official: str | None = None
        yara_sources = [("selftest", "selftest/selftest.yar", testset.yara_rule())]
        yara_ns = {"selftest": testset.SOURCE_ID}
        selftest_digest = hashlib.sha256(testset.eicar()).digest()
        hash_lists: dict[str, tuple[dict[str, Any], Any]] = {testset.SOURCE_ID: (
            {"name": "Self-test", "category": "test", "severity": "info",
             "signature": testset.HASH_SIGNATURE}, [selftest_digest])}
        authentihash_lists: dict[str, tuple[dict[str, Any], Any]] = {}
        known_good = None
        sources_info: dict[str, Any] = {}
        source_dirs: dict[str, str] = {}
        for source in self.sources:
            if not source.enabled():
                continue
            state = self.load_state(source.id)
            vdir = self.current_dir(source.id, state)
            if vdir is None:
                continue
            material = load_material(vdir)
            source_dirs[source.id] = vdir.name
            info = source.info
            sources_info[source.id] = {
                "name": info.name, "kind": info.kind, "version": state.get("version"),
                "updated": state.get("updated"), "size": state.get("size"), "license": info.license,
                "license_url": info.license_url, "verified": state.get("verified")}
            for name in material.get("clamav", []):
                target = name if name not in clamav_files else f"{source.id}-{name}"
                clamav_files[target] = vdir / name
            if material.get("clamav_official"):
                clamav_official = material["clamav_official"]
            for item in material.get("yara", []):
                text = (vdir / item["file"]).read_text(encoding="utf-8", errors="replace")
                yara_sources.append((source.id.replace("-", "_"), f"{source.id}/{item['origin']}", text))
                yara_ns[source.id.replace("-", "_")] = source.id
            for item in material.get("hashes", []):
                hash_lists[item["id"]] = (item["meta"], read_digests(vdir / item["file"]))
            for item in material.get("authentihash", []):
                authentihash_lists[item["id"]] = (item["meta"], read_digests(vdir / item["file"]))
            if material.get("known_good"):
                known_good = iter_digest_file(vdir / material["known_good"])
        try:
            manifest = build.build_set(
                out, set_id=out.name, sources=sources_info, clamav_files=clamav_files,
                clamav_official=clamav_official, yara_sources=yara_sources, yara_namespaces=yara_ns,
                hash_lists=hash_lists, authentihash_lists=authentihash_lists or None,
                known_good=known_good, known_good_sorted=True,
                extra={"source_dirs": source_dirs})
            self.smoke_test(out)
        except Exception:
            shutil.rmtree(out, ignore_errors=True)
            raise
        store.activate(out, self.base)
        return {"id": manifest["id"], "rules": manifest.get("yara", {}).get("rules"),
                "hashes": manifest.get("hashes", {}).get("malware_count"),
                "clamav_files": len(manifest["clamav"]["files"]), "clamav_official": clamav_official,
                "yara_errors": len(manifest.get("yara", {}).get("errors", []))}

    def smoke_test(self, set_dir: Path) -> None:
        """The new set must load and detect the EICAR test file with every engine it has."""
        from ..scan import runtime, worker
        from ..scan.options import Limits, ScanOptions
        with tempfile.TemporaryDirectory(prefix="smoke-") as tmp:
            rt = runtime.prepare(set_dir, ScanOptions(volumes=["x"], workers=1), os.geteuid(),
                                 os.getegid(), base=tmp)
            has_yara = bool((layout.load_manifest(set_dir).get("yara") or {}).get("file"))
            engines_wanted = ["hashes"] + (["yara"] if has_yara else [])
            config = {"runtime": str(rt), "engines": engines_wanted, "mode": "full",
                      "limits": vars(Limits()), "clamd": False}
            engines = worker.Engines(rt, config)
            sample = Path(tmp) / "eicar.com"
            sample.write_bytes(testset.eicar())
            fd = os.open(sample, os.O_RDONLY)
            try:
                result = worker.process(engines, {"id": 0, "path": "/eicar.com", "mode": "full"}, fd)
            finally:
                os.close(fd)
            found = {d["engine"] for d in result["detections"]}
            expected = {"hashes": "hash", "yara": "yara"}
            missing = {name for name in engines_wanted if expected[name] not in found}
            if missing:
                names = ", ".join(sorted(missing))
                raise UpdateError(f"the new definition set failed its self-test ({names})")
            clamdir = set_dir / "clamav"
            if any(p.suffix not in (".cvd", ".cld", ".cud", ".sign") for p in clamdir.iterdir()):
                third_party = Path(tmp) / "third-party"
                third_party.mkdir()
                for path in clamdir.iterdir():
                    if path.suffix not in (".cvd", ".cld", ".cud", ".sign"):
                        os.link(path, third_party / path.name)
                self._clamscan_detects(third_party, sample)

    @staticmethod
    def _clamscan_detects(dbdir: Path, sample: Path) -> None:
        from .. import tools
        clamscan = tools.find("clamscan")
        if clamscan is None:
            return
        proc = tools.run([clamscan, "--no-summary", f"--database={dbdir}", str(sample)], timeout=900,
                         check=False)
        if proc.returncode != 1:
            raise UpdateError("ClamAV could not load the combined third-party signatures: "
                              + (proc.stderr or proc.stdout).strip()[-300:])

    # -------------------------------------------------------------- maintenance

    def rollback(self) -> Path:
        return store.rollback(self.base)

    def gc(self) -> None:
        keep_sets: set[Path] = set()
        referenced: dict[str, set[str]] = {}
        for link in ("active", "previous"):
            try:
                target = (self.base / link).resolve(strict=True)
            except OSError:
                continue
            keep_sets.add(target)
            try:
                for sid, name in layout.load_manifest(target).get("source_dirs", {}).items():
                    referenced.setdefault(sid, set()).add(name)
            except layout.LayoutError:
                pass
        sets = store.sets_dir(self.base)
        if sets.is_dir():
            for child in sets.iterdir():
                if child.resolve() not in keep_sets:
                    shutil.rmtree(child, ignore_errors=True)
        sources_root = self.base / "sources"
        if sources_root.is_dir():
            for sdir in sources_root.iterdir():
                current = self.load_state(sdir.name).get("dir")
                keep = referenced.get(sdir.name, set()) | ({current} if current else set())
                for child in sdir.iterdir():
                    if child.is_dir() and child.name.startswith("v") and child.name not in keep:
                        shutil.rmtree(child, ignore_errors=True)

    # ----------------------------------------------------------------- status

    def status(self) -> dict[str, Any]:
        now = time.time()
        active = store.active_set(self.base)
        manifest = None
        if active is not None:
            try:
                manifest = layout.load_manifest(active)
            except layout.LayoutError:
                manifest = None
        sources = []
        for source in self.sources:
            state = self.load_state(source.id)
            configured, why = source.configured()
            interval = source.min_interval()
            last = float(state.get("last_check", 0))
            cooldown = float(state.get("cooldown_until", 0))
            sources.append({
                **source.info.to_dict(),
                "enabled": source.enabled(), "configured": configured, "configure_hint": why,
                "accepted_license": bool(self.settings.source(source.id).get("accepted_license")),
                "version": state.get("version"), "updated": state.get("updated"),
                "last_check": state.get("last_check"), "error": state.get("error"),
                "size": state.get("size"), "count": state.get("count"),
                "verified": state.get("verified"),
                "cooldown_until": cooldown if cooldown > now else None,
                "next_check": (last + interval) if last else None,
                "in_active_set": bool(manifest and source.id in manifest.get("sources", {})),
            })
        return {"store": str(self.base),
                "active": None if manifest is None else {
                    "id": manifest["id"], "created": manifest.get("created"),
                    "yara_rules": (manifest.get("yara") or {}).get("rules"),
                    "yara_engine": (manifest.get("yara") or {}).get("engine"),
                    "hashes": (manifest.get("hashes") or {}).get("malware_count"),
                    "clamav_files": len(manifest.get("clamav", {}).get("files", [])),
                    "clamav_official": manifest.get("clamav", {}).get("official")},
                "previous": self._previous_id(), "sources": sources}

    def _previous_id(self) -> str | None:
        try:
            return (self.base / "previous").resolve(strict=True).name
        except OSError:
            return None
