"""Quarantine, delete and restore: the only operations that change a target.

Every change is an explicit, confirmed request for one file.  It is made in
a short writable session (:mod:`.writable`) and appended to the change log
(``changes.jsonl`` in the system state directory) with everything needed
to see exactly what happened: volume, filesystem UUID, path, size, mode,
owner, SHA-256, the mount used and whether a journal had to be replayed.

Quarantined files are stored in the system quarantine directory (root only),
XOR-scrambled so that no scanner, indexer or double-click on the host can
run or flag them, with their metadata next to them.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from .. import appinfo, log, names, paths, privdrop, protocol
from ..protocol import Param, RemoteError, Schema
from ..safefs import RootFS, open_regular_at
from . import writable
from .server import Context, Server
from .volumes import VolumeError, VolumeManager

logger = log.get("helper.remedy")

KEY = hashlib.sha256(f"{appinfo.NAME} quarantine v1".encode()).digest() * 8     # 256-byte stream
CHUNK = 1 << 20
MAX_QUARANTINE = 8 << 30
ID_RE = re.compile(r"^[0-9a-f]{32}$")
CHANGED = "the file changed since it was confirmed (SHA-256 differs); nothing was done"


def scramble(data: bytes, offset: int) -> bytes:
    """XOR with the fixed key stream (its own inverse)."""
    start = offset % len(KEY)
    stream = (KEY * (len(data) // len(KEY) + 2))[start:start + len(data)]
    return bytes(a ^ b for a, b in zip(data, stream, strict=True)) if len(data) < 4096 else \
        (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


# ------------------------------------------------------------------ change log


def log_change(record: dict[str, Any]) -> None:
    path = paths.change_log()
    paths.ensure_dir(path.parent, 0o755)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def read_changes(limit: int = 500) -> list[dict[str, Any]]:
    try:
        lines = paths.change_log().read_text(encoding="ascii", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# ------------------------------------------------------------------ file operations


class RemedyError(Exception):
    def __init__(self, message: str, code: str = protocol.FAILED):
        super().__init__(message)
        self.code = code


def _hash_fd(fd: int) -> str:
    h = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, CHUNK, offset)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)
        offset += len(chunk)


def inspect(root: RootFS, path: bytes) -> dict[str, Any]:
    """Size, mode and hash of a regular file (links are never followed at the last step)."""
    try:
        fd = root.open_regular(path, follow_last=False)
    except FileNotFoundError as exc:
        raise RemedyError("the file no longer exists", protocol.NOT_FOUND) from exc
    except OSError as exc:
        raise RemedyError(f"not a regular file that can be opened: {exc.strerror or exc}",
                          protocol.NOT_PERMITTED) from exc
    try:
        st = os.fstat(fd)
        return {"sha256": _hash_fd(fd), "size": st.st_size, "mode": st.st_mode, "uid": st.st_uid,
                "gid": st.st_gid, "mtime": st.st_mtime}
    finally:
        os.close(fd)


def _open_checked(root: RootFS, path: bytes, expect_sha256: str) -> tuple[int, int, bytes, os.stat_result]:
    """(dir fd, file fd, name, stat) of the file, after checking it is the one the user confirmed."""
    parent, name = root.resolve(path, follow_last=False)
    try:
        fd = open_regular_at(parent, name)
    except OSError as exc:
        os.close(parent)
        raise RemedyError(f"cannot open the file: {exc.strerror or exc}", protocol.NOT_FOUND) from exc
    st = os.fstat(fd)
    actual = _hash_fd(fd)
    if actual != expect_sha256.lower():
        os.close(fd)
        os.close(parent)
        raise RemedyError(CHANGED, protocol.NOT_PERMITTED)
    return parent, fd, name, st


def _unlink_same(parent: int, name: bytes, st: os.stat_result) -> None:
    now = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
        raise RemedyError("the file was replaced while working on it; nothing was deleted")
    os.unlink(name, dir_fd=parent)
    dfd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _store(fd: int, size: int, meta: dict[str, Any]) -> Path:
    if size > MAX_QUARANTINE:
        raise RemedyError(f"the file is larger than {MAX_QUARANTINE >> 30} GiB; delete it instead")
    base = paths.ensure_dir(paths.quarantine_dir(), 0o700)
    if shutil.disk_usage(base).free < size + (64 << 20):
        raise RemedyError("not enough free space for the quarantine copy")
    entry = base / meta["id"]
    entry.mkdir(mode=0o700)
    data_fd = os.open(entry / "data", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    h = hashlib.sha256()
    try:
        offset = 0
        while True:
            chunk = os.pread(fd, CHUNK, offset)
            if not chunk:
                break
            h.update(chunk)
            os.write(data_fd, scramble(chunk, offset))
            offset += len(chunk)
        os.fsync(data_fd)
    finally:
        os.close(data_fd)
    if h.hexdigest() != meta["sha256"]:
        shutil.rmtree(entry, ignore_errors=True)
        raise RemedyError("the file changed while it was copied to quarantine; nothing was deleted")
    (entry / "meta.json").write_text(json.dumps(meta, indent=1, ensure_ascii=True), encoding="ascii")
    os.chmod(entry / "meta.json", 0o600)
    return entry


def quarantine_file(root: RootFS, path: bytes, expect_sha256: str, context: dict[str, Any]) -> dict[str, Any]:
    parent, fd, name, st = _open_checked(root, path, expect_sha256)
    try:
        meta = {"id": uuid.uuid4().hex, "time": time.time(), "path": names.to_wire(path),
                "sha256": expect_sha256.lower(), "size": st.st_size, "mode": st.st_mode, "uid": st.st_uid,
                "gid": st.st_gid, "mtime": st.st_mtime, **context}
        entry = _store(fd, st.st_size, meta)
        try:
            _unlink_same(parent, name, st)
        except Exception:
            shutil.rmtree(entry, ignore_errors=True)
            raise
        return meta
    finally:
        os.close(fd)
        os.close(parent)


def delete_file(root: RootFS, path: bytes, expect_sha256: str) -> dict[str, Any]:
    parent, fd, name, st = _open_checked(root, path, expect_sha256)
    try:
        _unlink_same(parent, name, st)
        return {"path": names.to_wire(path), "sha256": expect_sha256.lower(), "size": st.st_size,
                "mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime}
    finally:
        os.close(fd)
        os.close(parent)


def load_entry(entry_id: str) -> dict[str, Any]:
    if not ID_RE.match(entry_id):
        raise RemedyError("invalid quarantine id", protocol.INVALID_PARAMS)
    try:
        return json.loads((paths.quarantine_dir() / entry_id / "meta.json").read_text(encoding="ascii"))
    except (OSError, ValueError) as exc:
        raise RemedyError("no such quarantine entry", protocol.NOT_FOUND) from exc


def restore_file(root: RootFS, entry: dict[str, Any], path: bytes) -> dict[str, Any]:
    """Write a quarantined file back (never over an existing file)."""
    parent, name = root.resolve(path, follow_last=False)
    data_path = paths.quarantine_dir() / entry["id"] / "data"
    try:
        try:
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                          dir_fd=parent)
        except FileExistsError as exc:
            raise RemedyError("a file with that name exists again; nothing was restored",
                              protocol.NOT_PERMITTED) from exc
        h = hashlib.sha256()
        try:
            with open(data_path, "rb") as src:
                offset = 0
                while chunk := src.read(CHUNK):
                    plain = scramble(chunk, offset)
                    h.update(plain)
                    os.write(out, plain)
                    offset += len(chunk)
            if h.hexdigest() != entry["sha256"]:
                raise RemedyError("the quarantine copy is damaged (SHA-256 differs)")
            for call in (lambda: os.fchown(out, entry["uid"], entry["gid"]),
                         lambda: os.fchmod(out, stat.S_IMODE(entry["mode"])),
                         lambda: os.utime(out, (entry["mtime"], entry["mtime"]))):
                try:
                    call()
                except OSError as exc:            # e.g. NTFS without permission support
                    if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
                        raise
            os.fsync(out)
        except BaseException:
            os.close(out)
            os.unlink(name, dir_fd=parent)
            raise
        os.close(out)
        return {"path": names.to_wire(path), "sha256": entry["sha256"], "size": entry["size"]}
    finally:
        os.close(parent)


def list_quarantine() -> list[dict[str, Any]]:
    base = paths.quarantine_dir()
    out = []
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return out
    for entry in entries:
        try:
            out.append(json.loads((entry / "meta.json").read_text(encoding="ascii")))
        except (OSError, ValueError):
            continue
    return sorted(out, key=lambda m: m.get("time", 0), reverse=True)


# ------------------------------------------------------------------ helper methods


def _path(value: str) -> bool:
    return value.startswith("/") and "\0" not in value and len(value) <= 4096


SECRETS = Param(dict, required=False, default=None)


def _secrets(raw: dict[str, Any] | None) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for volume, item in (raw or {}).items():
        secret = item.get("secret") if isinstance(item, dict) else None
        if not isinstance(secret, str) or len(secret) > 4096:
            raise RemoteError(protocol.INVALID_PARAMS, "secrets must map a volume to {secret, kind}")
        kind = item.get("kind", "passphrase")
        if kind not in ("passphrase", "recovery_key", "password"):
            raise RemoteError(protocol.INVALID_PARAMS, f"unknown secret kind {kind!r}")
        log.register_secret(secret)
        out[str(volume)] = (secret, kind)
    return out


def register(server: Server, manager: VolumeManager, jobs: dict[int, Any]) -> None:
    def busy_check() -> None:
        if jobs:
            raise RemoteError(protocol.BUSY, "a scan is running; wait for it to finish or cancel it")

    def readonly_root(volume: str) -> str:
        mountpoint = manager.mountpoint(volume)
        if mountpoint is None:
            mountpoint = manager.mount(volume)["mountpoint"]
        return mountpoint

    def plan(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        info: dict[str, Any] = {}
        try:
            if p["path"] is not None:                 # without a path: only "can this volume be changed?"
                with RootFS(readonly_root(p["volume"])) as root:
                    info = inspect(root, names.from_wire(p["path"]))
        except RemedyError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        except VolumeError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        result: dict[str, Any] = {"volume": p["volume"], "path": p["path"], **info}
        try:
            wp = writable.plan(manager, p["volume"])
        except writable.WritableError as exc:
            result.update(possible=False, reason=str(exc))
            return result
        except VolumeError as exc:
            result.update(possible=False, reason=str(exc))
            return result
        result.update(possible=True, fstype=wp.fstype, needs_secret=wp.needs_secret, notes=wp.notes,
                      replay_journal=wp.replay_journal,
                      remounts=[m["stable"] for m in wp.restore["mounts"]])
        return result

    def context_for(volume: str, sess: writable.Session) -> dict[str, Any]:
        dev, _snap = manager.resolve(sess.plan.root) if sess.plan.root else (None, None)
        user = privdrop.invoking_user()
        return {"volume": volume, "device": dev.path if dev else None, "uuid": dev.uuid if dev else None,
                "label": (dev.label or dev.partlabel) if dev else None, "fstype": sess.plan.fstype,
                "mount": {"driver": sess.driver, "options": sess.options},
                "journal_replayed": sess.plan.replay_journal, "requested_by_uid": user.uid if user else 0}

    def run_change(volume: str, secrets: dict[str, tuple[str, str]], action: str,
                   work: Any, precheck: Any) -> dict[str, Any]:
        busy_check()
        # Everything that can refuse is checked on the read-only view first, so a refused
        # request never mounts the volume writable.
        try:
            with RootFS(readonly_root(volume)) as root:
                precheck(root)
        except RemedyError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        except VolumeError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        record: dict[str, Any] = {"time": time.time(), "action": action, "volume": volume, "result": "failed"}
        try:
            with writable.session(manager, volume, secrets) as sess:
                record.update(context_for(volume, sess))
                with RootFS(sess.mountpoint) as root:
                    record.update(work(root, record))
                record["result"] = "ok"
        except writable.WritableError as exc:
            record["error"] = str(exc)
            if exc.code != "needs_secret":
                log_change(record)
            raise RemoteError(exc.code if exc.code != "needs_secret" else protocol.NOT_PERMITTED, str(exc),
                              {"needs_secret": (exc.details or {}).get("volumes")}) from exc
        except (RemedyError, OSError, VolumeError) as exc:
            record["error"] = str(exc)
            log_change(record)
            code = getattr(exc, "code", protocol.FAILED)
            raise RemoteError(code if isinstance(code, str) else protocol.FAILED, str(exc)) from exc
        record["renamed"] = sess.renamed
        record["restore_errors"] = sess.restore_errors
        log_change(record)
        return record

    def apply(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        if p["confirm"] is not True:
            raise RemoteError(protocol.INVALID_PARAMS, "changes need confirm: true")
        path = names.from_wire(p["path"])
        expect = p["expect_sha256"]
        action = p["action"]

        def work(root: RootFS, record: dict[str, Any]) -> dict[str, Any]:
            if action == "quarantine":
                context = {k: record.get(k) for k in ("volume", "device", "uuid", "label", "fstype")}
                meta = quarantine_file(root, path, expect, context)
                keys = ("sha256", "size", "mode", "uid", "gid", "mtime")
                return {"path": p["path"], **{k: meta[k] for k in keys}, "quarantine_id": meta["id"]}
            return delete_file(root, path, expect)

        def precheck(root: RootFS) -> None:
            if inspect(root, path)["sha256"] != expect.lower():
                raise RemedyError(CHANGED, protocol.NOT_PERMITTED)

        return run_change(p["volume"], _secrets(p.get("secrets")), action, work, precheck)

    def restore(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        if p["confirm"] is not True:
            raise RemoteError(protocol.INVALID_PARAMS, "changes need confirm: true")
        try:
            entry = load_entry(p["id"])
        except RemedyError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        target = p.get("path") or entry["path"]
        if not _path(target):
            raise RemoteError(protocol.INVALID_PARAMS, "invalid path")

        def work(root: RootFS, record: dict[str, Any]) -> dict[str, Any]:
            return {**restore_file(root, entry, names.from_wire(target)), "quarantine_id": entry["id"]}

        def precheck(root: RootFS) -> None:
            raw = names.from_wire(target)
            try:
                root.lstat(raw)
                exists = True
            except FileNotFoundError:
                exists = False
            if exists:
                raise RemedyError("a file with that name exists; nothing was restored",
                                  protocol.NOT_PERMITTED)
            parent = raw.rsplit(b"/", 1)[0] or b"/"
            try:
                if not stat.S_ISDIR(root.stat(parent).st_mode):
                    raise RemedyError("the folder of the original file is gone", protocol.NOT_FOUND)
            except OSError as exc:
                raise RemedyError("the folder of the original file is gone", protocol.NOT_FOUND) from exc

        record = run_change(p["volume"], _secrets(p.get("secrets")), "restore", work, precheck)
        shutil.rmtree(paths.quarantine_dir() / entry["id"], ignore_errors=True)
        return record

    def purge(ctx: Context, p: dict[str, Any]) -> None:
        if p["confirm"] is not True:
            raise RemoteError(protocol.INVALID_PARAMS, "changes need confirm: true")
        try:
            entry = load_entry(p["id"])
        except RemedyError as exc:
            raise RemoteError(exc.code, str(exc)) from exc
        shutil.rmtree(paths.quarantine_dir() / entry["id"])
        log_change({"time": time.time(), "action": "purge", "quarantine_id": entry["id"],
                    "path": entry["path"], "sha256": entry["sha256"], "volume": entry.get("volume"),
                    "result": "ok"})

    volume = Param(str, check=lambda v: "/" not in v and 0 < len(v) <= 64)
    path = Param(str, check=_path)
    sha = Param(str, check=lambda v: re.fullmatch(r"[0-9a-fA-F]{64}", v) is not None)
    confirm = Param(bool)
    qid = Param(str, check=lambda v: ID_RE.match(v) is not None)
    optional_path = Param(str, required=False, check=_path)
    server.register("remedy.plan", Schema({"volume": volume, "path": optional_path}), plan, exclusive=True)
    server.register("remedy.apply", Schema({"volume": volume, "path": path, "expect_sha256": sha,
                                            "action": Param(str, choices=("quarantine", "delete")),
                                            "confirm": confirm, "secrets": SECRETS}), apply, exclusive=True)
    server.register("quarantine.list", Schema(), lambda ctx, p: {"entries": list_quarantine()})
    server.register("quarantine.restore", Schema({"id": qid, "volume": volume,
                                                  "path": Param(str, required=False, default=None),
                                                  "confirm": confirm, "secrets": SECRETS}), restore,
                    exclusive=True)
    server.register("quarantine.purge", Schema({"id": qid, "confirm": confirm}), purge, exclusive=True)
    server.register("changes.list", Schema({"limit": Param(int, required=False, default=200)}),
                    lambda ctx, p: {"changes": read_changes(max(1, min(int(p["limit"]), 5000)))})
