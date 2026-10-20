"""Scan worker process.

Started by the helper with one end of a SOCK_SEQPACKET socketpair.  It runs
unprivileged (the invoking user, or ``nobody``), has no network (inherited
empty namespace), sets ``no_new_privs`` and may not create files
(RLIMIT_FSIZE=0).  For each job it receives an already opened, read-only
file descriptor, reads the file *once*, and feeds the same bytes to the
SHA-256 matcher, YARA-X and clamd (INSTREAM).

Messages are JSON; the helper never trusts what comes back beyond its shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

from .. import privdrop
from . import clamd as clamd_mod
from . import hashdb, pe, selection, yara_engine
from .results import clamav_severity, yara_severity

READ_CHUNK = 1 << 20
HEAD = 64 * 1024
MAX_MSG = 1 << 20


class Engines:
    def __init__(self, runtime: Path, config: dict[str, Any]):
        self.runtime = runtime
        self.config = config
        self.status: dict[str, Any] = {}
        manifest = json.loads((runtime / "manifest.json").read_text(encoding="utf-8"))
        self.manifest = manifest
        self.hash_dbs: list[tuple[str, hashdb.HashDB]] = []
        self.known_good: hashdb.HashDB | None = None
        self.authentihash: hashdb.HashDB | None = None
        self.hash_meta: dict[str, dict[str, Any]] = manifest.get("hash_sources", {})
        engines = set(config.get("engines", []))
        if "hashes" in engines:
            for name in manifest.get("hashes", {}).get("malware", []):
                path = runtime / "hashes" / name
                try:
                    self.hash_dbs.append((name, hashdb.HashDB(path)))
                except (OSError, hashdb.HashDBError) as exc:
                    self.status.setdefault("errors", []).append(f"{name}: {exc}")
            kg = manifest.get("hashes", {}).get("known_good")
            if kg:
                try:
                    self.known_good = hashdb.HashDB(runtime / "hashes" / kg)
                except (OSError, hashdb.HashDBError) as exc:
                    self.status.setdefault("errors", []).append(f"{kg}: {exc}")
            ah = manifest.get("hashes", {}).get("authentihash")
            if ah:
                try:
                    self.authentihash = hashdb.HashDB(runtime / "hashes" / ah)
                except (OSError, hashdb.HashDBError) as exc:
                    self.status.setdefault("errors", []).append(f"{ah}: {exc}")
            self.status["hashes"] = sum(len(db) for _, db in self.hash_dbs)
        self.yara: yara_engine.Scanner | None = None
        yinfo = manifest.get("yara") or {}
        if "yara" in engines and yinfo.get("file"):
            try:
                self.yara = yara_engine.Scanner(runtime / "yara" / yinfo["file"], yinfo["engine"],
                                                timeout=int(config["limits"]["file_timeout"]))
                self.status["yara"] = {"engine": yinfo["engine"], "rules": yinfo.get("rules")}
            except Exception as exc:
                self.status["yara"] = {"error": f"{type(exc).__name__}: {exc}"}
        self.clamd: clamd_mod.Client | None = None
        self.fildes: bool | None = None if config.get("fildes", True) else False
        if "clamav" in engines and config.get("clamd"):
            client = clamd_mod.Client(str(runtime / clamd_mod.SOCKET_NAME),
                                      timeout=float(config["limits"]["file_timeout"]) + 60)
            if client.wait_ready(timeout=float(config.get("clamd_wait", 600))):
                self.clamd = client
                try:
                    self.status["clamav"] = {"version": client.version()}
                except (OSError, clamd_mod.ClamdError) as exc:
                    self.status["clamav"] = {"error": str(exc)}
            else:
                self.status["clamav"] = {"error": "clamd did not become ready"}


def _fildes_refused(message: str) -> bool:
    lower = message.lower()
    return any(word in lower for word in ("access denied", "permission denied", "can't", "cannot",
                                          "not permitted", "fildes", "file descriptor"))


def _read_all(fd: int, size: int) -> bytes:
    chunks = []
    offset = 0
    while True:
        chunk = os.pread(fd, READ_CHUNK, offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        if offset > size + READ_CHUNK * 4:     # file grew while reading; stop
            break
    return b"".join(chunks)


def process(engines: Engines, job: dict[str, Any], fd: int) -> dict[str, Any]:
    limits = engines.config["limits"]
    relpath = job["path"]
    out: dict[str, Any] = {"id": job["id"], "detections": [], "errors": [], "skipped": None,
                           "bytes": 0, "sha256": None, "known_good": False}
    st = os.fstat(fd)
    size = st.st_size
    if size > limits["max_hash_size"]:
        out["skipped"] = "larger than the hash size limit"
        return out
    try:
        head = os.pread(fd, HEAD, 0)
    except OSError as exc:
        out["errors"].append(f"read error: {exc.strerror}")
        return out
    if job.get("mode") == "quick" and not job.get("force") and not selection.interesting(relpath, head):
        out["skipped"] = "not selected by quick scan"
        return out
    digest = hashlib.sha256()
    data: bytes | None = None
    try:
        if size <= limits["max_file_size"]:
            data = _read_all(fd, size)
            digest.update(data)
            out["bytes"] = len(data)
        else:
            offset = 0
            while True:
                chunk = os.pread(fd, READ_CHUNK, offset)
                if not chunk:
                    break
                digest.update(chunk)
                offset += len(chunk)
            out["bytes"] = offset
            out["errors"].append("larger than the scan size limit: only hash-checked")
    except OSError as exc:
        out["errors"].append(f"read error: {exc.strerror or exc}")
        return out
    sha = digest.hexdigest()
    out["sha256"] = sha
    raw = bytes.fromhex(sha)
    for name, db in engines.hash_dbs:
        for source in db.lookup(raw):
            meta = engines.hash_meta.get(source, {})
            out["detections"].append({
                "engine": "hash", "signature": meta.get("signature", f"{source}:sha256"),
                "severity": meta.get("severity", "high"), "source": source,
                "category": meta.get("category", "malware"), "sha256": sha, "size": size,
                "details": {"list": meta.get("name", source), "database": name}})
    if data is not None and engines.authentihash is not None and data[:2] == b"MZ":
        _authentihash(engines, data, relpath, sha, size, out)
    if engines.known_good is not None and engines.known_good.lookup(raw):
        out["known_good"] = True
    if data is not None and engines.yara is not None:
        try:
            matches = engines.yara.scan(data, os.fsdecode(relpath) if isinstance(relpath, bytes) else relpath)
        except engines.yara.timeout_error:
            out["errors"].append("YARA timed out")
            matches = []
        except Exception as exc:
            out["errors"].append(f"YARA error: {exc}")
            matches = []
        for m in matches:
            severity, category = yara_severity(m.meta)
            source = engines.manifest.get("yara", {}).get("namespaces", {}).get(m.namespace, m.namespace)
            out["detections"].append({
                "engine": "yara", "signature": m.rule, "severity": severity, "category": category,
                "source": source, "sha256": sha, "size": size,
                "details": {k: m.meta[k] for k in ("author", "description", "reference", "score",
                                                   "license", "license_url", "date", "source_url")
                            if k in m.meta} | {"namespace": m.namespace, "tags": m.tags}})
    if data is not None and engines.clamd is not None:
        try:
            reply = None
            if engines.fildes is not False:
                reply = engines.clamd.scan_fd(fd)
                if reply.status == "ERROR" and _fildes_refused(reply.message):
                    engines.fildes = False          # e.g. AppArmor: stream from now on
                    reply = None
                elif engines.fildes is None:
                    engines.fildes = True
            if reply is None:
                stream = engines.clamd.open_stream()
                stream.feed(data)
                reply = stream.finish()
            if reply.status == "FOUND":
                severity, category = clamav_severity(reply.signature)
                out["detections"].append({
                    "engine": "clamav", "signature": reply.signature.removesuffix(".UNOFFICIAL"),
                    "severity": severity, "category": category, "sha256": sha, "size": size,
                    "source": "clamav-unofficial" if reply.signature.endswith(".UNOFFICIAL") else "clamav",
                    "details": {}})
            elif reply.status == "ERROR":
                out["errors"].append(f"ClamAV: {reply.message}")
        except (OSError, clamd_mod.ClamdError) as exc:
            out["errors"].append(f"ClamAV: {exc}")
    return out


def _authentihash(engines: Engines, data: bytes, relpath: str, sha: str, size: int,
                  out: dict[str, Any]) -> None:
    """Drivers: look up the Authenticode hash too (catches re-signed copies)."""
    try:
        info = pe.parse(data)
        if info is None or not (info.subsystem == pe.SUBSYSTEM_NATIVE or relpath.lower().endswith(".sys")):
            return
        digest = pe.authentihash(data, info)
    except (ValueError, IndexError, struct.error):
        return
    if digest is None or engines.authentihash is None:
        return
    for source in engines.authentihash.lookup(digest):
        meta = engines.hash_meta.get(source, {})
        out["detections"].append({
            "engine": "hash", "signature": meta.get("signature", f"{source}:authentihash"),
            "severity": meta.get("severity", "high"), "source": source,
            "category": meta.get("category", "malware"), "sha256": sha, "size": size,
            "details": {"list": meta.get("name", source), "hash": "authentihash",
                        "authentihash": digest.hex()}})


def main() -> None:
    sock_fd = int(sys.argv[2])
    config = json.loads(sys.argv[3])
    privdrop.set_no_new_privs()
    privdrop.set_limits(file_size=0, open_files=4096)
    sock = socket.socket(fileno=sock_fd)
    runtime = Path(config["runtime"])
    try:
        engines = Engines(runtime, config)
        ready = {"type": "ready", "pid": os.getpid(), "status": engines.status}
    except Exception as exc:
        sock.send(json.dumps({"type": "fatal", "error": f"{type(exc).__name__}: {exc}"}).encode())
        return
    drop = config.get("drop_to")
    if drop and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(int(drop[1]))
        os.setuid(int(drop[0]))
    sock.send(json.dumps(ready).encode())
    while True:
        try:
            msg, fds, _flags, _addr = socket.recv_fds(sock, MAX_MSG, 1)
        except (ConnectionResetError, OSError):
            return
        if not msg:
            return
        job = json.loads(msg)
        if job.get("type") == "stop":
            return
        fd = fds[0] if fds else -1
        started = time.monotonic()
        try:
            if fd < 0:
                result = {"id": job["id"], "detections": [], "errors": ["no file descriptor"],
                          "skipped": None, "bytes": 0, "sha256": None}
            else:
                job["path"] = os.fsencode(job["path"]).decode("utf-8", "surrogateescape")
                result = process(engines, job, fd)
        except MemoryError:
            result = {"id": job["id"], "detections": [], "errors": ["out of memory"],
                      "skipped": None, "bytes": 0, "sha256": None}
        finally:
            for extra in fds:
                os.close(extra)
        result["type"] = "result"
        result["seconds"] = round(time.monotonic() - started, 3)
        sock.send(json.dumps(result).encode())


BOOT = (
    "import json,sys\n"
    "sys.path[:0]=json.loads(sys.argv[1])\n"
    "from offscan.scan.worker import main\n"
    "main()\n"
)
