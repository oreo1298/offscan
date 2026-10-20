"""Package database verification for Linux targets (dpkg, pacman, rpm).

* Collection (helper): find the package database and copy it into a sealed
  memfd (dpkg/pacman text files) or pass the database files (rpm).
* Parsing (sandbox, :func:`task_list`): read the database ourselves.  The
  target's own tools are never run.  rpm's sqlite and ndb formats are read
  natively; the old Berkeley DB format needs the host ``rpm`` (read-only
  query of a private copy).
* Verification (helper, :func:`verify`): hash the packaged files on the
  read-only mount and compare; report files that no package owns in
  places where everything should be packaged.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import struct
import subprocess
import tempfile
import threading
import zlib
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .. import names, tools
from ..safefs import RootFS, iter_regular_files
from . import Finding, filepack

DPKG_DIR = "/var/lib/dpkg"
PACMAN_DIR = "/var/lib/pacman/local"
RPM_DIRS = ("/usr/lib/sysimage/rpm", "/var/lib/rpm")
MAX_DB = 2 << 30

# ----------------------------------------------------------------- collection


def detect(root: RootFS) -> dict[str, Any] | None:
    """Which package manager the installation uses, and where its database is."""
    if root.exists(DPKG_DIR + "/status"):
        return {"manager": "dpkg", "path": DPKG_DIR}
    if root.exists(PACMAN_DIR):
        return {"manager": "pacman", "path": PACMAN_DIR}
    for directory in RPM_DIRS:
        for name, backend in (("rpmdb.sqlite", "sqlite"), ("Packages.db", "ndb"), ("Packages", "bdb")):
            if root.exists(f"{directory}/{name}"):
                return {"manager": "rpm", "path": directory, "backend": backend, "file": name}
    return None


def collect(root: RootFS, info: dict[str, Any]) -> tuple[dict[str, Any], list[int]]:
    manager = info["manager"]
    args: dict[str, Any] = {"manager": manager}
    if manager == "rpm":
        fds: list[int] = []
        files: dict[str, int] = {}
        for suffix in ("", "-wal"):
            name = info["file"] + suffix
            try:
                fds.append(root.open_regular(f"{info['path']}/{name}"))
                files[name] = len(fds) - 1
            except OSError:
                continue
        args.update(backend=info["backend"], files=files)
        return args, fds
    pack = filepack.Packer(max_total=1 << 30, max_entries=500_000)
    try:
        if manager == "dpkg":
            pack.add(root, DPKG_DIR + "/status", "status", max_size=256 << 20)
            pack.add(root, DPKG_DIR + "/diversions", "diversions", max_size=16 << 20)
            try:
                for name in iter_regular_files(root, (DPKG_DIR + "/info").encode()):
                    if name.endswith((b".md5sums", b".list")):
                        pack.add(root, DPKG_DIR.encode() + b"/info/" + name,
                                 "md5sums" if name.endswith(b".md5sums") else "list", max_size=64 << 20)
            except OSError:
                pass
        else:
            try:
                packages = root.listdir(PACMAN_DIR)
            except OSError:
                packages = []
            for name in packages:
                base = PACMAN_DIR.encode() + b"/" + name
                for part, max_size in ((b"desc", 1 << 20), (b"files", 64 << 20), (b"mtree", 64 << 20)):
                    pack.add(root, base + b"/" + part, part.decode(), max_size=max_size,
                             package=names.to_wire(name))
        fd, index = pack.finish()
        args.update(pack=0, index=index, truncated=pack.full)
        return args, [os.dup(fd)]
    finally:
        pack.close()


# ---------------------------------------------------------------- parsing (sandbox)

ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
CONFIG, DOC, GHOST, LICENSE, README = 1, 2, 64, 128, 256


class _Out:
    def __init__(self, manager: str):
        self.manager = manager
        self.packages: list[str] = []
        self.files: list[list[Any]] = []        # [path, pkg, algo, digest, flags, size]
        self.owned: list[str] = []              # other owned paths (dirs, links, undigested files)
        self.errors: list[str] = []

    def package(self, name: str) -> int:
        self.packages.append(name[:200])
        return len(self.packages) - 1

    def result(self) -> dict[str, Any]:
        files = [f for f in self.files if plausible_path(f[0])]
        owned = [p for p in self.owned if plausible_path(p)]
        if len(files) < len(self.files) or len(owned) < len(self.owned):
            self.errors.append("entries with impossible paths were ignored")
        return {"manager": self.manager, "packages": self.packages, "files": files,
                "owned": owned, "errors": self.errors[:100]}


def plausible_path(path: str) -> bool:
    """A path a real filesystem can hold (PATH_MAX, NAME_MAX); anything else is junk or an attack."""
    return len(path) <= 4096 and all(len(part) <= 255 for part in path.split("/"))


def _dpkg(args: dict[str, Any], fd: int, out: _Out) -> None:
    diversions: dict[str, tuple[str, str]] = {}
    conffiles: list[tuple[str, str, str]] = []
    for entry, data in filepack.entries(fd, args["index"]):
        if entry["kind"] == "diversions":
            lines = data.decode("utf-8", "surrogateescape").split("\n")
            for i in range(0, len(lines) - 2, 3):
                if lines[i].startswith("/") and lines[i + 1].startswith("/"):
                    diversions[lines[i]] = (lines[i + 1], lines[i + 2])
        elif entry["kind"] == "status":
            package, installed, in_conf = "", False, False
            for line in data.decode("utf-8", "surrogateescape").split("\n"):
                if not line:
                    package, installed, in_conf = "", False, False
                elif line.startswith("Package: "):
                    package = line[9:].strip()
                elif line.startswith("Status: "):
                    installed = line.split()[-1] in ("installed", "half-configured", "unpacked")
                elif line.startswith("Conffiles:"):
                    in_conf = True
                elif in_conf and line.startswith(" "):
                    parts = line.split()
                    if installed and len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{32}", parts[1]) \
                            and "obsolete" not in parts[2:]:
                        conffiles.append((parts[0], parts[1], package))
                else:
                    in_conf = False
    packages: dict[str, int] = {}

    def pkg(name: str) -> int:
        if name not in packages:
            packages[name] = out.package(name)
        return packages[name]

    def place(path: str, owner: str) -> str:
        divert = diversions.get(path)
        return divert[0] if divert and divert[1] != owner.split(":")[0] else path

    for entry, data in filepack.entries(fd, args["index"]):
        if entry["kind"] not in ("md5sums", "list"):
            continue
        base = entry["file"].rsplit("/", 1)[-1]
        name = base.rsplit(".", 1)[0]
        idx = pkg(name)
        text = data.decode("utf-8", "surrogateescape")
        if entry["kind"] == "md5sums":
            for line in text.split("\n"):
                if len(line) > 34 and line[32:34] == "  " and re.fullmatch(r"[0-9a-f]{32}", line[:32]):
                    path = "/" + line[34:].lstrip("/")
                    out.files.append([place(path, name), idx, "md5", line[:32], "", -1])
        else:
            out.owned.extend(place(p, name) for p in text.split("\n") if p.startswith("/") and p != "/.")
    for path, digest, owner in conffiles:
        out.files.append([place(path, owner), pkg(owner), "md5", digest, "c", -1])
    if args.get("truncated"):
        out.errors.append("package database too large: only part of it was read")


_ESCAPE = re.compile(r"\\([0-3][0-7]{2})")         # one byte, \000 to \377


def _mtree_path(raw: str) -> str:
    """Undo mtree's octal escapes; the result is the UTF-8 (or surrogate-escaped) path."""
    data = _ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), raw)
    try:
        return data.encode("latin-1", "surrogateescape").decode("utf-8", "surrogateescape")
    except UnicodeEncodeError:              # not from a latin-1 decoded file; keep it as it is
        return data


def _gunzip(data: bytes, limit: int = 64 << 20) -> bytes:
    if data[:2] != b"\x1f\x8b":
        return data
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = inflater.decompress(data, limit)
    if inflater.unconsumed_tail:
        raise ValueError("decompressed data too large")
    return result


def _pacman(args: dict[str, Any], fd: int, out: _Out) -> None:
    by_pkg: dict[str, dict[str, bytes]] = {}
    for entry, data in filepack.entries(fd, args["index"]):
        by_pkg.setdefault(entry.get("package", "?"), {})[entry["kind"]] = data
    for dirname, parts in sorted(by_pkg.items()):
        # One damaged (or crafted) package entry must not stop the others being checked.
        try:
            _pacman_package(dirname, parts, out)
        except (ValueError, IndexError, KeyError, UnicodeError, OSError, EOFError, zlib.error) as exc:
            out.errors.append(f"{dirname}: {type(exc).__name__}: {exc}"[:300])


def _pacman_package(dirname: str, parts: dict[str, bytes], out: _Out) -> None:
    desc = parts.get("desc", b"").decode("utf-8", "replace").split("\n")
    name = desc[desc.index("%NAME%") + 1] if "%NAME%" in desc[:-1] else dirname
    idx = out.package(name)
    backup: set[str] = set()
    section = ""
    for line in parts.get("files", b"").decode("utf-8", "surrogateescape").split("\n"):
        if line.startswith("%") and line.endswith("%"):
            section = line
        elif line and section == "%FILES%":
            out.owned.append("/" + line.rstrip("/"))
        elif line and section == "%BACKUP%":
            backup.add("/" + line.split("\t", 1)[0])
    mtree = _gunzip(parts.get("mtree", b"")).decode("latin-1")
    defaults: dict[str, str] = {}
    for line in mtree.split("\n"):
        words = line.split()
        if not words or words[0].startswith("#"):
            continue
        if words[0] == "/set":
            defaults.update(w.split("=", 1) for w in words[1:] if "=" in w)
            continue
        if words[0] == "/unset" or not words[0].startswith("./") or words[0].startswith("./."):
            continue
        attrs = dict(defaults)
        attrs.update(w.split("=", 1) for w in words[1:] if "=" in w)
        if attrs.get("type", "file") != "file":
            continue
        path = "/" + _mtree_path(words[0][2:])
        digest = attrs.get("sha256digest") or attrs.get("md5digest")
        if not digest:
            continue
        algo = "sha256" if "sha256digest" in attrs else "md5"
        size = int(attrs["size"]) if attrs.get("size", "").isdigit() else -1
        out.files.append([path, idx, algo, digest, "c" if path in backup else "", size])


# -- rpm ----------------------------------------------------------------------

TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_EPOCH, TAG_ARCH = 1000, 1001, 1002, 1003, 1022
TAG_FILESIZES, TAG_FILEMODES, TAG_FILEDIGESTS, TAG_FILEFLAGS = 1028, 1030, 1035, 1037
TAG_OLDFILENAMES, TAG_DIRINDEXES, TAG_BASENAMES, TAG_DIRNAMES = 1027, 1116, 1117, 1118
TAG_LONGFILESIZES, TAG_FILEDIGESTALGO = 5008, 5011
WANTED = {TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_EPOCH, TAG_ARCH, TAG_FILESIZES, TAG_FILEMODES,
          TAG_FILEDIGESTS, TAG_FILEFLAGS, TAG_OLDFILENAMES, TAG_DIRINDEXES, TAG_BASENAMES, TAG_DIRNAMES,
          TAG_LONGFILESIZES, TAG_FILEDIGESTALGO}
_INT_FORMATS = {2: ("B", 1), 3: ("H", 2), 4: ("I", 4), 5: ("Q", 8)}


def parse_rpm_header(blob: bytes) -> dict[int, Any]:
    """Decode the tags we need from an rpm header blob (as stored in rpmdb)."""
    if len(blob) < 8:
        raise ValueError("short header")
    il, dl = struct.unpack(">II", blob[:8])
    if il > 100_000 or dl > len(blob) or 8 + il * 16 + dl > len(blob):
        raise ValueError("corrupt header")
    data = blob[8 + il * 16: 8 + il * 16 + dl]
    out: dict[int, Any] = {}
    for i in range(il):
        tag, typ, offset, count = struct.unpack(">iIiI", blob[8 + i * 16: 24 + i * 16])
        if tag not in WANTED or offset < 0 or offset > dl or count > 10_000_000:
            continue
        if typ in _INT_FORMATS:
            code, size = _INT_FORMATS[typ]
            end = offset + size * count
            if end > dl:
                raise ValueError("corrupt header entry")
            out[tag] = list(struct.unpack(f">{count}{code}", data[offset:end]))
        elif typ in (6, 8, 9):                  # STRING, STRING_ARRAY, I18NSTRING
            strings, pos = [], offset
            for _ in range(1 if typ == 6 else count):
                end = data.find(b"\0", pos)
                if end < 0:
                    raise ValueError("unterminated string")
                strings.append(data[pos:end].decode("utf-8", "surrogateescape"))
                pos = end + 1
            out[tag] = strings[0] if typ == 6 else strings
    return out


def _rpm_package(header: dict[int, Any], out: _Out) -> None:
    name = header.get(TAG_NAME, "?")
    epoch = (header.get(TAG_EPOCH) or [None])[0]
    nevra = f"{name}-{f'{epoch}:' if epoch else ''}{header.get(TAG_VERSION, '?')}-" \
            f"{header.get(TAG_RELEASE, '?')}.{header.get(TAG_ARCH, '?')}"
    if name == "gpg-pubkey":
        return
    idx = out.package(nevra)
    if TAG_BASENAMES in header:
        dirnames = header.get(TAG_DIRNAMES, [])
        paths = [dirnames[d] + b for d, b in zip(header.get(TAG_DIRINDEXES, []), header[TAG_BASENAMES],
                                                 strict=False) if d < len(dirnames)]
    else:
        paths = header.get(TAG_OLDFILENAMES, [])
    algo = ALGOS.get((header.get(TAG_FILEDIGESTALGO) or [1])[0], "md5")
    digests = header.get(TAG_FILEDIGESTS, [])
    modes = header.get(TAG_FILEMODES, [])
    flags = header.get(TAG_FILEFLAGS, [])
    sizes = header.get(TAG_LONGFILESIZES) or header.get(TAG_FILESIZES, [])
    for i, path in enumerate(paths):
        mode = modes[i] if i < len(modes) else 0
        flag = flags[i] if i < len(flags) else 0
        digest = digests[i] if i < len(digests) else ""
        if flag & GHOST:
            continue
        if not stat.S_ISREG(mode) or not digest:
            out.owned.append(path)
            continue
        marks = ("c" if flag & CONFIG else "") + ("d" if flag & (DOC | LICENSE | README) else "")
        out.files.append([path, idx, algo, digest, marks, sizes[i] if i < len(sizes) else -1])


def iter_ndb(data: bytes) -> Iterable[bytes]:
    """Header blobs of an rpm ndb ``Packages.db``."""
    if data[:4] != b"RpmP" or len(data) < 32:
        raise ValueError("not an rpm ndb database")
    slot_pages = struct.unpack("<I", data[12:16])[0]
    end = min(len(data), max(1, slot_pages) * 4096)
    for off in range(32, end - 15, 16):
        magic, pkgidx, blkoff, blkcnt = struct.unpack("<4sIII", data[off:off + 16])
        if magic != b"Slot" or pkgidx == 0:
            continue
        start, stop = blkoff * 16, (blkoff + blkcnt) * 16
        if stop > len(data) or blkcnt < 2:
            continue
        head, idx, _gen, length = struct.unpack("<4sIII", data[start:start + 16])
        if head != b"BlbS" or idx != pkgidx or data[stop - 4:stop] != b"BlbE" or 16 + length > stop - start:
            continue
        yield data[start + 16:start + 16 + length]


def _rpm(args: dict[str, Any], fds: list[int], out: _Out) -> None:
    files = args.get("files", {})
    backend = args.get("backend")
    with tempfile.TemporaryDirectory(prefix="rpmdb-") as tmp:
        for name, idx in files.items():
            src = fds[idx]
            with open(os.path.join(tmp, name), "wb") as dst:
                offset = 0
                while offset < MAX_DB:
                    chunk = os.pread(src, 8 << 20, offset)
                    if not chunk:
                        break
                    dst.write(chunk)
                    offset += len(chunk)
        if backend == "sqlite":
            con = sqlite3.connect(os.path.join(tmp, "rpmdb.sqlite"))
            try:
                for (blob,) in con.execute("SELECT blob FROM Packages"):
                    try:
                        _rpm_package(parse_rpm_header(bytes(blob)), out)
                    except (ValueError, struct.error, IndexError) as exc:
                        out.errors.append(f"rpm header: {exc}")
            finally:
                con.close()
        elif backend == "ndb":
            path = os.path.join(tmp, "Packages.db")
            with open(path, "rb") as fh:
                data = fh.read(min(os.path.getsize(path), MAX_DB))   # read(n) preallocates n bytes
            for blob in iter_ndb(data):
                try:
                    _rpm_package(parse_rpm_header(blob), out)
                except (ValueError, struct.error, IndexError) as exc:
                    out.errors.append(f"rpm header: {exc}")
        else:
            _rpm_with_tool(tmp, out)


RPM_QF = ("@@PKG %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{FILEDIGESTALGO}\\n"
          "[%{FILEFLAGS} %{FILEMODES} %{FILEDIGESTS} %{FILENAMES}\\n]")


def _rpm_with_tool(dbpath: str, out: _Out) -> None:
    """Berkeley DB rpmdb: query a private copy with the host's rpm (read-only, no scripts)."""
    rpm = tools.find("rpm")
    if rpm is None:
        out.errors.append("this installation uses the old Berkeley DB rpm database; install the 'rpm' "
                          "tool on the scanning system to verify its packages")
        return
    proc = subprocess.run([rpm, "--dbpath", dbpath, "--define", "_db_backend bdb_ro", "-qa", "--qf", RPM_QF],
                          capture_output=True, timeout=600, check=False, env=tools.safe_env())
    if proc.returncode != 0 and not proc.stdout:
        out.errors.append(f"rpm query failed: {proc.stderr.decode('utf-8', 'replace')[-300:]}")
        return
    idx, algo = -1, "md5"
    for line in proc.stdout.decode("utf-8", "surrogateescape").split("\n"):
        if line.startswith("@@PKG "):
            _, nevra, algo_id = [*line.split(" "), "", ""][:3]
            idx = out.package(nevra)
            algo = ALGOS.get(int(algo_id) if algo_id.isdigit() else 1, "md5")
            continue
        parts = line.split(" ", 3)
        if idx < 0 or len(parts) != 4:
            continue
        flag, mode, digest, path = int(parts[0] or 0), int(parts[1] or 0), parts[2], parts[3]
        if flag & GHOST:
            continue
        if stat.S_ISREG(mode) and digest and digest != "(none)":
            marks = ("c" if flag & CONFIG else "") + ("d" if flag & (DOC | LICENSE | README) else "")
            out.files.append([path, idx, algo, digest, marks, -1])
        else:
            out.owned.append(path)


def task_list(args: dict[str, Any], fds: list[int]) -> dict[str, Any]:
    """Sandbox entry point: the package database as a list of files with expected digests."""
    out = _Out(args["manager"])
    if args["manager"] == "dpkg":
        _dpkg(args, fds[args["pack"]], out)
    elif args["manager"] == "pacman":
        _pacman(args, fds[args["pack"]], out)
    elif args["manager"] == "rpm":
        _rpm(args, fds, out)
    return out.result()


# ----------------------------------------------------------- verification (helper)

_MERGED = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/bin/"), ("/usr/sbin/", "/usr/bin/"),
           ("/lib/", "/usr/lib/"), ("/lib64/", "/usr/lib64/"), ("/lib32/", "/usr/lib32/"),
           ("/libx32/", "/usr/libx32/"))


def norm(path: str) -> str:
    """Fold merged-/usr aliases so /bin/ls, /usr/bin/ls and /usr/sbin/x compare equal."""
    for old, new in _MERGED:
        if path.startswith(old):
            return new + path[len(old):]
    return path


CRITICAL_RE = re.compile(
    r"^/(usr/)?s?bin/[^/]+$"
    r"|^/(usr/)?lib(64|32|x32)?/([^/]+/)?security/[^/]+$"
    r"|^/(usr/)?lib(64|32|x32)?/([^/]+/)?(ld-linux[^/]*|libc[.-](?=[^/]*so)[^/]*|libpam[^/]*|libcrypt[^/]*"
    r"|libnss_[^/]*|libsystemd\.so[^/]*|libselinux\.so[^/]*|libaudit\.so[^/]*|libkeyutils\.so[^/]*"
    r"|libssl\.so[^/]*|libcrypto\.so[^/]*|libz\.so[^/]*)$"
    r"|^/(usr/)?lib/systemd/systemd[^/]*$"
    r"|^/usr/(lib|libexec)/(openssh|sudo|ssh)/")
DOC_RE = re.compile(r"^/usr/share/(doc|man|info|locale|help|gtk-doc|licenses)/")


@dataclass
class PackageIndex:
    manager: str
    packages: list[str]
    files: list[list[Any]]
    owned: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_result(cls, result: dict[str, Any]) -> PackageIndex:
        index = cls(result["manager"], result["packages"], result["files"], errors=list(result["errors"]))
        index.owned = {norm(p) for p in result["owned"]}
        index.owned.update(norm(f[0]) for f in result["files"])
        return index

    def owns(self, path: str) -> bool:
        return norm(path) in self.owned

    def package_of(self, item: list[Any]) -> str:
        return self.packages[item[1]] if 0 <= item[1] < len(self.packages) else "?"


def _digest(root: RootFS, path: str, algo: str, max_size: int) -> tuple[str | None, str | None]:
    """(hexdigest, problem) of a packaged file on the target."""
    try:
        fd = root.open_regular(names.from_wire(path), follow_last=False)
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        try:
            if stat.S_ISLNK(root.lstat(names.from_wire(path)).st_mode):
                return None, "symlink"
        except OSError:
            pass
        return None, f"unreadable: {exc.strerror or exc}"
    try:
        if os.fstat(fd).st_size > max_size:
            return None, "too large"
        h = hashlib.new(algo)
        offset = 0
        while True:
            chunk = os.pread(fd, 1 << 20, offset)
            if not chunk:
                break
            h.update(chunk)
            offset += len(chunk)
        return h.hexdigest(), None
    finally:
        os.close(fd)


def verify(root: RootFS, index: PackageIndex, scope: str = "quick", extra: Iterable[str] = (),
           stop: threading.Event | None = None, progress: Callable[[int, int], None] | None = None,
           max_size: int = 4 << 30, workers: int = 4) -> tuple[list[Finding], dict[str, int]]:
    """Compare packaged files against the database; returns (findings, counters)."""
    wanted = {norm(p) for p in extra}
    items = [f for f in index.files if scope == "full" or CRITICAL_RE.match(f[0]) or norm(f[0]) in wanted]
    seen: set[str] = set()
    unique = []
    for item in items:                        # merged /usr lists the same file twice
        key = norm(item[0])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    counters = {"checked": 0, "modified": 0, "missing": 0, "errors": 0, "total": len(unique)}
    findings: list[Finding] = []
    lock = threading.Lock()

    def report(check: str, title: str, path: str, item: list[Any], severity: str, reasons: list[str],
               target: str | None = None, mitre: str | None = None, **extra: Any) -> None:
        package = index.package_of(item)
        findings.append(Finding(check, title, path, package, severity, [*reasons, f"installed by {package}"],
                                path, target, None, mitre, {"package": package, "manager": index.manager,
                                                            **extra}))

    def check(item: list[Any]) -> None:
        if stop is not None and stop.is_set():
            return
        path, _pkg, algo, expected, marks, _size = item
        actual, problem = _digest(root, path, algo, max_size)
        with lock:
            counters["checked"] += 1
            if progress is not None and counters["checked"] % 200 == 0:
                progress(counters["checked"], counters["total"])
            critical = CRITICAL_RE.match(path) is not None
            if problem == "missing":
                counters["missing"] += 1
                if critical and "d" not in marks:
                    report("integrity.package_missing", "Packaged file is missing", path, item, "low", [])
            elif problem == "symlink":
                counters["modified"] += 1
                report("integrity.package_modified", "Packaged file replaced by a link", path, item,
                       "high" if critical else "medium", ["a regular file was installed here"], path, "T1036")
            elif problem:
                counters["errors"] += 1
            elif actual != expected.lower():
                counters["modified"] += 1
                if "c" in marks:
                    severity, why = "info", "configuration file changed (normal after editing)"
                elif critical:
                    severity, why = "high", "a system program or library differs from the packaged one"
                elif DOC_RE.match(path) or "d" in marks:
                    severity, why = "low", "documentation differs from the packaged one"
                else:
                    severity, why = "medium", "file differs from the packaged one"
                report("integrity.package_modified", "File changed since it was installed", path, item,
                       severity, [why], path, "T1036" if critical else None, algorithm=algo,
                       expected=expected, actual=actual, config="c" in marks)

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="verify") as pool:
        list(pool.map(check, unique))
    return findings, counters


# Locations where every file should belong to a package.
PAM_TITLE = "Login (PAM) module not installed by any package"
UNOWNED_DIRS: list[tuple[str, str, str, str]] = [
    # (directory, check, severity, title)
    ("/usr/lib/security", "integrity.unowned_pam", "high", PAM_TITLE),
    ("/usr/lib64/security", "integrity.unowned_pam", "high", PAM_TITLE),
    ("/usr/lib/x86_64-linux-gnu/security", "integrity.unowned_pam", "high", PAM_TITLE),
    ("/usr/lib/aarch64-linux-gnu/security", "integrity.unowned_pam", "high", PAM_TITLE),
    ("/usr/lib/systemd/system", "integrity.unowned_unit", "medium",
     "systemd unit not installed by any package"),
    ("/usr/lib/systemd/system-generators", "integrity.unowned_unit", "medium",
     "systemd generator not installed by any package"),
    ("/usr/bin", "integrity.unowned_program", "low", "Program not installed by any package"),
    ("/usr/sbin", "integrity.unowned_program", "low", "Program not installed by any package"),
]
DKMS_RE = re.compile(r"^/usr/lib/modules/[^/]+/(updates|extra|weak-updates|kernel/drivers/misc/vbox)(/|$)")


def unowned(root: RootFS, index: PackageIndex, setid: Iterable[dict[str, Any]] = (),
            stop: threading.Event | None = None) -> list[Finding]:
    """Files in package-managed places that no package installed, SUID programs and kernel modules."""
    findings: list[Finding] = []
    done: set[bytes] = set()
    for directory, check, severity, title in UNOWNED_DIRS:
        try:
            real = root.realpath(directory)
            if real in done:
                continue
            done.add(real)
            entries = list(iter_regular_files(root, real))
        except OSError:
            continue
        for name in entries[:20000]:
            path = names.to_wire(real + b"/" + name)
            if not index.owns(path) and not index.owns(f"{directory}/{names.to_wire(name)}"):
                findings.append(Finding(check, title, path, "", severity,
                                        [f"{index.manager} has no record of this file"], path, path))
    findings.extend(_unowned_modules(root, index, stop))
    for item in setid:
        path = item["path"]
        if index.owns(path):
            continue
        sev = "high" if re.match(r"^/(tmp|var/tmp|dev|home|root|run)/|/\.", path) else \
            "low" if path.startswith(("/usr/local/", "/opt/")) else "high"
        kind = "SUID" if int(item["mode"]) & stat.S_ISUID else "SGID"
        findings.append(Finding("integrity.setid", f"{kind} program not installed by any package", path,
                                f"mode {int(item['mode']) & 0o7777:o}", sev,
                                ["it runs with the rights of its owner (often root)"], path, path, None,
                                "T1548.001", {"uid": item.get("uid")}))
    return findings


def _unowned_modules(root: RootFS, index: PackageIndex, stop: threading.Event | None) -> list[Finding]:
    findings: list[Finding] = []
    count = 0
    bases: list[bytes] = []
    for candidate in ("/usr/lib/modules", "/lib/modules"):
        try:
            real = root.realpath(candidate)
            if real not in bases and root.exists(real):
                bases.append(real)
        except OSError:
            continue
    kernels = []
    for base in bases:
        try:
            kernels.extend(base + b"/" + k for k in root.listdir(base))
        except OSError:
            continue
    for kernel in kernels:
        stack = [kernel]
        while stack and count < 200_000:
            if stop is not None and stop.is_set():
                return findings
            current = stack.pop()
            try:
                fd = root.open_dir(current)
            except OSError:
                continue
            try:
                with os.scandir(fd) as it:
                    listing = [(os.fsencode(e.name), e.is_dir(follow_symlinks=False),
                                e.is_file(follow_symlinks=False)) for e in it]
            finally:
                os.close(fd)
            for name, is_dir, is_file in listing:
                path = current + b"/" + name
                count += 1
                if is_dir:
                    stack.append(path)
                elif is_file and re.search(rb"\.ko(\.(xz|zst|gz))?$", name):
                    wire = names.to_wire(path)
                    if not index.owns(wire) and not DKMS_RE.match(norm(wire)):
                        findings.append(Finding(
                            "integrity.unowned_module", "Kernel module not installed by any package", wire,
                            "",
                            "medium", ["kernel modules run with full system rights"], wire, wire, None,
                            "T1547.006"))
    return findings
