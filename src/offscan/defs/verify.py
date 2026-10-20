"""Integrity checks and safe handling of downloaded definition material.

Downloads are untrusted until verified.  Archives are never extracted with
the library's own extract functions: we copy only expected regular-file
members, with sanitised names and hard size limits (zip bombs, path
traversal, symlinks and device entries are rejected).
"""

from __future__ import annotations

import hashlib
import os
import re
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .. import tools
from ..defs.testset import eicar

COPY_CHUNK = 1 << 20


class VerificationError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(COPY_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


_HEX64 = re.compile(r"\b([0-9a-fA-F]{64})\b")


def parse_checksum_file(text: str, name: str | None = None) -> str:
    """Return the SHA-256 from a ``.sha256`` sidecar (``<hex>  <name>`` or just ``<hex>``)."""
    for line in text.splitlines():
        match = _HEX64.search(line)
        if match and (name is None or name in line or line.strip() == match.group(1)
                      or len(line.split()) == 1):
            return match.group(1).lower()
    raise VerificationError("no SHA-256 found in the checksum file")


def expect_sha256(path: Path, expected: str) -> None:
    actual = sha256_file(path)
    if actual != expected.lower():
        raise VerificationError(f"SHA-256 mismatch: expected {expected[:16]}…, got {actual[:16]}…")


# -- GnuPG -------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    fingerprint: str        # of the primary key
    timestamp: float        # when the signature was made


def gpg_verify(data: Path, signature: Path, keyring: Path, fingerprints: set[str],
               not_before: float | None = None) -> Signature:
    """Verify a detached signature with ``gpgv`` against a pinned key.

    ``not_before`` refuses a valid signature older than that time: a mirror
    must not be able to serve an old (correctly signed) file again.
    """
    gpgv = tools.find("gpgv") or tools.find("gpgv2")
    if gpgv is None:
        raise VerificationError("gpgv (GnuPG) is required to verify signatures but is not installed")
    with tempfile.TemporaryDirectory(prefix="gpgv-") as home:
        proc = tools.run([gpgv, "--homedir", home, "--status-fd", "1", "--keyring", str(keyring),
                          str(signature), str(data)], timeout=120, check=False)
    valid = [line.split() for line in proc.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG")]
    if proc.returncode != 0 or not valid:
        reason = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["unknown error"]
        raise VerificationError(f"bad or missing signature: {reason[0][:200]}")
    for fields in valid:
        signer = fields[2].upper()
        primary = fields[-1].upper() if len(fields) >= 12 else signer
        if signer in fingerprints or primary in fingerprints:
            stamp = float(fields[4]) if len(fields) > 4 and fields[4].isdigit() else 0.0
            if not_before is not None and stamp + 60 < not_before:
                raise VerificationError(f"{data.name}: the signature is older than the copy already "
                                        "installed (an outdated mirror, or a replay)")
            return Signature(primary, stamp)
    raise VerificationError("signed by an unexpected key")


# -- archives ----------------------------------------------------------------

def safe_member_name(name: str) -> PurePosixPath | None:
    """Normalised relative path of an archive member, or None if unsafe."""
    if not name or "\0" in name or "\\" in name:
        return None
    path = PurePosixPath(name)
    if path.is_absolute():
        return None
    parts = [p for p in path.parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return PurePosixPath(*parts)


def _copy_limited(src, dst: Path, limit: int) -> int:
    total = 0
    with open(dst, "wb") as out:
        while True:
            chunk = src.read(COPY_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise VerificationError(f"archive member exceeds the {limit} byte limit")
            out.write(chunk)
    return total


def extract_zip(archive: Path, dest: Path, want: Callable[[PurePosixPath], bool], *,
                max_file: int, max_total: int, max_members: int = 100_000,
                flatten: bool = False) -> list[Path]:
    out: list[Path] = []
    total = 0
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise VerificationError(f"not a valid zip archive: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > max_members:
            raise VerificationError("archive has too many members")
        for info in infos:
            if info.is_dir():
                continue
            rel = safe_member_name(info.filename)
            if rel is None:
                raise VerificationError(f"unsafe path in archive: {info.filename[:100]!r}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in (0, 0o100000):           # symlinks, devices, ...
                continue
            if not want(rel):
                continue
            target = dest / (rel.name if flatten else rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src:
                total += _copy_limited(src, target, min(max_file, max_total - total))
            out.append(target)
    return out


def extract_tar(archive: Path, dest: Path, want: Callable[[PurePosixPath], bool], *,
                max_file: int, max_total: int, max_members: int = 500_000,
                strip_components: int = 0, flatten: bool = False) -> list[Path]:
    out: list[Path] = []
    total = 0
    count = 0
    try:
        tf = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise VerificationError(f"not a valid tar archive: {exc}") from exc
    with tf:
        for member in tf:
            count += 1
            if count > max_members:
                raise VerificationError("archive has too many members")
            if not member.isreg():
                continue
            rel = safe_member_name(member.name)
            if rel is None:
                raise VerificationError(f"unsafe path in archive: {member.name[:100]!r}")
            if strip_components:
                if len(rel.parts) <= strip_components:
                    continue
                rel = PurePosixPath(*rel.parts[strip_components:])
            if not want(rel):
                continue
            if member.size > max_file:
                raise VerificationError(f"archive member {rel} is too large")
            target = dest / (rel.name if flatten else rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                total += _copy_limited(src, target, min(max_file, max_total - total))
            out.append(target)
    return out


# -- ClamAV database files -----------------------------------------------------

_TEXT_EXT = {".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb", ".ndb", ".ndu", ".ldb", ".ldu",
             ".cdb", ".fp", ".sfp", ".ign", ".ign2", ".ftm", ".idb", ".pdb", ".wdb", ".gdb", ".imp",
             ".yar", ".yara"}


def sanity_check_clamav_text(path: Path, min_lines: int = 1) -> int:
    """Cheap structural check of a text ClamAV database; returns the signature count."""
    data = path.read_bytes()
    if b"\0" in data:
        raise VerificationError(f"{path.name}: binary data in a text signature file")
    head = data[:512].lstrip().lower()
    if head.startswith((b"<!doctype", b"<html", b"<?xml", b"{")):
        raise VerificationError(f"{path.name}: the server returned a web page or notice, "
                                "not signatures")
    lines = [line for line in data.splitlines() if line.strip() and not line.startswith(b"#")]
    if len(lines) < min_lines:
        raise VerificationError(f"{path.name}: no signatures")
    if path.suffix in (".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb"):
        bad = [line for line in lines[:2000] if line.count(b":") < 2]
        if bad:
            raise VerificationError(f"{path.name}: malformed hash signature line {bad[0][:60]!r}")
    if path.suffix in (".ndb", ".ndu"):
        bad = [line for line in lines[:2000] if line.count(b":") < 3]
        if bad:
            raise VerificationError(f"{path.name}: malformed body signature line {bad[0][:60]!r}")
    return len(lines)


def clamav_load_test(path: Path) -> None:
    """Load one database file with clamscan (one bad file would abort the whole set)."""
    if path.suffix in _TEXT_EXT:
        sanity_check_clamav_text(path, 0 if path.suffix in (".ign", ".ign2", ".fp", ".sfp") else 1)
    clamscan = tools.find("clamscan")
    if clamscan is None:
        return                       # validated structurally only
    with tempfile.TemporaryDirectory(prefix="clamtest-") as tmp:
        sample = Path(tmp) / "sample.txt"
        sample.write_bytes(b"offline definition load test\n" + eicar()[:10])
        dbdir = Path(tmp) / "db"
        dbdir.mkdir()
        try:
            os.link(path, dbdir / path.name)
        except OSError:
            (dbdir / path.name).write_bytes(path.read_bytes())
        sign = path.with_name(path.name + ".sign")
        if sign.exists():
            (dbdir / sign.name).write_bytes(sign.read_bytes())
        proc = tools.run([clamscan, "--no-summary", f"--database={dbdir}", str(sample)],
                         timeout=900, check=False)
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["load failed"]
        raise VerificationError(f"{path.name}: ClamAV cannot load it: {detail[0][:200]}")


def cvd_info(path: Path) -> dict[str, str]:
    """``sigtool --info`` (also verifies the CVD's digital signature)."""
    sigtool = tools.find("sigtool")
    if sigtool is None:
        raise VerificationError("sigtool (ClamAV) is not installed")
    proc = tools.run([sigtool, "--info", str(path)], timeout=300, check=False)
    info: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            info[key.strip().lower()] = value.strip()
    if proc.returncode != 0:
        raise VerificationError(f"{path.name}: {(proc.stderr or proc.stdout).strip()[:200]}")
    if path.suffix == ".cvd" and "verification ok" not in proc.stdout.lower():
        raise VerificationError(f"{path.name}: digital signature verification failed")
    return info
