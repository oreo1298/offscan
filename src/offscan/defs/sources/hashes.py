"""SHA-256 hash list sources (malware lists and the NSRL known-good list)."""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from ...scan import hashdb
from .. import verify
from .base import (
    DAY,
    HOUR,
    FetchContext,
    Source,
    SourceError,
    SourceInfo,
    Unchanged,
    iter_digest_file,
    read_digests,
    write_digests,
    write_material,
)

MiB = 1 << 20
ABUSECH_TERMS = ("Free for personal and non-commercial use under abuse.ch's fair-use terms with "
                 "your own free Auth-Key (https://auth.abuse.ch/); commercial use needs a "
                 "Spamhaus licence. Do not redistribute.")


def _hashes_material(ctx: FetchContext, entries: list[dict[str, Any]], version: str,
                     verified: str, **extra: Any) -> dict[str, Any]:
    return write_material(ctx.staging, {"hashes": entries, "version": version, "verified": verified,
                                        **extra})


def _parse_hash_text(path: Path, strict: bool) -> list[bytes]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(hashdb.parse_hex_lines(fh, strict=strict))


class MalwareBazaar(Source):
    info = SourceInfo(
        id="malwarebazaar", name="MalwareBazaar (abuse.ch) SHA-256 list", kind="hashes",
        homepage="https://bazaar.abuse.ch/", license="abuse.ch terms of use",
        license_url="https://abuse.ch/terms-of-use/", terms=ABUSECH_TERMS,
        default_enabled=False, requires_secret="abusech_auth_key", min_interval=HOUR,
        size_hint="about 40 MB download, 35 MB on disk", group="Hash lists",
        integrity="HTTPS + strict line validation (no published checksums)")
    full_every = 7 * DAY

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        key = ctx.secret("abusech_auth_key")
        if not key or not re.fullmatch(r"[0-9a-fA-F]{20,128}", key):
            raise SourceError("set your abuse.ch Auth-Key (from https://auth.abuse.ch/)")
        base = self.base_url("https://mb-api.abuse.ch/v2/files/exports/").rstrip("/") + f"/{key}/"
        last_full = float(ctx.state.get("last_full", 0))
        digests: set[bytes] = set()
        if ctx.previous is None or ctx.now - last_full > self.full_every:
            ctx.progress("MalwareBazaar: full list…")
            archive = ctx.download(base + "sha256_full.txt.zip", "full.zip", max_size=512 * MiB,
                                   conditional=False)
            files = verify.extract_zip(archive, ctx.staging / "x", lambda r: r.suffix == ".txt",
                                       max_file=1024 * MiB, max_total=1024 * MiB, flatten=True)
            archive.unlink()
            for f in files:
                digests.update(_parse_hash_text(f, strict=True))
                f.unlink()
            (ctx.staging / "x").rmdir()
            if len(digests) < 100_000:
                raise SourceError(f"the full list has only {len(digests)} entries; refusing it")
            ctx.state["last_full"] = ctx.now
        else:
            ctx.progress("MalwareBazaar: recent additions…")
            digests.update(read_digests(ctx.previous / "digests.bin"))
            recent = ctx.download(base + "sha256_recent.txt", "recent.txt", max_size=64 * MiB,
                                  conditional=False)
            digests.update(_parse_hash_text(recent, strict=True))
            recent.unlink()
        count = write_digests(ctx.staging / "digests.bin", digests)
        return _hashes_material(ctx, [{"id": self.id, "file": "digests.bin", "meta": {
            "name": "MalwareBazaar", "category": "malware", "severity": "high",
            "signature": "MalwareBazaar.SHA256"}}], time.strftime("%Y-%m-%d", time.gmtime(ctx.now)),
            "https", count=count)


def iter_threatfox_sha256(data: Any) -> list[bytes]:
    """ThreatFox JSON exports map ids to lists of IOC objects; be tolerant of shape changes."""
    out: list[bytes] = []
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if str(item.get("ioc_type", "")).lower() in ("sha256_hash", "sha256"):
                value = str(item.get("ioc_value") or item.get("ioc") or "").strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", value):
                    out.append(bytes.fromhex(value))
                continue
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return out


class ThreatFox(Source):
    info = SourceInfo(
        id="threatfox", name="ThreatFox (abuse.ch) file hashes", kind="hashes",
        homepage="https://threatfox.abuse.ch/", license="abuse.ch terms of use",
        license_url="https://abuse.ch/terms-of-use/", terms=ABUSECH_TERMS,
        default_enabled=False, requires_secret="abusech_auth_key", min_interval=6 * HOUR,
        size_hint="a few MB", group="Hash lists", integrity="HTTPS + strict validation")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        key = ctx.secret("abusech_auth_key")
        if not key or not re.fullmatch(r"[0-9a-fA-F]{20,128}", key):
            raise SourceError("set your abuse.ch Auth-Key (from https://auth.abuse.ch/)")
        base = self.base_url("https://threatfox-api.abuse.ch/v2/files/exports/").rstrip("/") + f"/{key}/"
        archive = ctx.download(base + "full.json.zip", "full.zip", max_size=512 * MiB, conditional=False)
        files = verify.extract_zip(archive, ctx.staging / "x", lambda r: r.suffix == ".json",
                                   max_file=2048 * MiB, max_total=2048 * MiB, flatten=True)
        archive.unlink()
        digests: list[bytes] = []
        for f in files:
            try:
                digests.extend(iter_threatfox_sha256(json.loads(f.read_text(encoding="utf-8"))))
            except ValueError as exc:
                raise SourceError(f"ThreatFox export is not valid JSON: {exc}") from exc
            f.unlink()
        (ctx.staging / "x").rmdir()
        count = write_digests(ctx.staging / "digests.bin", digests)
        return _hashes_material(ctx, [{"id": self.id, "file": "digests.bin", "meta": {
            "name": "ThreatFox", "category": "malware", "severity": "high",
            "signature": "ThreatFox.SHA256"}}], time.strftime("%Y-%m-%d", time.gmtime(ctx.now)),
            "https", count=count)


class MalShare(Source):
    info = SourceInfo(
        id="malshare", name="MalShare daily SHA-256 lists", kind="hashes",
        homepage="https://malshare.com/", license="MalShare terms (credit MalShare)",
        license_url="https://malshare.com/about.php",
        terms="Free daily lists of samples uploaded to MalShare. MalShare notes that not every "
              "file is malicious, so matches are reported with medium severity.",
        default_enabled=False, requires_secret="malshare_api_key", secret_optional=True,
        min_interval=6 * HOUR, size_hint="< 10 MB", group="Hash lists",
        integrity="HTTPS + per-day checksum list", warning="Unvetted: may include benign files.")
    initial_days = 30

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        base = self.base_url("https://malshare.com/daily/").rstrip("/") + "/"
        today = dt.datetime.fromtimestamp(ctx.now, dt.UTC).date()
        have = set(ctx.state.get("days", [])) if ctx.previous else set()
        digests: set[bytes] = set(read_digests(ctx.previous / "digests.bin")) if ctx.previous else set()
        wanted = [today - dt.timedelta(days=i) for i in range(1, self.initial_days + 1)]
        new_days = []
        for day in wanted:
            ds = day.isoformat()
            if ds in have:
                continue
            ctx.check_cancel()
            name = f"malshare_fileList.{ds}.sha256.txt"
            try:
                path = ctx.download(f"{base}{ds}/{name}", name, max_size=32 * MiB, conditional=False)
            except Exception as exc:
                if "404" in str(exc):
                    continue
                raise
            digests.update(_parse_hash_text(path, strict=False))
            path.unlink()
            new_days.append(ds)
        if not new_days and ctx.previous:
            raise Unchanged("no new daily lists")
        keep = sorted(have | set(new_days))[-120:]
        ctx.state["days"] = keep
        count = write_digests(ctx.staging / "digests.bin", digests)
        return _hashes_material(ctx, [{"id": self.id, "file": "digests.bin", "meta": {
            "name": "MalShare", "category": "suspicious", "severity": "medium",
            "signature": "MalShare.SHA256"}}], keep[-1] if keep else "none", "https", count=count)


class LOLDrivers(Source):
    info = SourceInfo(
        id="loldrivers", name="LOLDrivers (vulnerable and malicious Windows drivers)", kind="hashes",
        homepage="https://www.loldrivers.io/", license="Apache-2.0",
        license_url="https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE",
        terms="Apache-2.0. Vulnerable drivers are legitimate but abusable ('bring your own "
              "vulnerable driver'); malicious drivers are malware.",
        default_enabled=True, min_interval=12 * HOUR, size_hint="< 1 MB", group="Hash lists",
        integrity="HTTPS from GitHub + strict validation")
    lists = (
        ("samples_malicious.sha256", "hashes", "loldrivers-malicious", "malicious_driver", "high"),
        ("samples_vulnerable.sha256", "hashes", "loldrivers-vulnerable", "vulnerable_driver", "medium"),
        # Separate ids: hash_sources metadata is keyed by id and the signature names differ.
        ("authentihash_samples_malicious.sha256", "authentihash", "loldrivers-malicious-authentihash",
         "malicious_driver", "high"),
        ("authentihash_samples_vulnerable.sha256", "authentihash", "loldrivers-vulnerable-authentihash",
         "vulnerable_driver", "medium"),
    )

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        base = self.base_url(
            "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/")
        base = base.rstrip("/") + "/"
        material: dict[str, Any] = {"hashes": [], "authentihash": []}
        changed = False
        total = 0
        for name, kind, sub_id, category, severity in self.lists:
            ctx.check_cancel()
            try:
                path = ctx.download(base + name, name, max_size=16 * MiB)
                changed = True
            except Unchanged:
                path = ctx.reuse(name)
            digests = _parse_hash_text(path, strict=False)
            if len(digests) < 50:
                raise SourceError(f"{name} has only {len(digests)} hashes; refusing it")
            out = name.replace(".sha256", ".bin")
            total += write_digests(ctx.staging / out, digests)
            label = "Malicious driver" if "malicious" in sub_id else "Vulnerable driver"
            material[kind].append({"id": sub_id, "file": out, "meta": {
                "name": f"LOLDrivers: {label.lower()}", "category": category, "severity": severity,
                "signature": f"LOLDrivers.{label.replace(' ', '')}"
                             + (".Authentihash" if kind == "authentihash" else ".SHA256")}})
        if not changed:
            raise Unchanged("lists unchanged")
        return write_material(ctx.staging, {**material, "verified": "https", "count": total,
                                            "version": time.strftime("%Y-%m-%d", time.gmtime(ctx.now))})


class ESETMalwareIOC(Source):
    info = SourceInfo(
        id="eset-ioc", name="ESET malware-ioc SHA-256 lists", kind="hashes",
        homepage="https://github.com/eset/malware-ioc", license="BSD-2-Clause",
        license_url="https://github.com/eset/malware-ioc/blob/master/LICENSE",
        terms="BSD-2-Clause. Indicators published with ESET Research reports.",
        default_enabled=True, min_interval=DAY, size_hint="< 1 MB (downloads a 10–30 MB archive)",
        group="Hash lists", integrity="HTTPS from GitHub, pinned to the latest commit")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        from .yara import fetch_repo_tarball
        tarball, version, verified = fetch_repo_tarball(ctx, "eset/malware-ioc", "master")
        files = verify.extract_tar(tarball, ctx.staging / "x",
                                   lambda r: r.name.endswith(".sha256") or r.name == "samples.sha256",
                                   max_file=32 * MiB, max_total=256 * MiB, strip_components=1)
        tarball.unlink()
        digests: list[bytes] = []
        for f in files:
            digests.extend(_parse_hash_text(f, strict=False))
        import shutil
        shutil.rmtree(ctx.staging / "x", ignore_errors=True)
        if len(digests) < 500:
            raise SourceError(f"only {len(digests)} hashes found; refusing it")
        count = write_digests(ctx.staging / "digests.bin", digests)
        return _hashes_material(ctx, [{"id": self.id, "file": "digests.bin", "meta": {
            "name": "ESET malware-ioc", "category": "malware", "severity": "high",
            "signature": "ESET.IOC.SHA256"}}], version, verified, count=count)


class NSRL(Source):
    info = SourceInfo(
        id="nsrl", name="NIST NSRL RDS (known software, allowlist)", kind="known_good",
        homepage="https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl",
        license="NIST Special Database 28 (public)", license_url="https://www.nist.gov/open/license",
        terms="Public data from NIST. Used only to mark files as known software; it never hides "
              "a malware detection (the NSRL also contains hacking tools).",
        default_enabled=False, min_interval=30 * DAY,
        size_hint="downloads about 18 GB and needs over 100 GB of temporary disk; "
                  "keeps about 2.3 GB", group="Allowlists",
        integrity="SHA-1 checksum file next to the archive + zip CRC",
        warning="Very large; meant for forensic workstations.")
    release_default = "2026.09.1"

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        release = self.settings.source(self.id).get("release") or self.release_default
        if not re.fullmatch(r"\d{4}\.\d{2}\.\d", release):
            raise SourceError("invalid NSRL release name")
        if ctx.previous and ctx.state.get("version") == release:
            raise Unchanged(release)
        base = self.base_url("https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/").rstrip("/")
        name = f"RDS_{release}_modern_minimal.zip"
        ctx.progress(f"NSRL: downloading {name} (very large)…")
        archive = ctx.download(f"{base}/rds_{release}/{name}", name, max_size=64 << 30, conditional=False)
        sha1_text = ctx.session.fetch_text(f"{base}/rds_{release}/{name}.sha", max_size=4096)
        import hashlib
        expected = re.search(r"\b[0-9a-fA-F]{40}\b", sha1_text)
        if expected:
            h = hashlib.sha1(usedforsecurity=False)
            with open(archive, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest().lower() != expected.group(0).lower():
                raise SourceError("NSRL archive checksum mismatch")
        dbs = verify.extract_zip(archive, ctx.staging / "x", lambda r: r.suffix == ".db",
                                 max_file=1 << 40, max_total=1 << 40, flatten=True)
        archive.unlink()
        if not dbs:
            raise SourceError("no RDS database in the archive")
        count = export_known_good(dbs[0], ctx.staging / "digests.bin")
        import shutil
        shutil.rmtree(ctx.staging / "x", ignore_errors=True)
        return write_material(ctx.staging, {"known_good": "digests.bin", "version": release,
                                            "verified": "sha1+crc", "count": count})


def export_known_good(rds_db: Path, out: Path) -> int:
    """Stream DISTINCT sha256 values (SQLite sorts on disk) into a raw digest file."""
    conn = sqlite3.connect(f"file:{rds_db}?mode=ro&immutable=1", uri=True)
    count = 0
    try:
        with open(out, "wb") as fh:
            for (value,) in conn.execute("SELECT DISTINCT lower(sha256) FROM FILE "
                                         "WHERE sha256 IS NOT NULL ORDER BY 1"):
                if isinstance(value, str) and len(value) == 64:
                    try:
                        fh.write(bytes.fromhex(value))
                        count += 1
                    except ValueError:
                        continue
    finally:
        conn.close()
    return count


__all__ = [
    "NSRL",
    "ESETMalwareIOC",
    "LOLDrivers",
    "MalShare",
    "MalwareBazaar",
    "ThreatFox",
    "export_known_good",
    "iter_digest_file",
    "iter_threatfox_sha256",
]
