"""Definition source framework.

A source knows how to fetch, verify and store one upstream feed.  Each
successful fetch produces an immutable *version directory* containing the
verified files plus ``material.json``, which tells the set builder what to
use::

    {"clamav": ["rogue.hdb", ...],                       # ClamAV database files
     "clamav_official": "system" | "private" | null,
     "yara": [{"file": "rules.yar", "origin": "core"}],  # rule sources
     "hashes": [{"id": "malwarebazaar", "file": "digests.bin", "meta": {...}}],
     "authentihash": [{"id": ..., "file": ..., "meta": {...}}],
     "known_good": "digests.bin" | null,
     "version": "...", "verified": "gpg|sha256|github-digest|https|local", ...}

Digest files (``*.bin``) are sorted, de-duplicated raw 32-byte SHA-256s.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ... import log
from ...settings import Settings
from .. import net, verify

logger = log.get("defs.sources")

HOUR = 3600
DAY = 86400


class SourceError(Exception):
    pass


class Unchanged(Exception):
    """The upstream data has not changed since the stored version."""


@dataclass(frozen=True)
class SourceInfo:
    id: str
    name: str
    kind: str                          # clamav | yara | hashes | known_good
    homepage: str
    license: str
    license_url: str
    terms: str
    default_enabled: bool = False
    requires_secret: str | None = None  # settings secret name
    secret_optional: bool = False
    requires_acceptance: bool = False   # licence must be accepted before enabling
    min_interval: int = 6 * HOUR        # politeness: never check more often
    size_hint: str = ""
    warning: str = ""
    group: str = ""
    integrity: str = ""                 # how downloads are verified (shown in the UI)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FetchContext:
    session: net.Session
    settings: Settings
    staging: Path
    previous: Path | None              # previous version dir (for incremental feeds)
    state: dict[str, Any]
    store: Path = Path(".")            # definitions store root
    cancel: threading.Event = field(default_factory=threading.Event)
    progress: Callable[[str], None] = lambda message: None
    now: float = field(default_factory=time.time)

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise SourceError("cancelled")

    def secret(self, name: str | None) -> str | None:
        if name is None:
            return None
        value = self.settings.secret(name)
        if value:
            log.register_secret(value)
        return value

    # -- conditional download helpers ---------------------------------------

    def download(self, url: str, name: str, *, max_size: int, allow_http: bool = False,
                 conditional: bool = True, headers: dict[str, str] | None = None) -> Path:
        """Download ``url`` into staging as ``name``; raises :class:`Unchanged` on 304."""
        etags = self.state.setdefault("etags", {})
        modified = self.state.setdefault("last_modified", {})
        key = _url_key(url)
        try:
            dl = self.session.fetch(
                url, self.staging, max_size=max_size, allow_http=allow_http, headers=headers,
                cancel=self.cancel,
                etag=etags.get(key) if conditional and self.previous else None,
                last_modified=modified.get(key) if conditional and self.previous else None)
        except net.NotModified:
            raise Unchanged(url) from None
        target = self.staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(dl.path, target)
        if dl.etag:
            etags[key] = dl.etag
        if dl.last_modified:
            modified[key] = dl.last_modified
        return target

    def reuse(self, name: str) -> Path:
        """Copy an unchanged file from the previous version into staging."""
        if self.previous is None or not (self.previous / name).exists():
            raise SourceError(f"{name} is unchanged upstream but missing locally; retry with --force")
        target = self.staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(self.previous / name, target)
        except OSError:
            target.write_bytes((self.previous / name).read_bytes())
        return target


def _url_key(url: str) -> str:
    # Never store secrets (keys in URL paths) in state files.
    import hashlib
    return hashlib.sha256(url.encode()).hexdigest()[:32]


class Source:
    info: SourceInfo

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def id(self) -> str:
        return self.info.id

    def base_url(self, default: str) -> str:
        return self.settings.override(self.id).get("base_url") or default

    def enabled(self) -> bool:
        if self.info.requires_acceptance and not self.settings.source(self.id).get("accepted_license"):
            return False
        return self.settings.source_enabled(self.id, self.info.default_enabled)

    def configured(self) -> tuple[bool, str]:
        if self.info.requires_secret and not self.info.secret_optional \
                and not self.settings.secret(self.info.requires_secret):
            return False, f"needs the setting '{self.info.requires_secret}'"
        return True, ""

    def min_interval(self) -> int:
        override = self.settings.source(self.id).get("interval")
        if isinstance(override, int) and override >= self.info.min_interval:
            return override
        return self.info.min_interval

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        """Download into ``ctx.staging`` and return the material description."""
        raise NotImplementedError


# -- helpers shared by sources ----------------------------------------------------

def jitter(seconds: int) -> int:
    return seconds + random.randint(0, max(60, seconds // 10))  # noqa: S311 (not security)


def write_digests(path: Path, digests: Iterable[bytes]) -> int:
    unique = sorted(set(digests))
    with open(path, "wb") as fh:
        for d in unique:
            fh.write(d)
    return len(unique)


def read_digests(path: Path) -> list[bytes]:
    data = path.read_bytes()
    if len(data) % 32:
        raise SourceError(f"{path.name}: corrupt digest file")
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def iter_digest_file(path: Path) -> Iterable[bytes]:
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(32 * 4096)
            if not chunk:
                return
            for i in range(0, len(chunk), 32):
                yield chunk[i:i + 32]


def write_material(staging: Path, material: dict[str, Any]) -> dict[str, Any]:
    (staging / "material.json").write_text(json.dumps(material, indent=1, sort_keys=True),
                                           encoding="utf-8")
    return material


def material_files(material: dict[str, Any]) -> list[str]:
    """Every file a material.json refers to (relative to its version directory)."""
    files = list(material.get("clamav", []))
    for key in ("yara", "hashes", "authentihash"):
        files += [item["file"] for item in material.get(key, [])]
    if material.get("known_good"):
        files.append(material["known_good"])
    return files


def material_path(version_dir: Path, name: Any) -> Path:
    """``version_dir / name``, refusing anything that could lead outside it."""
    safe = verify.safe_member_name(name) if isinstance(name, str) else None
    if safe is None:
        raise SourceError(f"material.json: unsafe file name {str(name)[:100]!r}")
    path = version_dir
    for part in safe.parts:
        path = path / part
        if path.is_symlink():
            raise SourceError(f"material.json: {safe} goes through a symbolic link")
    return path


def load_material(version_dir: Path) -> dict[str, Any]:
    """Read and check a version directory's material.json.

    It names the files the set is built from. They must all be plain files
    inside the version directory, whatever wrote the material (a source, or
    an imported bundle).
    """
    try:
        material = json.loads((version_dir / "material.json").read_text(encoding="utf-8"))
        if not isinstance(material, dict):
            raise TypeError("not an object")
        for name in material_files(material):
            path = material_path(version_dir, name)
            if not path.is_file():
                raise SourceError(f"material.json: {name} is missing")
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise SourceError(f"material.json is malformed: {exc}") from exc
    return material


def validate_clamav_files(files: list[Path]) -> None:
    for path in files:
        verify.clamav_load_test(path)
