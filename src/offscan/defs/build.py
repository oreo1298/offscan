"""Build a definition set directory from fetched source material."""

from __future__ import annotations

import os
import shutil
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..scan import hashdb, yara_engine
from . import layout


def build_set(out: Path, *,
              set_id: str,
              sources: dict[str, dict[str, Any]],
              clamav_files: dict[str, Path | bytes] | None = None,
              clamav_official: str | None = None,
              yara_sources: list[tuple[str, str, str]] | None = None,
              yara_namespaces: dict[str, str] | None = None,
              hash_lists: dict[str, tuple[dict[str, Any], Iterable[bytes]]] | None = None,
              known_good: Iterable[bytes] | None = None,
              yara_engine_name: str | None = None) -> dict[str, Any]:
    """Create ``out`` (must not exist) and return the manifest written into it."""
    out.mkdir(parents=True, mode=0o755)
    manifest: dict[str, Any] = {"id": set_id, "created": time.time(), "sources": sources,
                                "clamav": {"files": [], "official": clamav_official,
                                           "system_dir": layout.SYSTEM_CLAMAV_DIR},
                                "yara": {}, "hashes": {"malware": [], "known_good": None},
                                "hash_sources": {}}
    cdir = out / "clamav"
    cdir.mkdir(mode=0o755)
    for name, content in sorted((clamav_files or {}).items()):
        if "/" in name or name.startswith("."):
            raise layout.LayoutError(f"bad ClamAV file name {name!r}")
        target = cdir / name
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            _link_or_copy(Path(content), target)
        os.chmod(target, 0o644)
        manifest["clamav"]["files"].append(name)
    ydir = out / "yara"
    ydir.mkdir(mode=0o755)
    if yara_sources:
        src = ydir / "src"
        src.mkdir(mode=0o755)
        for namespace, origin, text in yara_sources:
            safe = origin.replace("/", "__")
            (src / f"{namespace}--{safe}").write_text(text, encoding="utf-8")
        engine = yara_engine_name or yara_engine.engine_name()
        if engine:
            target = ydir / yara_engine.compiled_filename(engine)
            result = yara_engine.compile_sources(yara_sources, target, engine)
            os.chmod(target, 0o644)
            manifest["yara"] = {"engine": result.engine, "version": result.version,
                                "file": target.name, "rules": result.rules,
                                "namespaces": yara_namespaces or {},
                                "skipped_files": result.skipped_files[:200],
                                "errors": result.errors[:200]}
    hdir = out / "hashes"
    hdir.mkdir(mode=0o755)
    if hash_lists:
        entries: list[tuple[bytes, str]] = []
        for source_id, (meta, digests) in hash_lists.items():
            manifest["hash_sources"][source_id] = meta
            entries.extend((d, source_id) for d in digests)
        count = hashdb.build(hdir / "malware.ofh", entries)
        os.chmod(hdir / "malware.ofh", 0o644)
        manifest["hashes"]["malware"].append("malware.ofh")
        manifest["hashes"]["malware_count"] = count
    if known_good is not None:
        count = hashdb.build(hdir / "known_good.ofh", ((d, "known_good") for d in known_good))
        os.chmod(hdir / "known_good.ofh", 0o644)
        manifest["hashes"]["known_good"] = "known_good.ofh"
        manifest["hashes"]["known_good_count"] = count
    layout.write_manifest(out, manifest)
    return layout.load_manifest(out)


def _link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)
