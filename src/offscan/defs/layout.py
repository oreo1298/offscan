"""On-disk layout of one *definition set* (immutable once built).

::

    <set>/manifest.json
    <set>/clamav/            ClamAV database files (third-party + private official copy)
    <set>/yara/rules.yarx    compiled by us for the installed engine version
    <set>/yara/src/...       rule sources (bundles carry these, never compiled rules)
    <set>/hashes/*.ofh       hash databases (see offscan.scan.hashdb)

``manifest.json`` (version 1)::

    {"format": 1, "id": "...", "created": 1760000000.0,
     "sources": {"<id>": {"name", "version", "updated", "size", "license", ...}},
     "clamav": {"files": [...], "official": "system" | "private" | null,
                "system_dir": "/var/lib/clamav"},
     "yara": {"engine": "yara-x", "version": "1.22.0", "file": "rules.yarx",
              "rules": 5137, "namespaces": {"<ns>": "<source id>"}},
     "hashes": {"malware": ["malware.ofh"], "known_good": "known_good.ofh" | null},
     "hash_sources": {"<source id>": {"name", "category", "severity", "signature"}}}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FORMAT = 1
MANIFEST = "manifest.json"
CLAMAV_EXTENSIONS = (".cvd", ".cld", ".cud", ".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb",
                     ".mdu", ".msu", ".ndb", ".ndu", ".ldb", ".ldu", ".idb", ".cdb", ".cbc",
                     ".fp", ".sfp", ".ign", ".ign2", ".ftm", ".pdb", ".wdb", ".gdb", ".imp",
                     ".yar", ".yara", ".sign", ".info", ".crb", ".cat")
SYSTEM_CLAMAV_DIR = "/var/lib/clamav"


class LayoutError(Exception):
    pass


def load_manifest(set_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads((set_dir / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LayoutError(f"cannot read {set_dir / MANIFEST}: {exc}") from exc
    if data.get("format") != FORMAT:
        raise LayoutError(f"unsupported definition set format {data.get('format')!r}")
    return data


def write_manifest(set_dir: Path, manifest: dict[str, Any]) -> None:
    manifest = {"format": FORMAT, **manifest}
    tmp = set_dir / (MANIFEST + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(set_dir / MANIFEST)


def system_clamav_files(directory: str = SYSTEM_CLAMAV_DIR) -> list[Path]:
    """Official databases maintained by the distribution's freshclam."""
    base = Path(directory)
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return []
    return [p for p in entries if p.is_file() and p.suffix in (".cvd", ".cld", ".cud", ".sign")
            and (p.name.startswith(("main", "daily", "bytecode")))]
