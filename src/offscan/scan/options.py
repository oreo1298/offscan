"""Scan options shared by client and helper (validated on both sides)."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any

MODES = ("quick", "full", "custom")
ENGINES = ("clamav", "yara", "hashes")
TOOLS = ("chkrootkit", "hayabusa", "chainsaw")          # optional external checkers, never bundled
MiB = 1024 * 1024


@dataclass
class Limits:
    max_file_size: int = 100 * MiB         # larger files are hashed only
    max_hash_size: int = 4096 * MiB        # larger files are skipped entirely
    max_scan_size: int = 400 * MiB         # ClamAV: data scanned per file incl. archive members
    archive_depth: int = 17                # ClamAV MaxRecursion
    max_archive_files: int = 10000         # ClamAV MaxFiles
    file_timeout: int = 120                # seconds per file (YARA timeout / clamd MaxScanTime)

    def validate(self) -> None:
        if not (1 * MiB <= self.max_file_size <= 4000 * MiB):
            raise ValueError("max_file_size must be between 1 MiB and 4000 MiB")
        if self.max_hash_size < self.max_file_size:
            raise ValueError("max_hash_size must be at least max_file_size")
        if not (1 * MiB <= self.max_scan_size <= 4000 * MiB):
            raise ValueError("max_scan_size must be between 1 MiB and 4000 MiB")
        if not (0 <= self.archive_depth <= 64):
            raise ValueError("archive_depth must be between 0 and 64")
        if not (1 <= self.max_archive_files <= 1_000_000):
            raise ValueError("max_archive_files must be between 1 and 1000000")
        if not (5 <= self.file_timeout <= 3600):
            raise ValueError("file_timeout must be between 5 and 3600 seconds")


@dataclass
class ScanOptions:
    volumes: list[str]
    mode: str = "quick"
    paths: list[str] = field(default_factory=list)          # custom mode: paths inside the volumes
    engines: list[str] = field(default_factory=lambda: list(ENGINES))
    limits: Limits = field(default_factory=Limits)
    workers: int = 0                                         # 0 = automatic
    detect_pua: bool = False
    runtime_dir: str = ""                                    # prepared by the client
    persistence: bool = True                                 # autostart/persistence checks
    integrity: bool = True                                   # package verification, unowned files
    tools: list[str] = field(default_factory=list)          # optional external tools (opt-in)

    def validate(self) -> None:
        if not self.volumes:
            raise ValueError("no volumes selected")
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if self.mode == "custom" and not self.paths:
            raise ValueError("custom scans need at least one path")
        unknown = set(self.engines) - set(ENGINES)
        if unknown:
            raise ValueError(f"unknown engines: {sorted(unknown)}")
        if not self.engines:
            raise ValueError("enable at least one engine")
        for path in self.paths:
            if "\0" in path or len(path) > 4096:
                raise ValueError("invalid path")
        unknown_tools = set(self.tools) - set(TOOLS)
        if unknown_tools:
            raise ValueError(f"unknown tools: {sorted(unknown_tools)}")
        if not (0 <= self.workers <= 64):
            raise ValueError("workers must be between 0 and 64")
        self.limits.validate()

    def worker_count(self) -> int:
        if self.workers:
            return self.workers
        return max(1, min(8, (os.cpu_count() or 2)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanOptions:
        limits = Limits(**{k: int(v) for k, v in (data.get("limits") or {}).items()
                           if k in Limits.__dataclass_fields__})
        opts = cls(
            volumes=[str(v) for v in data.get("volumes") or []],
            mode=str(data.get("mode", "quick")),
            paths=[str(p) for p in data.get("paths") or []],
            engines=[str(e) for e in data.get("engines") or list(ENGINES)],
            limits=limits,
            workers=int(data.get("workers") or 0),
            detect_pua=bool(data.get("detect_pua", False)),
            runtime_dir=str(data.get("runtime_dir", "")),
            persistence=bool(data.get("persistence", True)),
            integrity=bool(data.get("integrity", True)),
            tools=[str(t) for t in data.get("tools") or []],
        )
        opts.validate()
        return opts


def parse_size(text: str) -> int:
    """Parse '100M', '2G', '512k' or a plain byte count."""
    text = text.strip().upper()
    units = {"K": 1024, "M": MiB, "G": 1024 * MiB, "T": 1024 * 1024 * MiB}
    if text and text[-1] == "B":
        text = text[:-1]
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text)
