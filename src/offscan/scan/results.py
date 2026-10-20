"""Detections, severities and scan summaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CHECK_ENGINES = ("persistence", "integrity", "tool")      # findings that are not file detections


@dataclass
class Detection:
    volume: str
    path: str                     # protocol form (surrogateescape str), relative to the volume root
    engine: str                   # clamav | yara | hash | persistence | integrity
    signature: str
    severity: str = "high"
    sha256: str | None = None
    size: int | None = None
    source: str | None = None     # definition source id
    category: str | None = None   # malware | pua | vulnerable_driver | persistence | ...
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Detection:
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in fields})

    @property
    def key(self) -> tuple[str, str, str, str]:
        location = self.details.get("location") if self.engine in CHECK_ENGINES else None
        signature = f"{self.signature}\0{location}" if location else self.signature
        return (self.volume, self.path, self.engine, signature)

    @property
    def identity(self) -> str | None:
        """What a false-positive mark refers to: the file hash, or the entry's fingerprint."""
        return self.sha256 or self.details.get("fingerprint")

    @property
    def inventory(self) -> bool:
        """An informational autostart/integrity entry, not something to act on."""
        return self.engine in CHECK_ENGINES and self.severity == "info"


def clamav_severity(name: str) -> tuple[str, str]:
    """Map a ClamAV signature name to (severity, category)."""
    base = name.removesuffix(".UNOFFICIAL")
    if base.startswith("Heuristics.Limits.Exceeded"):
        return "info", "limits"
    if base.startswith("Heuristics."):
        return "medium", "heuristic"
    if base.startswith("PUA."):
        return "low", "pua"
    if base.startswith(("Sanesecurity.Junk", "Sanesecurity.Spam", "Sanesecurity.Phishing")):
        return "low", "spam"
    if "Eicar" in base or "EICAR" in base:
        return "info", "test"
    return "high", "malware"


def yara_severity(meta: dict[str, Any]) -> tuple[str, str]:
    category = str(meta.get("category", "")).lower()
    if category == "info":
        return "info", "informational"
    sev = str(meta.get("severity", "")).lower()
    if sev in SEVERITY_RANK:
        return sev, category or "malware"
    if sev in ("critical",):
        return "high", category or "malware"
    try:
        score = int(meta.get("score", -1))
    except (TypeError, ValueError):
        score = -1
    if score >= 80:
        return "high", category or "malware"
    if score >= 60:
        return "medium", category or "malware"
    if score >= 0:
        return "low", category or "suspicious"
    return "medium", category or "malware"


@dataclass
class ScanSummary:
    job: int
    state: str                     # finished | cancelled | failed
    started: float
    finished: float
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_skipped: int = 0
    errors: int = 0
    detections: int = 0
    inventory: int = 0                 # informational persistence/integrity entries
    engines: dict[str, Any] = field(default_factory=dict)
    checks: dict[str, Any] = field(default_factory=dict)      # per-volume persistence/integrity results
    error_samples: list[dict[str, str]] = field(default_factory=list)
    volumes: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
