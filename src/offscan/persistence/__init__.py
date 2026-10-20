"""Offline persistence and integrity checks for Windows and Linux targets.

Parsing of target data (registry hives, task XML, cron/systemd files,
package databases) always happens in the unprivileged sandbox; the helper
only collects and opens the files.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    check: str                    # e.g. windows.run_key, linux.cron
    title: str
    location: str                 # registry key / file (and line)
    value: str = ""               # command line, key content, ...
    severity: str = "info"
    reasons: list[str] = field(default_factory=list)
    file: str | None = None       # file holding the entry (volume-relative posix path)
    target: str | None = None     # program it starts (volume-relative posix path), if known
    user: str | None = None
    mitre: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def raise_severity(current: str, new: str) -> str:
    return new if SEVERITY_ORDER.get(new, 0) > SEVERITY_ORDER.get(current, 0) else current
