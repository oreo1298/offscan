"""Parse ``/proc/<pid>/mountinfo``."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MountEntry:
    mount_id: int
    parent_id: int
    majmin: str
    root: str
    mountpoint: str
    options: tuple[str, ...]
    fstype: str
    source: str
    super_options: tuple[str, ...]

    @property
    def readonly(self) -> bool:
        return "ro" in self.options


_OCTAL = re.compile(r"\\([0-7]{3})")


def _unescape(field: str) -> str:
    # mountinfo escapes space, tab, newline and backslash as \ooo octal.
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), field)


def parse(text: str) -> list[MountEntry]:
    entries = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or "-" not in parts:
            continue
        sep = parts.index("-", 6)
        try:
            entries.append(MountEntry(
                mount_id=int(parts[0]), parent_id=int(parts[1]), majmin=parts[2],
                root=_unescape(parts[3]), mountpoint=_unescape(parts[4]),
                options=tuple(parts[5].split(",")), fstype=parts[sep + 1],
                source=_unescape(parts[sep + 2]) if len(parts) > sep + 2 else "",
                super_options=tuple(parts[sep + 3].split(",")) if len(parts) > sep + 3 else (),
            ))
        except (ValueError, IndexError):
            continue
    return entries


def read(pid: int | str = 1) -> list[MountEntry]:
    for candidate in (f"/proc/{pid}/mountinfo", "/proc/self/mountinfo"):
        try:
            with open(candidate, encoding="utf-8", errors="surrogateescape") as fh:
                return parse(fh.read())
        except OSError:
            continue
    return []
