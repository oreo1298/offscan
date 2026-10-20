"""Helpers for hostile filenames.

Paths from target drives are arbitrary bytes.  Internally we keep them as
``bytes`` or as ``str`` decoded with surrogateescape (``os.fsdecode``), so
they round-trip exactly.  For display, everything that is not a printable
character is escaped so a filename can never inject newlines, terminal
escape sequences or bidi overrides into logs, tables or reports.
"""

from __future__ import annotations

import os
import unicodedata

# Characters that are printable per str.isprintable() but can still be used
# to disguise text (bidirectional overrides and isolates, zero-width chars).
_DISGUISE = {
    "​", "‌", "‍", "‎", "‏", " ", " ",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "﻿",
}


def to_wire(path: bytes | str) -> str:
    """Convert a filesystem path to the protocol's string form."""
    return os.fsdecode(path) if isinstance(path, bytes) else path


def from_wire(path: str) -> bytes:
    return os.fsencode(path)


def display(path: bytes | str, max_len: int | None = None) -> str:
    """Return a safe, single-line, human-readable rendering of ``path``."""
    text = os.fsdecode(path) if isinstance(path, bytes) else path
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 0xDC80 <= code <= 0xDCFF:          # undecodable byte (surrogateescape)
            out.append(f"\\x{code - 0xDC00:02x}")
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch in _DISGUISE or (not ch.isprintable() and ch != " "):
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        elif 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    result = "".join(out)
    if max_len is not None and len(result) > max_len:
        keep = max(max_len - 1, 1)
        head = keep // 2
        result = result[:head] + "…" + result[len(result) - (keep - head):]
    return result


def is_suspicious_name(name: bytes | str) -> bool:
    """True if a filename contains characters typically used for disguise."""
    text = os.fsdecode(name) if isinstance(name, bytes) else name
    for ch in text:
        if ch in _DISGUISE or 0xDC80 <= ord(ch) <= 0xDCFF:
            return True
        if unicodedata.category(ch) in ("Cc", "Cf"):
            return True
    return False
