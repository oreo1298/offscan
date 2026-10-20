"""Detect Windows hibernation and Fast Startup on a mounted NTFS volume."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..safefs import RootFS

# hiberfil.sys header magic (libyal libhibr documentation).
RESUMABLE = {b"hibr": "hibernated (Windows XP style image)",
             b"HIBR": "hibernated or shut down with Fast Startup"}
INVALIDATED = {b"wake": "image already resumed", b"WAKE": "image already resumed",
               b"RSTR": "resume in progress or failed"}


@dataclass
class HibernationState:
    hibernated: bool
    reason: str
    fast_startup_enabled: bool | None = None

    def explain(self) -> str:
        if not self.hibernated:
            return "Windows was shut down completely."
        text = ("Windows did not shut down completely (it is hibernated, or Fast Startup "
                "saved the system state). The drive is still safe to scan read-only, but the "
                "view may miss changes Windows has not written to disk yet. For a complete "
                "view, start Windows and choose Restart, or hold Shift while clicking Shut "
                "down, or run 'shutdown /s /t 0'. To avoid this in future, turn off Fast "
                "Startup in Control Panel > Power Options.")
        if self.fast_startup_enabled:
            text += " Fast Startup is enabled on this installation."
        return text


def classify_header(header: bytes, size: int) -> HibernationState:
    magic = header[:4]
    if size == 0 or not header:
        return HibernationState(False, "no hibernation file content")
    if magic in RESUMABLE:
        return HibernationState(True, RESUMABLE[magic])
    if magic in INVALIDATED:
        return HibernationState(False, INVALIDATED[magic])
    if header.count(0) == len(header):
        return HibernationState(False, "hibernation file is empty")
    # Drivers treat any non-zero header as hibernated; so do we.
    return HibernationState(True, "unrecognised hibernation header")


def detect(root: RootFS) -> HibernationState | None:
    """Return None when the volume has no hiberfil.sys (not a Windows system volume)."""
    path = root.find_ci("hiberfil.sys")
    if path is None:
        return None
    try:
        st = root.lstat(path)
        fd = root.open_regular(path, follow_last=False)
    except OSError as exc:
        return HibernationState(False, f"cannot read hiberfil.sys: {exc.strerror}")
    try:
        header = os.pread(fd, 4096, 0)
    finally:
        os.close(fd)
    return classify_header(header, st.st_size)
