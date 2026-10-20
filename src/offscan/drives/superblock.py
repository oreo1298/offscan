"""Read-only peeks at on-disk superblocks (never writes; opens O_RDONLY).

Used to tell the user, before mounting, that a filesystem was not cleanly
unmounted and that the read-only view will not include the last journal
transactions.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass


@dataclass
class FsState:
    fstype: str
    clean: bool | None            # None = unknown
    needs_recovery: bool = False
    orphans: bool = False
    detail: str = ""


def _read(path: str, offset: int, length: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY)
    try:
        return os.pread(fd, length, offset)
    finally:
        os.close(fd)


EXT4_MAGIC = 0xEF53
EXT4_INCOMPAT_RECOVER = 0x0004
EXT4_STATE_VALID = 0x0001
EXT4_STATE_ERROR = 0x0002


def ext4_state(data: bytes) -> FsState | None:
    """``data`` is the 1024-byte superblock found at byte 1024 of the volume."""
    if len(data) < 0x100:
        return None
    (magic,) = struct.unpack_from("<H", data, 0x38)
    if magic != EXT4_MAGIC:
        return None
    (state,) = struct.unpack_from("<H", data, 0x3A)
    (incompat,) = struct.unpack_from("<I", data, 0x60)
    (last_orphan,) = struct.unpack_from("<I", data, 0xE8)
    needs_recovery = bool(incompat & EXT4_INCOMPAT_RECOVER)
    orphans = last_orphan != 0
    clean = bool(state & EXT4_STATE_VALID) and not (state & EXT4_STATE_ERROR) and not needs_recovery
    details = []
    if needs_recovery:
        details.append("journal has unreplayed transactions")
    if orphans:
        details.append("orphan inodes pending cleanup")
    if state & EXT4_STATE_ERROR:
        details.append("filesystem has recorded errors")
    return FsState("ext4", clean, needs_recovery, orphans, "; ".join(details))


BTRFS_MAGIC = b"_BHRfS_M"
BTRFS_SUPER_OFFSET = 0x10000


def btrfs_state(data: bytes) -> FsState | None:
    """``data`` is the superblock at 64 KiB."""
    if len(data) < 0x70 or data[0x40:0x48] != BTRFS_MAGIC:
        return None
    (log_root,) = struct.unpack_from("<Q", data, 0x60)
    needs = log_root != 0
    return FsState("btrfs", not needs, needs, False,
                   "tree log has unreplayed entries" if needs else "")


XFS_MAGIC = b"XFSB"


def xfs_state(data: bytes) -> FsState | None:
    if data[:4] != XFS_MAGIC:
        return None
    # The log's cleanliness is not in the superblock; we always mount with
    # norecovery, so report "unknown" rather than guessing.
    return FsState("xfs", None, False, False, "")


def probe(path: str, fstype: str | None) -> FsState | None:
    try:
        if fstype in ("ext2", "ext3", "ext4"):
            return ext4_state(_read(path, 1024, 1024))
        if fstype == "btrfs":
            return btrfs_state(_read(path, BTRFS_SUPER_OFFSET, 4096))
        if fstype == "xfs":
            return xfs_state(_read(path, 0, 512))
    except OSError:
        return None
    return None


BITLOCKER_SIGNATURES = (b"-FVE-FS-", b"MSWIN4.1")


def looks_like_bitlocker(boot_sector: bytes) -> bool:
    return len(boot_sector) >= 11 and boot_sector[3:11] in BITLOCKER_SIGNATURES and \
        boot_sector[:3] in (b"\xeb\x52\x90", b"\xeb\x58\x90")
