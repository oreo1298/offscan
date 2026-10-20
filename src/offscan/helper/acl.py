"""POSIX access ACLs, written directly as the kernel's xattr (no libacl or setfacl needed).

Used to let exactly the invoking user (and nobody else) into the directory
that holds our mounts: the drives being scanned must not be readable by every
account on the computer.
"""

from __future__ import annotations

import errno
import os
import struct
from collections.abc import Iterable

XATTR = "system.posix_acl_access"
VERSION = 2
USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
UNDEFINED_ID = 0xFFFFFFFF


def encode(owner: int, users: dict[int, int], group: int = 0, other: int = 0) -> bytes:
    """ACL with permission bits for the owner, named users, the owning group and others."""
    entries = [(USER_OBJ, owner, UNDEFINED_ID)]
    entries += [(USER, perm, uid) for uid, perm in sorted(users.items())]
    entries.append((GROUP_OBJ, group, UNDEFINED_ID))
    if users:
        mask = group
        for perm in users.values():
            mask |= perm
        entries.append((MASK, mask, UNDEFINED_ID))
    entries.append((OTHER, other, UNDEFINED_ID))
    return struct.pack("<I", VERSION) + b"".join(struct.pack("<HHI", tag, perm, ident)
                                                for tag, perm, ident in entries)


def decode(data: bytes) -> list[tuple[int, int, int]]:
    if len(data) < 4 or struct.unpack("<I", data[:4])[0] != VERSION or (len(data) - 4) % 8:
        raise ValueError("not a POSIX ACL")
    return [struct.unpack("<HHI", data[i:i + 8]) for i in range(4, len(data), 8)]


def restrict_to(path: str, uids: Iterable[int], perm: int = 0o5) -> bool:
    """Owner rwx, the given users ``perm`` (default r-x), nobody else.

    Returns False when the filesystem has no ACL support; the caller then
    decides what to fall back to.
    """
    os.chmod(path, 0o700)                    # before the ACL: chmod would change its mask
    users = {uid: perm for uid in uids if uid != os.stat(path).st_uid}
    if not users:
        return True
    try:
        os.setxattr(path, XATTR, encode(0o7, users), follow_symlinks=False)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            return False
        raise
    return True
