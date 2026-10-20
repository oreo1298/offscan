"""Block-layer read-only protection.

``mount -o ro`` alone is not read-only at the device level (ext4 replays
the journal and cleans orphans, XFS and btrfs replay logs).  Only a
read-only block device stops all of it, so before anything touches a
target we set the kernel's read-only flag (BLKROSET) on the partition and,
when nothing else uses it, on the whole disk, and then access the data
only through read-only loop devices.  The flag is sticky, so we remember
the original state and restore it on teardown.
"""

from __future__ import annotations

import fcntl
import os
import struct

from .. import tools

BLKROSET = 0x125D
BLKROGET = 0x125E


def _open(path: str) -> int:
    # O_RDONLY never writes; O_NONBLOCK avoids waiting for removable media.
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)


def get_ro(path: str) -> bool:
    fd = _open(path)
    try:
        buf = fcntl.ioctl(fd, BLKROGET, struct.pack("i", 0))
        return struct.unpack("i", buf)[0] != 0
    finally:
        os.close(fd)


def set_ro(path: str, readonly: bool = True) -> None:
    fd = _open(path)
    try:
        fcntl.ioctl(fd, BLKROSET, struct.pack("i", 1 if readonly else 0))
    finally:
        os.close(fd)
    # Clearing cannot be verified on a partition whose disk is read-only
    # (BLKROGET reports either flag), so only verify when setting.
    if readonly and not get_ro(path):
        raise OSError(f"could not set the read-only flag of {path}")


def attach_loop_readonly(source: str) -> str:
    """Attach ``source`` (a block device or image file) to a new read-only loop device."""
    losetup = tools.require("losetup")
    proc = tools.run([losetup, "--find", "--show", "--read-only", source], timeout=60)
    loop = proc.stdout.strip().splitlines()[-1].strip()
    if not loop.startswith("/dev/loop"):
        raise tools.ToolError(f"unexpected losetup output: {proc.stdout!r}")
    if not get_ro(loop):
        detach_loop(loop)
        raise OSError(f"{loop} is not read-only; refusing to continue")
    return loop


def detach_loop(loop: str) -> None:
    losetup = tools.require("losetup")
    tools.run([losetup, "--detach", loop], timeout=60, check=False)


def loop_backing(loop: str) -> str | None:
    name = os.path.basename(loop)
    try:
        with open(f"/sys/block/{name}/loop/backing_file", encoding="utf-8",
                  errors="surrogateescape") as fh:
            return fh.read().strip()
    except OSError:
        return None


def size_bytes(path: str) -> int:
    fd = _open(path)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def read_bytes(path: str, offset: int, length: int) -> bytes:
    fd = _open(path)
    try:
        return os.pread(fd, length, offset)
    finally:
        os.close(fd)
