"""Work out which block devices belong to the running system.

A device is "system" when it (or anything stacked on it) backs one of the
running system's essential mounts, active swap, the hibernation resume
device, or the live boot medium.  We never block-level-protect such a disk
(that could break the running system) and the UI warns loudly about it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import mountinfo

ESSENTIAL_MOUNTS = ("/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/var")
# GPT types of the EFI system partition and the extended boot loader partition.
BOOT_PARTITION_TYPES = ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "bc13c2ff-59e6-4262-a352-b275fd6f7172")
LIVE_MEDIUM_MOUNTS = ("/cdrom", "/run/live/medium", "/run/initramfs/live",
                      "/run/archiso/bootmnt", "/run/archiso/cowspace", "/lib/live/mount/medium",
                      "/run/media/liveuser", "/isodevice")


@dataclass
class SystemDevices:
    # kernel name -> human readable reason
    reasons: dict[str, str] = field(default_factory=dict)
    live_medium: set[str] = field(default_factory=set)

    def is_system(self, kname: str) -> bool:
        return kname in self.reasons

    def add(self, kname: str, reason: str) -> None:
        self.reasons.setdefault(kname, reason)


def kname_for_majmin(majmin: str, sys_block: str = "/sys/dev/block") -> str | None:
    try:
        target = os.readlink(os.path.join(sys_block, majmin))
    except OSError:
        return None
    return os.path.basename(target)


def kname_for_path(path: str) -> str | None:
    try:
        real = os.path.realpath(path)
        st = os.stat(real)
    except OSError:
        return None
    if not (st.st_mode & 0o060000 == 0o060000):  # S_ISBLK
        return None
    return kname_for_majmin(f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}")


def mount_kname(entry: mountinfo.MountEntry) -> str | None:
    """The block device behind a mount, or None.

    Device numbers are trusted. A ``/dev/...`` source string only is for
    root's own FUSE block mounts (ntfs-3g): any user can start a FUSE mount
    that calls itself ``/dev/sdb1``.
    """
    kname = kname_for_majmin(entry.majmin)
    if kname is None and entry.fstype == "fuseblk" and entry.source.startswith("/dev/") \
            and "user_id=0" in entry.super_options:
        kname = kname_for_path(entry.source)
    return kname


def _fstab_kname(mountpoint: str, fstab: str = "/etc/fstab") -> str | None:
    """Device of an fstab entry (for automount points that are not mounted yet)."""
    try:
        with open(fstab, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith("#") or fields[1] != mountpoint:
            continue
        spec = fields[0]
        for prefix, directory in (("UUID=", "by-uuid"), ("PARTUUID=", "by-partuuid"),
                                  ("LABEL=", "by-label"), ("PARTLABEL=", "by-partlabel")):
            if spec.startswith(prefix):
                spec = f"/dev/disk/{directory}/{spec[len(prefix):].strip(chr(34))}"
        return kname_for_path(spec) if spec.startswith("/dev/") else None
    return None


def lower_devices(kname: str, sys_class: str = "/sys/class/block") -> set[str]:
    """All devices below ``kname`` (dm slaves, partitions' disks) including itself."""
    seen: set[str] = set()
    todo = [kname]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        base = os.path.join(sys_class, name)
        try:
            todo.extend(os.listdir(os.path.join(base, "slaves")))
        except OSError:
            pass
        # A partition's parent disk is its parent directory in sysfs.
        try:
            real = os.path.realpath(base)
            if os.path.exists(os.path.join(real, "partition")):
                todo.append(os.path.basename(os.path.dirname(real)))
        except OSError:
            pass
        # Loop devices: the backing file's device.
        backing = os.path.join(base, "loop", "backing_file")
        try:
            with open(backing, encoding="utf-8", errors="surrogateescape") as fh:
                bfile = fh.read().strip()
            st = os.stat(bfile)
            parent = kname_for_majmin(f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}")
            if parent:
                todo.append(parent)
        except OSError:
            pass
    return seen


def _swap_devices() -> list[str]:
    out = []
    try:
        with open("/proc/swaps", encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if parts and parts[1] == "partition":
                    out.append(parts[0])
    except OSError:
        pass
    return out


def _resume_device() -> str | None:
    try:
        with open("/sys/power/resume", encoding="ascii") as fh:
            value = fh.read().strip()
    except OSError:
        return None
    if value and value != "0:0":
        return kname_for_majmin(value)
    return None


def detect(entries: list[mountinfo.MountEntry] | None = None) -> SystemDevices:
    entries = entries if entries is not None else mountinfo.read(1)
    result = SystemDevices()
    by_mountpoint = {e.mountpoint: e for e in entries}
    for mp in ESSENTIAL_MOUNTS:
        entry = by_mountpoint.get(mp)
        if entry is None:
            continue
        kname = mount_kname(entry)
        if kname is None and entry.fstype == "autofs":       # e.g. an ESP not mounted yet
            kname = _fstab_kname(mp)
        if kname:
            for low in lower_devices(kname):
                result.add(low, f"backs {mp} of the running system")
    for mp in LIVE_MEDIUM_MOUNTS:
        entry = by_mountpoint.get(mp)
        if entry is None:
            continue
        kname = kname_for_majmin(entry.majmin)
        if kname:
            for low in lower_devices(kname):
                result.add(low, "live boot medium")
                result.live_medium.add(low)
    for swap in _swap_devices():
        kname = kname_for_path(swap)
        if kname:
            for low in lower_devices(kname):
                result.add(low, "active swap of the running system")
    resume = _resume_device()
    if resume:
        for low in lower_devices(resume):
            result.add(low, "hibernation resume device of the running system")
    return result
