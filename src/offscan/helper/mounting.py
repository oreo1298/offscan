"""Mount filesystems read-only with journal/log replay disabled.

Order of protection (see blockdev.py): the source is always a read-only
loop or read-only dm device, and on top of that every mount gets
``ro,nosuid,nodev,noexec,nosymfollow`` plus the filesystem's own
"do not replay" option.  After mounting we verify in mountinfo that the
mount really is read-only and unmount immediately if it is not.
"""

from __future__ import annotations

import os
import platform
import re
import time
from dataclasses import dataclass, field

from .. import tools
from ..drives import mountinfo

BASE_OPTIONS = ("ro", "nosuid", "nodev", "noexec")

# fstype -> list of alternative option sets, tried in order.
FS_OPTIONS: dict[str, list[list[str]]] = {
    "ext2": [["noload"]],
    "ext3": [["noload"]],
    "ext4": [["noload"]],
    "xfs": [["norecovery", "nouuid"], ["norecovery"]],
    "btrfs": [["rescue=nologreplay", "subvolid=5"], ["nologreplay", "subvolid=5"],
              ["rescue=nologreplay"]],
    "f2fs": [["norecovery"]],
    "vfat": [["utf8", "shortname=mixed"], []],
    "exfat": [[]],
    "iso9660": [[]],
    "udf": [[]],
    "squashfs": [[]],
    "erofs": [[]],
    "hfsplus": [[]],
    "reiserfs": [["nolog"]],
    "jfs": [[]],
}
NTFS_TYPES = ("ntfs", "ntfs3")
SUPPORTED_FSTYPES = tuple(FS_OPTIONS) + NTFS_TYPES


class MountError(Exception):
    def __init__(self, message: str, attempts: list[str] | None = None):
        super().__init__(message)
        self.attempts = attempts or []


@dataclass
class MountResult:
    target: str
    fstype: str
    driver: str
    options: list[str]
    fuse: bool = False
    messages: list[str] = field(default_factory=list)


def kernel_version() -> tuple[int, int]:
    match = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def kernel_filesystems() -> set[str]:
    try:
        with open("/proc/filesystems", encoding="ascii", errors="replace") as fh:
            return {line.split()[-1] for line in fh if line.strip()}
    except OSError:
        return set()


def _modprobe(module: str) -> None:
    modprobe = tools.find("modprobe")
    if modprobe:
        tools.run([modprobe, "-q", module], timeout=30, check=False)


def supports_nosymfollow() -> bool:
    return kernel_version() >= (5, 10)


def ntfs_drivers() -> list[str]:
    """Candidate NTFS drivers, best first: kernel ``ntfs`` (7.1+), ``ntfs3``, ntfs-3g."""
    available = kernel_filesystems()
    if "ntfs3" not in available:
        _modprobe("ntfs3")
    if kernel_version() >= (7, 1) and "ntfs" not in available:
        _modprobe("ntfs")
    available = kernel_filesystems()
    out = []
    # Before 7.1 "ntfs" is either the long-removed legacy driver or an alias
    # of ntfs3, so only trust it as the new driver from 7.1 on.
    if kernel_version() >= (7, 1) and "ntfs" in available:
        out.append("ntfs")
    if "ntfs3" in available:
        out.append("ntfs3")
    if tools.find("ntfs-3g"):
        out.append("ntfs-3g")
    return out


def options_for(fstype: str, extra: list[str]) -> str:
    opts = list(BASE_OPTIONS)
    if supports_nosymfollow():
        opts.append("nosymfollow")
    opts += extra
    return ",".join(opts)


def _mount_kernel(source: str, target: str, fstype: str, opts: str) -> tools.subprocess.CompletedProcess:
    mount = tools.require("mount")
    # -i: never run /sbin/mount.<type> helpers (on Debian mount.ntfs is ntfs-3g).
    return tools.run([mount, "-i", "-t", fstype, "-o", opts, source, target], timeout=120,
                     check=False)


def _mount_ntfs3g(source: str, target: str) -> tools.subprocess.CompletedProcess:
    ntfs3g = tools.require("ntfs-3g")
    # Never "recover" or "remove_hiberfile": both write to the volume.
    opts = "ro,nosuid,nodev,noexec,allow_other,norecover,streams_interface=none"
    return tools.run([ntfs3g, "-o", opts, source, target], timeout=120, check=False)


def _harden_bind(target: str) -> None:
    """Re-apply per-mount flags (needed for FUSE mounts, harmless otherwise)."""
    mount = tools.require("mount")
    flags = list(BASE_OPTIONS)
    if supports_nosymfollow():
        flags.append("nosymfollow")
    tools.run([mount, "-o", "remount,bind," + ",".join(flags), target], timeout=60, check=False)


def verify_readonly(target: str) -> mountinfo.MountEntry:
    real = os.path.realpath(target)
    entries = [e for e in mountinfo.read("self") if e.mountpoint == real]
    if not entries:
        raise MountError(f"{target} is not mounted")
    entry = entries[-1]
    if not entry.readonly:
        raise MountError(f"{target} was mounted read-write; refusing to use it")
    for flag in ("nosuid", "nodev", "noexec"):
        if flag not in entry.options:
            raise MountError(f"{target} lacks the {flag} flag")
    return entry


WRITABLE_FSTYPES = ("ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "f2fs", *NTFS_TYPES)
WRITE_OPTIONS = ("rw", "nosuid", "nodev", "noexec")
WRITE_EXTRA = {"btrfs": ["subvolid=5"], "xfs": ["nouuid"]}


def mount_writable(source: str, target: str, fstype: str) -> MountResult:
    """Read-write mount for one confirmed quarantine/delete/restore.

    Still nosuid,nodev,noexec(,nosymfollow).  Journals are replayed as on a
    normal boot (the caller has told the user).  Never removes a Windows
    hibernation file: ntfs-3g refuses such volumes and so do we, earlier.
    """
    if fstype not in WRITABLE_FSTYPES:
        raise MountError(f"changing files on {fstype or 'this'} filesystem is not supported")
    os.makedirs(target, mode=0o700, exist_ok=True)
    flags = [*WRITE_OPTIONS, *(["nosymfollow"] if supports_nosymfollow() else [])]
    attempts: list[str] = []
    candidates = ntfs_drivers() if fstype in NTFS_TYPES else [fstype]
    for driver in candidates:
        if driver == "ntfs-3g":
            ntfs3g = tools.require("ntfs-3g")
            opts = "rw,nosuid,nodev,noexec,norecover,streams_interface=none"
            proc = tools.run([ntfs3g, "-o", opts, source, target], timeout=120, check=False)
        else:
            opts = ",".join(flags + WRITE_EXTRA.get(driver, []))
            proc = _mount_kernel(source, target, driver, opts)
        if proc.returncode == 0:
            if driver == "ntfs-3g":
                _harden_bind_rw(target)
            real = os.path.realpath(target)
            entry = next((e for e in mountinfo.read("self") if e.mountpoint == real), None)
            if entry is None or entry.readonly:
                umount(target)
                raise MountError("the filesystem refused to mount writable (it may need checking first)")
            return MountResult(target, "ntfs" if fstype in NTFS_TYPES else fstype, driver, opts.split(","),
                               driver == "ntfs-3g", [ln for ln in proc.stderr.splitlines() if ln.strip()])
        attempts.append(f"{driver}: {(proc.stderr or proc.stdout).strip()}")
    raise MountError("could not mount the volume writable", attempts)


def _harden_bind_rw(target: str) -> None:
    mount = tools.require("mount")
    flags = ["nosuid", "nodev", "noexec"] + (["nosymfollow"] if supports_nosymfollow() else [])
    tools.run([mount, "-o", "remount,bind," + ",".join(flags), target], timeout=60, check=False)


def mount(source: str, target: str, fstype: str) -> MountResult:
    os.makedirs(target, mode=0o755, exist_ok=True)
    attempts: list[str] = []
    if fstype in NTFS_TYPES:
        for driver in ntfs_drivers():
            if driver == "ntfs-3g":
                proc = _mount_ntfs3g(source, target)
                opts = "ntfs-3g ro"
            else:
                opts = options_for(driver, [])
                proc = _mount_kernel(source, target, driver, opts)
            if proc.returncode == 0:
                return _finish(source, target, "ntfs", driver, opts, driver == "ntfs-3g",
                               proc.stderr)
            attempts.append(f"{driver}: {(proc.stderr or proc.stdout).strip()}")
        raise MountError("no NTFS driver could mount the volume", attempts)
    variants = FS_OPTIONS.get(fstype)
    if variants is None:
        raise MountError(f"filesystem type {fstype!r} is not supported")
    for extra in variants:
        opts = options_for(fstype, extra)
        proc = _mount_kernel(source, target, fstype, opts)
        if proc.returncode == 0:
            return _finish(source, target, fstype, fstype, opts, False, proc.stderr)
        attempts.append(f"{opts}: {(proc.stderr or proc.stdout).strip()}")
    raise MountError(f"could not mount {fstype} read-only", attempts)


def _finish(source: str, target: str, fstype: str, driver: str, opts: str, fuse: bool,
            stderr: str) -> MountResult:
    if fuse:
        _harden_bind(target)
    try:
        verify_readonly(target)
    except MountError:
        umount(target)
        raise
    messages = [line for line in stderr.splitlines() if line.strip()]
    return MountResult(target, fstype, driver, opts.split(","), fuse, messages)


def bind_readonly(existing: str, target: str) -> MountResult:
    """Read-only view of a filesystem that is already mounted elsewhere."""
    mount_bin = tools.require("mount")
    os.makedirs(target, mode=0o755, exist_ok=True)
    tools.run([mount_bin, "--bind", existing, target], timeout=60)
    flags = list(BASE_OPTIONS)
    if supports_nosymfollow():
        flags.append("nosymfollow")
    proc = tools.run([mount_bin, "-o", "remount,bind," + ",".join(flags), target], timeout=60,
                     check=False)
    if proc.returncode != 0:
        umount(target)
        raise MountError(f"could not make the view of {existing} read-only: {proc.stderr.strip()}")
    try:
        verify_readonly(target)
    except MountError:
        umount(target)
        raise
    return MountResult(target, "bind", "bind", flags)


def umount(target: str, attempts: int = 6) -> None:
    umount_bin = tools.require("umount")
    last = ""
    for i in range(attempts):
        proc = tools.run([umount_bin, target], timeout=120, check=False)
        if proc.returncode == 0 or not is_mounted(target):
            try:
                os.rmdir(target)
            except OSError:
                pass
            return
        last = proc.stderr.strip()
        time.sleep(0.3 * (i + 1))
    raise MountError(f"could not unmount {target}: {last}")


def is_mounted(target: str) -> bool:
    real = os.path.realpath(target)
    return any(e.mountpoint == real for e in mountinfo.read("self"))
