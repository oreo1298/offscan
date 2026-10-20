"""Who to run unprivileged work as, and process hardening primitives."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import pwd
import resource
from dataclasses import dataclass

NOBODY_NAMES = ("nobody", "nfsnobody")
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4
CLONE_NEWNET = 0x40000000

_libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)


@dataclass(frozen=True)
class Identity:
    uid: int
    gid: int
    name: str
    home: str


def _from_uid(uid: int) -> Identity | None:
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return None
    return Identity(pw.pw_uid, pw.pw_gid, pw.pw_name, pw.pw_dir)


def invoking_user() -> Identity | None:
    """The real (non-root) user on whose behalf the root helper runs."""
    for var in ("PKEXEC_UID", "SUDO_UID", "DOAS_UID"):
        value = os.environ.get(var, "")
        if value.isdigit() and int(value) != 0:
            ident = _from_uid(int(value))
            if ident:
                return ident
    if os.getuid() != 0:
        return _from_uid(os.getuid())
    return None


def nobody() -> Identity:
    for name in NOBODY_NAMES:
        try:
            pw = pwd.getpwnam(name)
            return Identity(pw.pw_uid, pw.pw_gid, pw.pw_name, "/")
        except KeyError:
            continue
    return Identity(65534, 65534, "nobody", "/")


def worker_identity() -> Identity | None:
    """Identity for sandboxed children; ``None`` when we cannot change uid."""
    if os.geteuid() != 0:
        return None
    return invoking_user() or nobody()


def set_no_new_privs() -> bool:
    return _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0


def set_not_dumpable() -> bool:
    return _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0


def disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def unshare_network() -> bool:
    """Move this process into a new, empty network namespace (needs root)."""
    unshare = getattr(os, "unshare", None)
    try:
        if unshare is not None:
            unshare(CLONE_NEWNET)
            return True
        if _libc.unshare(CLONE_NEWNET) == 0:
            return True
    except OSError:
        return False
    return False


def has_network_namespace_isolation() -> bool:
    """True if this process sees no network interface except loopback.

    ``/proc/self/net`` reflects the caller's own network namespace (unlike
    ``/sys/class/net``, which shows the namespace sysfs was mounted in).
    """
    try:
        with open("/proc/self/net/dev", encoding="ascii", errors="replace") as fh:
            lines = fh.read().splitlines()[2:]
    except OSError:
        return False
    names = [line.split(":", 1)[0].strip() for line in lines if ":" in line]
    return all(name == "lo" for name in names)


def set_limits(memory: int | None = None, cpu_seconds: int | None = None,
               file_size: int | None = None, open_files: int | None = None) -> None:
    pairs = (
        (resource.RLIMIT_AS, memory),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, file_size),
        (resource.RLIMIT_NOFILE, open_files),
    )
    for which, value in pairs:
        if value is None:
            continue
        try:
            _soft, hard = resource.getrlimit(which)
            new_hard = value if hard == resource.RLIM_INFINITY or value < hard else hard
            resource.setrlimit(which, (min(value, new_hard), new_hard))
        except (ValueError, OSError):
            pass
    disable_core_dumps()
