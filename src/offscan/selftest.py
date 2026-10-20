"""Report what this installation can do (engines, drivers, privileges).

Used by ``offscan selftest``, by the GUI's About/Settings page and by the
package install tests.
"""

from __future__ import annotations

import importlib
import os
import platform
import sys
from typing import Any

from . import appinfo, tools


def _module_version(name: str, attr: str = "__version__") -> str | None:
    try:
        module = importlib.import_module(name)
    except Exception:
        return None
    value = getattr(module, attr, None)
    return str(value) if value is not None else "available"


def _qt() -> dict[str, Any]:
    try:
        from .gui import qt
    except ImportError as exc:
        return {"available": False, "error": str(exc)}
    return {"available": True, "binding": qt.BINDING, "binding_version": qt.BINDING_VERSION,
            "qt_version": ".".join(map(str, qt.QT_VERSION)), "qtdbus": qt.QtDBus is not None}


def kernel_filesystems() -> set[str]:
    found: set[str] = set()
    try:
        with open("/proc/filesystems", encoding="ascii", errors="replace") as fh:
            for line in fh:
                found.add(line.split()[-1])
    except OSError:
        pass
    release = platform.release()
    for fs in ("ntfs", "ntfs3", "btrfs", "xfs", "exfat", "vfat", "f2fs"):
        if fs in found:
            continue
        for ext in ("ko", "ko.xz", "ko.zst", "ko.gz"):
            if os.path.exists(f"/lib/modules/{release}/kernel/fs/{fs}/{fs}.{ext}"):
                found.add(f"{fs} (module)")
                break
    return found


def collect() -> dict[str, Any]:
    tool_names = [
        "clamd", "clamscan", "clamdscan", "freshclam", "sigtool", "yara",
        "cryptsetup", "dislocker", "lvm", "mdadm", "losetup", "blockdev", "mount",
        "ntfs-3g", "gpgv", "rpm", "dpkg", "pacman", "chkrootkit", "hayabusa",
        "chainsaw", "pkexec", "sudo",
    ]
    return {
        "app": {"name": appinfo.NAME, "version": appinfo.VERSION, "id": appinfo.APP_ID},
        "python": {"version": platform.python_version(), "executable": sys.executable},
        "qt": _qt(),
        "modules": {
            "yara_x": _module_version("yara_x"),
            "yara": _module_version("yara"),
            "regipy": _module_version("regipy"),
            "cryptography": _module_version("cryptography"),
            "pefile": _module_version("pefile"),
        },
        "tools": {name: tools.find(name) for name in tool_names},
        "kernel": {"release": platform.release(),
                   "filesystems": sorted(kernel_filesystems())},
        "privileges": {"root": tools.is_root()},
    }


def format_text(report: dict[str, Any]) -> str:
    lines = [f"{appinfo.DISPLAY_NAME} {report['app']['version']} ({report['app']['id']})",
             f"Python {report['python']['version']} ({report['python']['executable']})"]
    qt = report["qt"]
    if qt.get("available"):
        lines.append(f"Qt {qt['qt_version']} via {qt['binding']} {qt['binding_version']}")
    else:
        lines.append(f"Qt: not available ({qt.get('error')})")
    lines.append("Python modules:")
    for name, ver in report["modules"].items():
        lines.append(f"  {name:13} {ver or 'missing'}")
    lines.append("Programs:")
    for name, path in report["tools"].items():
        lines.append(f"  {name:13} {path or 'missing'}")
    lines.append(f"Kernel {report['kernel']['release']}: "
                 + ", ".join(fs for fs in report["kernel"]["filesystems"]
                             if fs.split()[0] in {"ext4", "xfs", "btrfs", "ntfs", "ntfs3",
                                                  "vfat", "exfat", "fuse", "f2fs"}))
    lines.append(f"Running as root: {report['privileges']['root']}")
    return "\n".join(lines)
