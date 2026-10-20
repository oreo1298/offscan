"""Detect the operating system installed on a mounted (read-only) volume."""

from __future__ import annotations

import os
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any

from ..safefs import RootFS


@dataclass
class OSInfo:
    family: str                     # windows | linux | efi | boot | unknown
    name: str
    version: str | None = None
    build: str | None = None
    edition: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines()[:200]:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key = key.strip()
        if not key.isidentifier():
            continue
        try:
            parts = shlex.split(raw, posix=True)
        except ValueError:
            continue
        values[key] = " ".join(parts)[:200]
    return values


def detect_linux(root: RootFS) -> OSInfo | None:
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            data = root.read_file(candidate, max_size=64 * 1024)
        except OSError:
            continue
        info = parse_os_release(data.decode("utf-8", "replace"))
        name = info.get("PRETTY_NAME") or info.get("NAME") or "Linux"
        return OSInfo("linux", name, info.get("VERSION_ID"), None, info.get("VARIANT"),
                      {"id": info.get("ID"), "id_like": info.get("ID_LIKE")})
    if root.exists("/etc/fstab") and (root.exists("/usr/bin") or root.exists("/bin")):
        return OSInfo("linux", "Linux (unknown distribution)")
    if root.exists("/vmlinuz") or any(n.startswith(b"vmlinuz") for n in _safe_list(root, "/")):
        return OSInfo("boot", "Linux boot partition")
    return None


def _safe_list(root: RootFS, path: str) -> list[bytes]:
    try:
        return root.listdir(path)
    except OSError:
        return []


def windows_hive(root: RootFS, hive: str = "SOFTWARE") -> bytes | None:
    return root.find_ci(f"Windows/System32/config/{hive}")


def detect_efi(root: RootFS) -> OSInfo | None:
    efi = root.find_ci("EFI")
    if efi is None:
        return None
    vendors = [os.fsdecode(v) for v in _safe_list(root, efi) if v.upper() != b"BOOT"]
    names = []
    for vendor in vendors:
        names.append("Windows Boot Manager" if vendor.lower() == "microsoft" else vendor)
    return OSInfo("efi", "EFI system partition", details={"loaders": names})


def windows_version_from_values(values: dict[str, Any]) -> OSInfo:
    product = str(values.get("ProductName") or "Windows")
    build_text = str(values.get("CurrentBuild") or values.get("CurrentBuildNumber") or "")
    try:
        build = int(build_text)
    except ValueError:
        build = 0
    # ProductName still says "Windows 10" on Windows 11.
    if build >= 22000 and "Windows 10" in product:
        product = product.replace("Windows 10", "Windows 11")
    version = values.get("DisplayVersion") or values.get("ReleaseId") or values.get("CSDVersion")
    ubr = values.get("UBR")
    build_full = f"{build_text}.{ubr}" if build_text and ubr not in (None, "") else build_text or None
    return OSInfo("windows", product, str(version) if version else None, build_full,
                  str(values.get("EditionID")) if values.get("EditionID") else None,
                  {"installation_type": values.get("InstallationType")})


VERSION_VALUES = ("ProductName", "CurrentBuild", "CurrentBuildNumber", "DisplayVersion",
                  "ReleaseId", "UBR", "EditionID", "InstallationType", "CSDVersion")


def task_windows_version(args: dict[str, Any], fds: list[int]) -> dict[str, Any]:
    """Sandbox task: read version values from a SOFTWARE hive passed as fd 0 of ``fds``."""
    from regipy.registry import RegistryHive

    from ..persistence.filepack import fd_path
    path, copy = fd_path(fds[0])
    try:
        hive = RegistryHive(path)
    finally:
        os.close(copy)
    key = hive.get_key("\\Microsoft\\Windows NT\\CurrentVersion")
    values: dict[str, Any] = {}
    for value in key.iter_values():
        if value.name in VERSION_VALUES:
            data = value.value
            values[value.name] = data if isinstance(data, (str, int)) else str(data)
    return values
