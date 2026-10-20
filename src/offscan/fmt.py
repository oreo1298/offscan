"""Small formatting helpers shared by the CLI, GUI and reports."""

from __future__ import annotations

import datetime as _dt


def size(num: int | float | None) -> str:
    if num is None:
        return "?"
    value = float(num)
    for unit in ("B", "kB", "MB", "GB", "TB", "PB"):
        if abs(value) < 1000 or unit == "PB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} PB"


def duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "?"
    seconds = round(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def age(timestamp: float | None, now: float | None = None) -> str:
    if not timestamp:
        return "never"
    now = now if now is not None else _dt.datetime.now(_dt.UTC).timestamp()
    delta = max(0.0, now - timestamp)
    if delta < 90:
        return "just now"
    if delta < 3600 * 1.5:
        return f"{int(delta // 60)} minutes ago"
    if delta < 86400 * 1.5:
        return f"{int(delta // 3600)} hours ago"
    return f"{int(delta // 86400)} days ago"


def iso(timestamp: float) -> str:
    return _dt.datetime.fromtimestamp(timestamp, _dt.UTC).isoformat(timespec="seconds")


def volume_summary(vol: dict) -> str:
    """One-line description of a volume for lists."""
    parts = []
    osinfo = vol.get("os")
    if osinfo:
        name = osinfo.get("name") or osinfo.get("family")
        if osinfo.get("version"):
            name += f" {osinfo['version']}"
        if osinfo.get("build"):
            name += f" (build {osinfo['build']})"
        if osinfo.get("family") == "efi" and osinfo.get("details", {}).get("loaders"):
            name += ": " + ", ".join(osinfo["details"]["loaders"])
        parts.append(name)
    enc = vol.get("encryption")
    if enc:
        kind = "BitLocker" if enc["kind"] == "bitlocker" else f"LUKS{enc.get('version') or ''}"
        parts.append(f"{kind}, {'unlocked' if enc.get('unlocked') else 'locked'}")
    if vol.get("role") == "lvm_pv":
        parts.append("LVM physical volume")
    if vol.get("mountpoint"):
        parts.append(f"mounted read-only at {vol['mountpoint']}")
    return "; ".join(parts)
