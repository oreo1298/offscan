"""What a quick scan looks at, and which directories it skips.

Quick scan = executables, scripts, macro documents and archives (by
extension or magic bytes), plus *every* file in high-risk locations
(downloads, temp folders, AppData, startup folders, /tmp ...).  Large
read-only system stores (WinSxS, documentation) are pruned in quick mode.
"""

from __future__ import annotations

EXECUTABLE_EXT = frozenset("""
exe dll sys scr com pif cpl ocx drv efi mui ax acm tsp msc msi msp msu msix appx cab
ps1 psm1 psd1 ps1xml bat cmd vbs vbe js jse wsf wsh wsc hta lnk url scf inf reg chm
jar class apk dex so ko elf bin run appimage sh bash zsh ksh csh py pyc pl pm rb php
phtml php5 phar asp aspx jsp cgi lua tcl awk docm dotm xlsm xltm xlam pptm potm ppam
doc dot xls xlt ppt rtf pdf one hwp iso img vhd vhdx dmg zip rar 7z gz tgz bz2 xz z
cpio ace arj lzh lha uue
""".split())

MAGIC = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"#!", "script"),
    (b"\xca\xfe\xba\xbe", "macho_or_class"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"%PDF", "pdf"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
    (b"dex\n", "dex"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"MSCF", "cab"),
)

# Lower-case path fragments (with slashes) whose contents are always scanned.
HIGH_RISK_DIRS = (
    "/downloads/", "/desktop/", "/appdata/", "/temp/", "/tmp/", "/startup/",
    "/programdata/", "/windows/temp/", "/$recycle.bin/", "/users/public/",
    "/var/tmp/", "/dev/shm/", "/.cache/", "/.local/bin/", "/.config/autostart/",
    "/etc/cron", "/var/spool/cron/", "/etc/systemd/", "/etc/init.d/", "/etc/profile.d/",
    "/usr/local/bin/", "/usr/local/sbin/", "/opt/", "/srv/", "/var/www/",
)

# Directory paths (relative to the volume root, lower case) pruned in quick mode.
QUICK_PRUNE = frozenset({
    "/windows/winsxs", "/windows/servicing", "/windows/softwaredistribution/datastore",
    "/windows/assembly", "/windows/microsoft.net/assembly", "/windows/installer/$patchcache$",
    "/windows/fonts", "/windows/systemresources", "/windows/inf", "/windows/logs",
    "/system volume information", "/usr/share/doc", "/usr/share/man", "/usr/share/locale",
    "/usr/share/icons", "/usr/share/fonts", "/usr/share/help", "/usr/lib/firmware",
    "/lib/firmware", "/usr/share/texlive", "/usr/share/texmf-dist", "/var/cache/apt/archives",
    "/var/cache/pacman/pkg", "/var/cache/dnf", "/var/cache/zypp", "/var/lib/flatpak/repo",
    "/var/lib/snapd/cache", "/snap", "/proc", "/sys", "/dev",
})

# Never descended into in any mode (virtual or self-referential on targets).
ALWAYS_PRUNE = frozenset({"/proc", "/sys"})


def magic_kind(head: bytes) -> str | None:
    for prefix, kind in MAGIC:
        if head.startswith(prefix):
            return kind
    return None


def extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    if "." not in base[1:]:
        return ""
    return base.rsplit(".", 1)[-1].lower()


def interesting(relpath: str, head: bytes) -> bool:
    """Should a quick scan look at this file?"""
    lower = relpath.lower()
    if any(fragment in lower for fragment in HIGH_RISK_DIRS):
        return True
    if extension(lower) in EXECUTABLE_EXT:
        return True
    return magic_kind(head) is not None


def interesting_by_name(relpath: str) -> bool:
    """Cheap pre-filter used by the size estimator (no file contents)."""
    lower = relpath.lower()
    return any(f in lower for f in HIGH_RISK_DIRS) or extension(lower) in EXECUTABLE_EXT \
        or extension(lower) == ""


def prune(rel_dir: str, mode: str) -> bool:
    lower = rel_dir.lower().rstrip("/")
    if lower in ALWAYS_PRUNE:
        return True
    return mode == "quick" and lower in QUICK_PRUNE
