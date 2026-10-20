"""Single source of truth for the application's names and identifiers.

To rename the application, edit the values in the first block and run
``python3 tools/rename.py`` (it updates ``pyproject.toml``).  Everything
else -- executables, the polkit action, desktop/AppStream files, package
names, install paths and the D-Bus-free helper path -- is derived from
these values at build time (``packaging/build.py``) or at run time.

The Python import package stays ``offscan`` internally; it is never shown
to users.
"""

from __future__ import annotations

# --- edit these to rename -------------------------------------------------
NAME = "offscan"
DISPLAY_NAME = "Offscan"
APP_ID = "io.github.oreo1298.offscan"
VERSION = "0.1.0.dev0"
SUMMARY = "Offline drive malware scanner"
DESCRIPTION = (
    "Scans the drives of Windows and Linux installations that are not "
    "running for malware and persistence, strictly read-only, using "
    "public definitions from multiple sources."
)
HOMEPAGE = "https://github.com/oreo1298/offscan"
MAINTAINER = "Offscan contributors <noreply@users.noreply.github.com>"
LICENSE = "GPL-3.0-or-later"
# ---------------------------------------------------------------------------

# Derived identifiers.  Do not hard-code these anywhere else.
HELPER_NAME = f"{NAME}-helper"
GUI_NAME = f"{NAME}-gui"
POLKIT_ACTION = f"{APP_ID}.helper"
ICON_NAME = APP_ID
DESKTOP_FILE = f"{APP_ID}.desktop"
# System account the scanners (workers, clamd, parsers, external checkers) run as,
# created by the packages (sysusers.d) and install.sh; "nobody" if it is missing.
SCAN_USER = NAME

LIB_DIR = f"/usr/lib/{NAME}"
PYTHON_DIR = f"{LIB_DIR}/python"
HELPER_PATH = f"{LIB_DIR}/{HELPER_NAME}"
# Python packages that distributions do not ship (yara-x, regipy and its
# dependencies), unpacked from pinned wheels by packaging/build.py.
VENDOR_DIR = f"{LIB_DIR}/vendor"
SYSTEM_STATE_DIR = f"/var/lib/{NAME}"
RUNTIME_DIR = f"/run/{NAME}"

# Prefix for device-mapper / loop names we create, so we can recognise and
# clean up our own devices and tell udisks to ignore them.
DEVICE_PREFIX = f"{NAME}-"

# Environment variables we read are all prefixed with this.
ENV_PREFIX = NAME.upper().replace("-", "_") + "_"

USER_AGENT = f"{DISPLAY_NAME}/{VERSION} (+{HOMEPAGE})"

# Prefix for our own signature/rule names (ASCII letters and digits only).
SIGNATURE_PREFIX = "".join(c for c in DISPLAY_NAME if c.isascii() and c.isalnum()) or "Scanner"


def env(name: str) -> str:
    """Return the full environment variable name for ``name``."""
    return ENV_PREFIX + name
