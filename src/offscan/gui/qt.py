"""Qt binding shim: PySide6 when available, otherwise PyQt6.

Ubuntu 24.04, Linux Mint 22 and Debian 12 package PyQt6 but not PySide6;
every other target distro packages both.  Importing Qt only through this
module lets every distro use its own, natively themed Qt bindings.

Set ``OFFSCAN_QT_API=pyside6`` or ``=pyqt6`` to force one.
"""

from __future__ import annotations

import os

from .. import appinfo

_forced = os.environ.get(appinfo.env("QT_API"), "").strip().lower()
_order = [_forced] if _forced in ("pyside6", "pyqt6") else ["pyside6", "pyqt6"]

_last_error: ImportError | None = None
for _api in _order:
    try:
        if _api == "pyside6":
            import PySide6
            from PySide6 import QtCore, QtGui, QtWidgets
            from PySide6.QtCore import Property, Signal, Slot

            BINDING = "PySide6"
            BINDING_VERSION = PySide6.__version__
        else:
            from PyQt6 import QtCore, QtGui, QtWidgets
            from PyQt6.QtCore import pyqtProperty as Property
            from PyQt6.QtCore import pyqtSignal as Signal
            from PyQt6.QtCore import pyqtSlot as Slot

            BINDING = "PyQt6"
            BINDING_VERSION = QtCore.PYQT_VERSION_STR
        break
    except ImportError as exc:  # try the next binding
        _last_error = exc
else:
    raise ImportError(
        "Neither PySide6 nor PyQt6 could be imported; install your "
        "distribution's PySide6 or PyQt6 package"
    ) from _last_error

try:
    if BINDING == "PySide6":
        from PySide6 import QtDBus
    else:
        from PyQt6 import QtDBus
except ImportError:  # QtDBus is optional (only used for the accent colour)
    QtDBus = None  # type: ignore[assignment]


def _parse_version(text: str) -> tuple[int, int, int]:
    parts = [int(p) for p in text.split(".")[:3] if p.isdigit()]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


QT_VERSION = _parse_version(QtCore.qVersion())


def qt_at_least(major: int, minor: int = 0, patch: int = 0) -> bool:
    return QT_VERSION >= (major, minor, patch)


__all__ = [
    "BINDING",
    "BINDING_VERSION",
    "QT_VERSION",
    "Property",
    "QtCore",
    "QtDBus",
    "QtGui",
    "QtWidgets",
    "Signal",
    "Slot",
    "qt_at_least",
]
