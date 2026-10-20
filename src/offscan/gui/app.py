"""Entry point of the graphical interface (``offscan-gui``)."""

from __future__ import annotations

import argparse
import faulthandler
import logging
import os
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

from .. import appinfo, log

if TYPE_CHECKING:
    from .bridge import Bridge
    from .qt import QtWidgets


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=appinfo.GUI_NAME, description=f"{appinfo.DISPLAY_NAME} — "
                                     f"{appinfo.SUMMARY}")
    parser.add_argument("--version", action="version", version=f"{appinfo.DISPLAY_NAME} {appinfo.VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("--no-connect", action="store_true",
                        help="do not ask for administrator rights at start-up")
    parser.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    parser.add_argument("--self-check", action="store_true",
                        help="build the window without showing it, print the Qt binding and exit")
    args, qt_args = parser.parse_known_args(argv if argv is not None else sys.argv[1:])
    if args.self_check and not any(os.environ.get(v) for v in ("QT_QPA_PLATFORM", "DISPLAY",
                                                                  "WAYLAND_DISPLAY")):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
    log.setup("gui", verbose=args.verbose, to_file=not args.self_check)
    faulthandler.enable()            # a crash in Qt prints every thread's Python stack to stderr
    from ..history import History
    from ..settings import Settings
    from .bridge import Bridge
    from .qt import QtWidgets
    from .theme import Theme, icon
    from .window import MainWindow

    app = QtWidgets.QApplication([sys.argv[0], *qt_args])
    app.setApplicationName(appinfo.NAME)
    app.setApplicationDisplayName(appinfo.DISPLAY_NAME)
    app.setApplicationVersion(appinfo.VERSION)
    app.setDesktopFileName(appinfo.APP_ID)
    app.setWindowIcon(icon(appinfo.ICON_NAME, "security-high", "drive-harddisk"))
    theme = Theme(app)
    theme.refresh()
    if args.self_check:
        return _self_check(app)
    settings = Settings()
    try:
        history: History | None = History()
    except Exception as exc:                 # history is a convenience; never block scanning on it
        log.get("gui").error("history unavailable: %s", exc)
        history = None
    bridge = Bridge()
    window = MainWindow(bridge, settings, history)
    window.show()
    if not args.no_connect:
        bridge.connect_helper(prefer_sudo=args.sudo)
    code = app.exec()
    return _finish(bridge, int(code))


def _finish(bridge: Bridge, code: int) -> int:
    """Close the bridge; leave without tearing Qt down if one of its threads is still running.

    Such a thread (a definitions update, say) still holds references to Qt
    objects. If it dropped the last one after the application is destroyed,
    the objects would be freed from the wrong thread and the process would
    crash on exit. The thread cannot be stopped cleanly anyway.
    """
    bridge.close()
    if not bridge.busy:
        return code
    log.get("gui").warning("quitting while background work is still running")
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _self_check(app: QtWidgets.QApplication) -> int:
    """Build every page without a helper, history or network; used by package tests."""
    from ..settings import Settings
    from .bridge import Bridge
    from .qt import BINDING, BINDING_VERSION, QT_VERSION, QtWidgets
    from .theme import is_dark
    from .window import MainWindow

    bridge = Bridge()
    window = MainWindow(bridge, Settings(), None)
    for row in range(window.nav.count()):
        window.nav.setCurrentRow(row)
        QtWidgets.QApplication.processEvents()
    pages = window.stack.count()
    window.close()
    print(f"{appinfo.GUI_NAME} self-check: OK ({BINDING} {BINDING_VERSION}, "
          f"Qt {'.'.join(map(str, QT_VERSION))}, platform {app.platformName()}, {pages} pages, "
          f"{'dark' if is_dark(app.palette()) else 'light'} palette)", flush=True)
    return _finish(bridge, 0)


if __name__ == "__main__":
    sys.exit(main())
