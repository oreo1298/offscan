"""Entry point of the graphical interface (``offscan-gui``)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .. import appinfo, log


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=appinfo.GUI_NAME, description=f"{appinfo.DISPLAY_NAME} — "
                                     f"{appinfo.SUMMARY}")
    parser.add_argument("--version", action="version", version=f"{appinfo.DISPLAY_NAME} {appinfo.VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("--no-connect", action="store_true",
                        help="do not ask for administrator rights at start-up")
    parser.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    args, qt_args = parser.parse_known_args(argv if argv is not None else sys.argv[1:])
    log.setup("gui", verbose=args.verbose)
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
    bridge.close()
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
