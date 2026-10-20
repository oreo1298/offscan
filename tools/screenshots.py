"""Render every GUI page against the fake helper, in light and dark, for the docs.

    QT_QPA_PLATFORM=offscreen python tools/screenshots.py docs/screenshots

Uses temporary XDG directories and the EICAR self-test definitions; no root,
no drives, no network.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def main(out: Path) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="shots-"))
    for var, sub in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"),
                     ("XDG_STATE_HOME", "state")):
        os.environ[var] = str(tmp / sub)
    from offscan import appinfo
    os.environ[appinfo.env("SYSTEM_STATE_DIR")] = str(tmp / "var-lib")
    os.environ[appinfo.env("RUNTIME_DIR")] = str(tmp / "run")
    from offscan.defs import store, testset
    from offscan.gui import theme
    from offscan.gui.bridge import Bridge
    from offscan.gui.qt import QtCore, QtGui, QtWidgets
    from offscan.gui.window import PAGES, MainWindow
    from offscan.history import History
    from offscan.settings import Settings
    from support.fakehelper import FakeHelper

    target = store.sets_dir() / "set"
    target.parent.mkdir(parents=True, exist_ok=True)
    testset.build_test_set(target, with_clamav=False)
    store.activate(target)
    app = QtWidgets.QApplication(["shots"])
    app.setStyle("Fusion")
    light = QtGui.QPalette(app.style().standardPalette())
    out.mkdir(parents=True, exist_ok=True)

    def settle(seconds: float = 0.3) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)

    fake = FakeHelper(str(tmp / "mnt"), delay=0.005)
    bridge = Bridge(lambda on_event: fake)
    history = History(tmp / "history.sqlite3")
    window = MainWindow(bridge, Settings(tmp / "settings.json"), history)
    window.resize(1180, 780)
    window.show()
    bridge.connect_helper()
    settle(1.0)
    drives = window.page("drives")
    for item in drives._items():
        data = item.data(0, QtCore.Qt.ItemDataRole.UserRole) or {}
        if data.get("id") == "sdb2":
            item.setCheckState(0, QtCore.Qt.CheckState.Checked)
            drives.tree.setCurrentItem(item)
    drives._scan()
    settle()
    window.page("scan").start_button.click()
    settle(2.0)
    results = window.page("results")
    results.table.selectRow(0)
    settle()
    for scheme, palette in (("light", light), ("dark", theme.derive_dark(light))):
        app.setPalette(theme.with_accent(palette, palette.color(QtGui.QPalette.ColorRole.Highlight)))
        for index, (key, *_rest) in enumerate(PAGES):
            window.nav.setCurrentRow(index)
            settle(0.2)
            path = out / f"{key}-{scheme}.png"
            window.grab().save(str(path))
            print(path)
    history.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots")))
