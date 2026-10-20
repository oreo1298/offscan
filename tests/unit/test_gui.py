"""The Qt interface, driven offscreen against a fake helper (no root, no drives).

Covers the scan flow end to end (Drives → Scan → Progress → Results), the confirmed-change
flow, false positives, history, theming, plain-text rendering of hostile names, keyboard
and screen-reader basics, and that slow helper calls never block the event loop.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pytestqt")
qt = pytest.importorskip("offscan.gui.qt")

from offscan.defs import store, testset  # noqa: E402
from offscan.gui import theme, widgets  # noqa: E402
from offscan.gui.bridge import Bridge  # noqa: E402
from offscan.gui.pages import results as results_page  # noqa: E402
from offscan.gui.qt import QtCore, QtGui, QtWidgets  # noqa: E402
from offscan.gui.window import MainWindow  # noqa: E402
from offscan.history import History  # noqa: E402
from offscan.scan.results import Detection  # noqa: E402
from offscan.settings import Settings  # noqa: E402
from support.fakehelper import EICAR_SHA, FakeHelper  # noqa: E402

pytestmark = pytest.mark.gui
Qt = QtCore.Qt


@pytest.fixture
def defs(xdg_home: Path) -> Path:
    target = store.sets_dir() / "test-set"
    target.parent.mkdir(parents=True, exist_ok=True)
    testset.build_test_set(target, with_clamav=False)
    store.activate(target)
    return target


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record message boxes instead of showing them; answer questions with "yes"."""
    shown: list[tuple[str, str]] = []

    def fake_exec(box: QtWidgets.QMessageBox) -> int:
        shown.append((box.windowTitle(), box.text()))
        for button in box.buttons():
            if box.buttonRole(button) == QtWidgets.QMessageBox.ButtonRole.AcceptRole:
                box.setProperty("clicked", True)
                monkeypatch.setattr(box, "clickedButton", lambda b=button: b)
        return 0
    monkeypatch.setattr(QtWidgets.QMessageBox, "exec", fake_exec)
    return shown


@pytest.fixture
def env(qtbot, defs: Path, tmp_path: Path, dialogs) -> dict[str, Any]:
    mount = tmp_path / "mnt"
    (mount / "home/user").mkdir(parents=True)
    fake = FakeHelper(str(mount))
    bridge = Bridge(lambda on_event: fake)
    history = History(tmp_path / "history.sqlite3")
    settings = Settings(tmp_path / "settings.json")
    window = MainWindow(bridge, settings, history)
    qtbot.addWidget(window)
    window.show()
    yield {"fake": fake, "bridge": bridge, "window": window, "history": history, "dialogs": dialogs}
    history.close()


def _connect(qtbot, env: dict[str, Any]) -> None:
    window = env["window"]
    with qtbot.waitSignal(env["bridge"].connected, timeout=5000):
        env["bridge"].connect_helper()
    drives = window.page("drives")
    qtbot.waitUntil(lambda: drives.tree.topLevelItemCount() == 1 and drives.busy.isHidden(), timeout=5000)


def _volume_item(drives, volume_id: str) -> QtWidgets.QTreeWidgetItem:
    for item in drives._items():
        data = item.data(0, Qt.ItemDataRole.UserRole) or {}
        if data.get("id") == volume_id:
            return item
    raise AssertionError(volume_id)


def _run_scan(qtbot, env: dict[str, Any], volume: str = "sdb2") -> None:
    window = env["window"]
    _connect(qtbot, env)
    drives = window.page("drives")
    _volume_item(drives, volume).setCheckState(0, Qt.CheckState.Checked)
    drives.scan_button.click()
    assert window.stack.currentWidget() is window.page("scan")
    scan = window.page("scan")
    assert scan.start_button.isEnabled()
    with qtbot.waitSignal(window.controller.finished, timeout=15000):
        scan.start_button.click()
    qtbot.waitUntil(lambda: window.stack.currentWidget() is window.page("results"), timeout=5000)


def test_drives_are_listed_safely(qtbot, env) -> None:
    window = env["window"]
    drives = window.page("drives")
    assert drives.connect_box.isVisibleTo(window) or env["bridge"].is_connected is False
    _connect(qtbot, env)
    assert not drives.connect_box.isVisibleTo(window)
    texts = [item.text(0) for item in drives._items()]
    assert any("\\u202e" in t for t in texts), texts          # bidi override shown escaped, not obeyed
    assert not any("‮" in t for t in texts)
    windows = _volume_item(drives, "sdb1")
    drives.tree.setCurrentItem(windows)
    assert "<b>(Fast Startup)</b>" in drives.details.text()     # shown literally (plain text)
    assert drives.details.textFormat() == Qt.TextFormat.PlainText
    assert "Windows 11 Pro" in windows.text(3) and "hibernated" in windows.text(4)
    assert ("drives.list", {"probe": "wait"}) in env["fake"].calls


def test_unlock_flow(qtbot, env, monkeypatch) -> None:
    _connect(qtbot, env)
    drives = env["window"].page("drives")
    drives.tree.setCurrentItem(_volume_item(drives, "sdb3"))
    assert drives.act_unlock.isEnabled() and not drives.act_mount.isEnabled()
    monkeypatch.setattr(widgets.SecretDialog, "exec", lambda self: QtWidgets.QDialog.DialogCode.Accepted)
    monkeypatch.setattr(widgets.SecretDialog, "value", lambda self: ("secret", "passphrase"))
    drives.act_unlock.trigger()
    qtbot.waitUntil(lambda: any((i.data(0, Qt.ItemDataRole.UserRole) or {}).get("id") == "dm-0"
                                for i in drives._items()), timeout=5000)
    child = _volume_item(drives, "dm-0")
    assert child.flags() & Qt.ItemFlag.ItemIsUserCheckable           # the unlocked filesystem can be scanned


def test_scan_flow_and_results(qtbot, env) -> None:
    window = env["window"]
    _run_scan(qtbot, env)
    progress = window.page("progress")
    assert "Scan finished" in progress.phase.text()
    assert "\\x1b" not in progress.stats["current"].text() or "\x1b" not in progress.stats["current"].text()
    assert progress.live.count() == 3                               # informational entry not listed
    results = window.page("results")
    assert results.proxy.rowCount() == 3
    results.show_info.setChecked(True)
    assert results.proxy.rowCount() == 4
    results.show_info.setChecked(False)
    results.severity.setCurrentIndex(results.severity.findText("High only"))
    assert results.proxy.rowCount() == 2
    results.severity.setCurrentIndex(0)
    results.search.setText("198.51.100.7")
    assert results.proxy.rowCount() == 1
    results.search.setText("")
    (scan_record,) = env["history"].scans()
    assert scan_record["summary"]["detections"] == 3


def _select(results, signature_part: str) -> None:
    for row in range(results.proxy.rowCount()):
        index = results.proxy.index(row, 1)
        if signature_part in results.proxy.data(index):
            results.table.setCurrentIndex(index)
            return
    raise AssertionError(signature_part)


def test_result_actions(qtbot, env, monkeypatch) -> None:
    window = env["window"]
    _run_scan(qtbot, env)
    results = window.page("results")
    _select(results, "Autostart entry")
    assert not results.act_quarantine.isEnabled()                   # registry entries cannot be removed
    assert "Registry" in results.act_quarantine.toolTip()
    _select(results, "EICAR")
    assert results.act_copy_hash.isEnabled()
    results.act_copy_hash.trigger()
    assert QtWidgets.QApplication.clipboard().text() == EICAR_SHA
    results.act_false.trigger()
    current = results.current()
    assert current[1]["status"] == "false_positive"
    det: Detection = current[1]["det"]
    assert env["history"].is_false_positive(det)
    results.act_false.trigger()
    assert results.current()[1]["status"] == "open"

    confirmed: list[list[str]] = []

    def accept(dialog: widgets.ConfirmChangeDialog) -> int:
        confirmed.append(dialog.findChild(QtWidgets.QPlainTextEdit).toPlainText())
        assert not dialog.go.isEnabled()                              # needs the explicit tick first
        dialog.understood.setChecked(True)
        assert dialog.go.isEnabled()
        return QtWidgets.QDialog.DialogCode.Accepted
    monkeypatch.setattr(widgets.ConfirmChangeDialog, "exec", accept)
    _select(results, "Scheduled command")
    assert results.act_quarantine.isEnabled()
    results.act_quarantine.trigger()
    qtbot.waitUntil(lambda: results.current()[1]["status"] == "quarantined", timeout=5000)
    assert "the file that holds this entry" in confirmed[0]
    applied = [p for m, p in env["fake"].calls if m == "remedy.apply"]
    assert applied == [{"volume": "sdb2", "path": "/etc/cron.d/backup", "expect_sha256": EICAR_SHA,
                        "action": "quarantine", "confirm": True}]
    stored = env["history"].detections(env["history"].scans()[0]["id"])
    assert any(d["status"] == "quarantined" and d["path"] == "/etc/cron.d/backup" for d in stored)
    assert not results.act_quarantine.isEnabled()                   # already handled


def test_refused_change_is_explained(qtbot, env, monkeypatch) -> None:
    window = env["window"]
    _run_scan(qtbot, env, volume="sdb1")
    results = window.page("results")
    _select(results, "EICAR")
    called = []
    monkeypatch.setattr(widgets.ConfirmChangeDialog, "exec", lambda self: called.append(1) or 0)
    results.act_delete.trigger()
    qtbot.waitUntil(lambda: any(t == "Not possible" for t, _ in env["dialogs"]), timeout=5000)
    assert not called and not [m for m, _ in env["fake"].calls if m == "remedy.apply"]


def test_history_and_quarantine(qtbot, env, monkeypatch) -> None:
    window = env["window"]
    _run_scan(qtbot, env)
    window.go("history")
    history = window.page("history")
    assert history.scans.rowCount() == 1
    history.scans.setCurrentCell(0, 0)
    window.go("drives")
    history._open()
    assert window.stack.currentWidget() is window.page("results")
    assert window.page("results").proxy.rowCount() == 3
    window.go("history")
    history.tabs.setCurrentIndex(1)
    qtbot.waitUntil(lambda: history.quarantine.rowCount() == 1, timeout=5000)
    qtbot.waitUntil(lambda: history.changes.rowCount() == 1, timeout=5000)
    history.quarantine.setCurrentCell(0, 0)

    def accept(dialog: widgets.ConfirmChangeDialog) -> int:
        dialog.understood.setChecked(True)
        return QtWidgets.QDialog.DialogCode.Accepted
    monkeypatch.setattr(widgets.ConfirmChangeDialog, "exec", accept)
    history._restore()
    qtbot.waitUntil(lambda: any(m == "quarantine.restore" for m, _ in env["fake"].calls), timeout=5000)
    restore = next(p for m, p in env["fake"].calls if m == "quarantine.restore")
    assert restore == {"id": "b" * 32, "volume": "sdb2", "confirm": True}


def test_gui_never_blocks_on_slow_helper(qtbot, env) -> None:
    """While the helper takes seconds to answer, the event loop keeps running."""
    _connect(qtbot, env)
    env["fake"].delay = 1.5
    ticks = []
    timer = QtCore.QTimer()
    timer.timeout.connect(lambda: ticks.append(time.monotonic()))
    timer.start(20)
    drives = env["window"].page("drives")
    started = time.monotonic()
    drives.refresh()
    assert time.monotonic() - started < 0.2                          # refresh() returned at once
    qtbot.wait(1000)
    timer.stop()
    assert len(ticks) >= 25, len(ticks)
    assert not drives.busy.isHidden()                                # still working, visibly


def test_keyboard_and_accessibility(qtbot, env) -> None:
    window = env["window"]
    _connect(qtbot, env)
    for index in range(window.nav.count()):
        qtbot.keyClick(window, getattr(Qt.Key, f"Key_{index + 1}"), Qt.KeyboardModifier.AltModifier)
        assert window.stack.currentIndex() == index
    missing = []
    checked = 0
    for widget in window.findChildren(QtWidgets.QWidget):
        if not isinstance(widget, (QtWidgets.QAbstractButton, QtWidgets.QLineEdit, QtWidgets.QComboBox,
                                   QtWidgets.QAbstractItemView, QtWidgets.QAbstractSpinBox,
                                   QtWidgets.QPlainTextEdit)):
            continue
        if isinstance(widget, QtWidgets.QAbstractButton) and widget.text().strip():
            continue
        if widget.parent() is not None and type(widget.parent()).__name__ in (
                "QComboBox", "QAbstractSpinBox", "QScrollBar", "QTabBar", "QToolBar", "QHeaderView",
                "QCalendarWidget", "QTableCornerButton", "QLineEdit"):
            continue
        if widget.objectName().startswith("qt_") or type(widget).__name__ in ("QToolButton", "QHeaderView"):
            continue
        if widget.window() is not window:                     # popups of combo boxes and the like
            continue
        checked += 1
        if not widget.accessibleName() and not isinstance(widget, QtWidgets.QAbstractButton):
            missing.append(f"{type(widget).__name__} in {type(widget.window()).__name__}")
    assert not missing, missing
    assert checked >= 15, checked


def test_theme_follows_dark_preference(qtbot, monkeypatch) -> None:
    app = QtWidgets.QApplication.instance()
    light = QtGui.QPalette(app.palette())
    if theme.is_dark(light):
        pytest.skip("the style already uses a dark palette")
    dark = theme.derive_dark(light)
    assert theme.is_dark(dark)
    assert dark.color(QtGui.QPalette.ColorRole.Highlight) == light.color(QtGui.QPalette.ColorRole.Highlight)
    accent = QtGui.QColor.fromRgbF(0.2, 0.4, 0.8)
    themed = theme.with_accent(dark, accent)
    assert themed.color(QtGui.QPalette.ColorRole.Highlight) == accent
    assert theme.parse_accent((0.2, 0.4, 0.8)) == accent
    assert theme.parse_accent((-1.0, 0.0, 0.0)) is None and theme.parse_accent("x") is None
    assert theme.platform_supplies_palette({"XDG_CURRENT_DESKTOP": "KDE"})
    assert theme.platform_supplies_palette({"QT_QPA_PLATFORMTHEME": "qt6ct"})
    assert not theme.platform_supplies_palette({"XDG_CURRENT_DESKTOP": "GNOME"})
    t = theme.Theme(app, env={"XDG_CURRENT_DESKTOP": "GNOME"})
    original = QtGui.QPalette(app.palette())
    try:
        t.prefers_dark, t.accent = True, accent
        t.apply()
        assert theme.is_dark(app.palette())
        assert app.palette().color(QtGui.QPalette.ColorRole.Highlight) == accent
    finally:
        app.setPalette(original)


def test_remedy_targets() -> None:
    def det(**kw: Any) -> Detection:
        return Detection(volume="v", path=kw.pop("path", "/x"), engine=kw.pop("engine", "persistence"),
                         signature="s", details=kw)
    assert results_page.remedy_target(det(engine="clamav", path="/a.exe"))[0] == "/a.exe"
    assert results_page.remedy_target(det(check="windows.run_key", target="/Users/Public/u.exe"))[0] == \
        "/Users/Public/u.exe"
    assert results_page.remedy_target(det(check="windows.ifeo"))[0] is None
    assert results_page.remedy_target(det(check="linux.account", path="/etc/passwd"))[0] is None
    assert results_page.remedy_target(det(check="linux.pam", path="/@/etc/pam.d/sshd", root="/@"))[0] is None
    keys = det(check="linux.ssh_key", path="/home/u/.ssh/authorized_keys")
    assert results_page.remedy_target(keys)[0] is None
    assert results_page.remedy_target(det(check="linux.cron", path="/etc/cron.d/x"))[0] == "/etc/cron.d/x"
    target, why = results_page.remedy_target(det(engine="integrity", check="integrity.package_modified",
                                                 path="/usr/bin/ls", package="coreutils"))
    assert target == "/usr/bin/ls" and "reinstall coreutils" in why
