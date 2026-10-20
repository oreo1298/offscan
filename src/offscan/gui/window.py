"""Main window: a sidebar of pages, with the scan flow wired between them."""

from __future__ import annotations

from typing import Any

from .. import appinfo
from ..history import History
from ..settings import Settings
from .bridge import Bridge
from .pages.definitions import DefinitionsPage
from .pages.drives import DrivesPage
from .pages.history import HistoryPage
from .pages.results import ResultsPage
from .pages.scan import ProgressPage, ScanController, ScanPage
from .pages.settings import SettingsPage
from .qt import QtCore, QtGui, QtWidgets
from .theme import icon
from .widgets import ask, error

Qt = QtCore.Qt
SP = QtWidgets.QStyle.StandardPixmap
PAGES = (
    ("drives", "Drives", ("drive-harddisk",), SP.SP_DriveHDIcon),
    ("scan", "Scan", ("system-search", "edit-find"), SP.SP_FileDialogContentsView),
    ("progress", "Progress", ("view-refresh", "process-working"), SP.SP_BrowserReload),
    ("results", "Results", ("view-list-details", "document-properties"), SP.SP_FileDialogDetailedView),
    ("definitions", "Definitions", ("system-software-update", "folder-download"), SP.SP_DialogSaveButton),
    ("history", "History", ("document-open-recent", "appointment-recurring"), SP.SP_FileDialogListView),
    ("settings", "Settings", ("preferences-system", "configure"), SP.SP_FileDialogInfoView),
)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, bridge: Bridge, settings: Settings, history: History | None,
                 updater_factory: Any = None, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.bridge = bridge
        self.settings = settings
        self.history = history
        self.setWindowTitle(appinfo.DISPLAY_NAME)
        self.resize(1100, 760)
        self.controller = ScanController(bridge, history, self)
        self.pages: dict[str, QtWidgets.QWidget] = {
            "drives": DrivesPage(bridge),
            "scan": ScanPage(settings),
            "progress": ProgressPage(self.controller),
            "results": ResultsPage(bridge, history),
            "definitions": DefinitionsPage(bridge, settings, updater_factory=updater_factory),
            "history": HistoryPage(bridge, history),
            "settings": SettingsPage(settings),
        }
        self.nav = QtWidgets.QListWidget()
        self.nav.setAccessibleName("Pages")
        self.nav.setIconSize(QtCore.QSize(24, 24))
        self.nav.setSpacing(2)
        self.stack = QtWidgets.QStackedWidget()
        for index, (key, title, icons, fallback) in enumerate(PAGES):
            item = QtWidgets.QListWidgetItem(icon(*icons, fallback=fallback), title)
            item.setToolTip(f"{title} (Alt+{index + 1})")
            item.setData(Qt.ItemDataRole.AccessibleTextRole, title)
            self.nav.addItem(item)
            self.stack.addWidget(self.pages[key])
            shortcut = QtGui.QShortcut(QtGui.QKeySequence(f"Alt+{index + 1}"), self)
            shortcut.activated.connect(lambda i=index: self.nav.setCurrentRow(i))
        self.nav.setFixedWidth(self.nav.sizeHintForColumn(0) + 2 * self.nav.frameWidth() + 24)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.currentRowChanged.connect(lambda _row: self._page_shown())
        central = QtWidgets.QWidget()
        row = QtWidgets.QHBoxLayout(central)
        row.addWidget(self.nav)
        row.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.helper_state = QtWidgets.QLabel()
        self.helper_state.setAccessibleName("Administrator connection")
        self.statusBar().addPermanentWidget(self.helper_state)
        quit_action = QtGui.QAction("&Quit", self)
        quit_action.setShortcut(QtGui.QKeySequence(QtGui.QKeySequence.StandardKey.Quit))
        quit_action.triggered.connect(lambda *_: self.close())
        self.addAction(quit_action)
        self._wire()
        self.nav.setCurrentRow(0)
        self._helper_state()

    def page(self, key: str) -> Any:
        return self.pages[key]

    def go(self, key: str) -> None:
        self.nav.setCurrentRow([p[0] for p in PAGES].index(key))

    def _page_shown(self) -> None:
        key = PAGES[self.nav.currentRow()][0]
        if key == "history":
            self.page("history").refresh()
        elif key == "scan":
            self.page("scan").refresh_definitions()

    def _wire(self) -> None:
        drives: DrivesPage = self.page("drives")
        scan: ScanPage = self.page("scan")
        results: ResultsPage = self.page("results")
        drives.scan_requested.connect(lambda vols: (scan.set_volumes(vols), self.go("scan")))
        drives.selection_changed.connect(scan.set_volumes)
        scan.choose_drives.connect(lambda: self.go("drives"))
        scan.show_definitions.connect(lambda: self.go("definitions"))
        scan.start_requested.connect(self._start_scan)
        self.page("progress").show_results.connect(lambda: self.go("results"))
        self.controller.finished.connect(self._scan_finished)
        self.page("history").open_scan.connect(self._open_history_scan)
        self.page("definitions").changed.connect(scan.refresh_definitions)
        self.page("settings").changed.connect(self._settings_changed)
        results.status_message.connect(lambda text: self.statusBar().showMessage(text, 8000))
        self.bridge.connected.connect(lambda _info: self._helper_state())
        self.bridge.disconnected.connect(self._helper_state)
        self.bridge.connection_failed.connect(lambda _msg: self._helper_state())
        results.show_info.setChecked(bool(self.settings.data.get("ui", {}).get("show_info", False)))

    def _helper_state(self) -> None:
        self.helper_state.setText("Administrator access: connected" if self.bridge.is_connected
                                  else "Administrator access: not connected")

    def _settings_changed(self) -> None:
        self.page("results").show_info.setChecked(bool(self.settings.data.get("ui", {}).get("show_info")))
        self.statusBar().showMessage("Settings saved", 5000)

    def _start_scan(self, options: Any) -> None:
        if self.controller.running:
            error(self, "A scan is running", "Wait for the current scan to finish, or cancel it.")
            return
        if not self.bridge.is_connected:
            error(self, "Not connected", "Connect on the Drives page first.")
            return
        self.controller.start(options)
        self.go("progress")

    def _scan_finished(self, summary: Any, err: Any) -> None:
        session = getattr(self.controller, "last_session", None)
        if err is not None or summary is None or session is None:
            if err is not None:
                error(self, "The scan could not run", str(getattr(err, "message", err)))
            return
        detections: list[dict[str, Any]]
        if self.history is not None and session.scan_id is not None:
            detections = self.history.detections(session.scan_id)
        else:
            detections = [d.to_dict() for d in session.detections]
        self.page("results").load(summary, session.options.to_dict(), session.targets, detections,
                                  session.definitions)
        self.page("history").refresh()
        if self.stack.currentWidget() is self.page("progress"):
            self.go("results")

    def _open_history_scan(self, record: dict[str, Any]) -> None:
        self.page("results").load(record.get("summary") or {}, record.get("options") or {},
                                  record.get("targets") or [], record.get("detections") or [],
                                  record.get("definitions") or {})
        self.go("results")

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        if self.controller.running:
            if not ask(self, "A scan is running", "Cancel the scan and quit?", "Cancel scan and quit"):
                event.ignore()
                return
            self.controller.cancel()
        self.statusBar().showMessage("Unmounting drives…")
        QtWidgets.QApplication.processEvents()
        self.bridge.close()
        event.accept()
