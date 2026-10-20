"""Results: findings of a scan, details, and the actions on them."""

from __future__ import annotations

import html
import os
import posixpath
from typing import Any

from ... import fmt, names, remediation, reports
from ...history import History
from ...protocol import RemoteError
from ...scan.results import CHECK_ENGINES, SEVERITY_RANK, Detection
from ..bridge import Bridge
from ..qt import QtCore, QtGui, QtWidgets, Signal
from ..theme import severity_icon
from ..widgets import ConfirmChangeDialog, action, error, heading, info, plain_label, safe, safe_text

Qt = QtCore.Qt
COLUMNS = ("Severity", "Finding", "Volume", "Where", "Engine", "Status")
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
ENGINE_GROUPS = {"All engines": None, "Files (ClamAV, YARA, hashes)": ("clamav", "yara", "hash"),
                 "Autostart and persistence": ("persistence",), "Packages and system files": ("integrity",),
                 "External tools": ("tool",)}
STATUS_TEXT = {"open": "", "false_positive": "false positive", "quarantined": "quarantined",
               "deleted": "deleted"}
# Files that hold an entry but must be edited, never removed.
KEEP_FILES = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/crontab",
              "/etc/ssh/sshd_config", "/etc/default/grub", "/etc/fstab", "/etc/environment", "/etc/profile",
              "/etc/bash.bashrc", "/etc/bashrc", "/etc/ld.so.conf")
KEEP_PREFIXES = ("/etc/pam.d/", "/boot/", "/etc/apt/apt.conf.d/", "/etc/modprobe.d/")
KEEP_SUFFIXES = ("/.bashrc", "/.profile", "/.bash_profile", "/.zshrc", "/.zprofile", "/authorized_keys")


def remedy_target(det: Detection) -> tuple[str | None, str]:
    """(volume-relative path to act on, explanation).  None means: no file can be removed."""
    if det.engine not in CHECK_ENGINES:
        return det.path, "the detected file"
    check = str(det.details.get("check") or "")
    target = det.details.get("target")
    if check.startswith("integrity."):
        package = det.details.get("package")
        return det.path, "the changed file" + (f" (reinstall {package} afterwards)" if package else "")
    if target:
        return target, "the program this entry starts"
    if check.startswith("windows."):
        return None, ("Registry entries cannot be changed offline. Remove the program the entry starts, "
                      "or fix the entry from Windows.")
    path = det.path or ""
    root = det.details.get("root") or ""
    inner = path[len(root):] if root and path.startswith(root) else path
    if not path or inner in KEEP_FILES or inner.startswith(KEEP_PREFIXES) or inner.endswith(KEEP_SUFFIXES):
        return None, f"Edit {safe(inner or 'the file')} to remove this entry; the file itself is needed."
    return path, "the file that holds this entry"


class DetectionsModel(QtCore.QAbstractTableModel):
    def __init__(self, parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self.rows: list[dict[str, Any]] = []        # {"det": Detection, "status": str, "id": int | None}

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation,  # noqa: N802
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: QtCore.QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        det: Detection = row["det"]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return det.severity
            if col == 1:
                return safe(det.signature, 200)
            if col == 2:
                return det.volume
            if col == 3:
                where = det.details.get("location") if det.engine in CHECK_ENGINES else det.path
                return safe(where or det.path, 300)
            if col == 4:
                return det.engine
            return STATUS_TEXT.get(row["status"], row["status"])
        if role == Qt.ItemDataRole.DecorationRole and col == 0:
            return severity_icon(det.severity)
        if role == Qt.ItemDataRole.ToolTipRole and col in (1, 3):
            # Qt guesses whether a tooltip is rich text; target data must never be HTML.
            return "<qt>" + html.escape(safe(det.details.get("value") or det.path, 1000)) + "</qt>"
        if role == SORT_ROLE:
            if col == 0:
                return SEVERITY_RANK.get(det.severity, 9)
            return str(self.data(index, Qt.ItemDataRole.DisplayRole) or "").lower()
        if role == Qt.ItemDataRole.AccessibleTextRole and col == 0:
            return f"severity {det.severity}"
        return None

    def update_status(self, row: int, status: str) -> None:
        self.rows[row]["status"] = status
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(COLUMNS) - 1))


class FilterModel(QtCore.QSortFilterProxyModel):
    def __init__(self, parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self.text = ""
        self.min_rank = 9
        self.engines: tuple[str, ...] | None = None
        self.show_info = False
        self.show_closed = True
        self.setSortRole(SORT_ROLE)

    def filterAcceptsRow(self, source_row: int, source_parent: QtCore.QModelIndex) -> bool:  # noqa: N802
        model: DetectionsModel = self.sourceModel()
        row = model.rows[source_row]
        det: Detection = row["det"]
        if det.inventory and not self.show_info:
            return False
        if SEVERITY_RANK.get(det.severity, 9) > self.min_rank and not det.inventory:
            return False
        if self.engines is not None and det.engine not in self.engines:
            return False
        if not self.show_closed and row["status"] != "open":
            return False
        if self.text:
            hay = " ".join(str(x) for x in (det.signature, det.path, det.volume, det.details.get("location"),
                                             det.details.get("value"), det.sha256, det.category)).lower()
            if self.text not in hay:
                return False
        return True


class ResultsPage(QtWidgets.QWidget):
    status_message = Signal(str)

    def __init__(self, bridge: Bridge, history: History | None, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.bridge = bridge
        self.history = history
        self.report_data: dict[str, Any] | None = None
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("Results"))
        self.summary = plain_label("No results yet. Run a scan, or open one from the History page.")
        self.summary.setAccessibleName("Scan summary")
        layout.addWidget(self.summary)

        filters = QtWidgets.QHBoxLayout()
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Filter by name, path, hash…")
        self.search.setAccessibleName("Filter results")
        self.search.setClearButtonEnabled(True)
        self.severity = QtWidgets.QComboBox()
        self.severity.setAccessibleName("Minimum severity")
        for text, rank in (("All severities", 9), ("Low and above", SEVERITY_RANK["low"]),
                           ("Medium and above", SEVERITY_RANK["medium"]),
                           ("High only", SEVERITY_RANK["high"])):
            self.severity.addItem(text, rank)
        self.engine = QtWidgets.QComboBox()
        self.engine.setAccessibleName("Engine")
        for text in ENGINE_GROUPS:
            self.engine.addItem(text)
        self.show_info = QtWidgets.QCheckBox("Show &informational entries")
        self.show_closed = QtWidgets.QCheckBox("Show &handled")
        self.show_closed.setChecked(True)
        for widget in (self.search, self.severity, self.engine, self.show_info, self.show_closed):
            filters.addWidget(widget, 1 if widget is self.search else 0)
        layout.addLayout(filters)

        self.model = DetectionsModel(self)
        self.proxy = FilterModel(self)
        self.proxy.setSourceModel(self.model)
        split = QtWidgets.QSplitter(Qt.Orientation.Vertical)
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.proxy)
        self.table.setAccessibleName("Findings")
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self.table.selectionModel().currentRowChanged.connect(lambda *_: self._update_details())
        split.addWidget(self.table)
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setAccessibleName("Details of the selected finding")
        split.addWidget(self.details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

        self.toolbar = QtWidgets.QToolBar("Finding actions")
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.act_copy_hash = action(self, "Copy &hash", self.copy_hash, ("edit-copy",), "Ctrl+Shift+C",
                                    "Copy the SHA-256 of the file")
        self.act_copy_path = action(self, "Copy &path", self.copy_path, ("edit-copy",), None, "Copy the path")
        self.act_open = action(self, "&Open folder", self.open_folder, ("folder-open",), "Ctrl+O",
                               "Show the folder (read-only) in the file manager",
                               QtWidgets.QStyle.StandardPixmap.SP_DirOpenIcon)
        self.act_quarantine = action(self, "&Quarantine…", lambda: self.change("quarantine"),
                                     ("security-high", "document-encrypt"), "Ctrl+Shift+Q",
                                     "Move the file to the quarantine (changes the drive)")
        self.act_delete = action(self, "&Delete…", lambda: self.change("delete"), ("edit-delete",),
                                 QtGui.QKeySequence.StandardKey.Delete, "Delete the file (changes the drive)",
                                 QtWidgets.QStyle.StandardPixmap.SP_TrashIcon)
        self.act_false = action(self, "Mark as &false positive", self.toggle_false_positive,
                                ("emblem-ok", "dialog-ok"), "Ctrl+Shift+F",
                                "Hide this finding for this file from now on")
        self.act_export = action(self, "&Export report…", self.export, ("document-save-as", "document-save"),
                                 "Ctrl+E", "Save the results as HTML, JSON or CSV",
                                 QtWidgets.QStyle.StandardPixmap.SP_DialogSaveButton)
        for act in (self.act_copy_hash, self.act_copy_path, self.act_open, self.act_quarantine,
                    self.act_delete, self.act_false, self.act_export):
            self.toolbar.addAction(act)
            if act is not self.act_export:
                self.table.addAction(act)
        self.addAction(self.act_export)
        find = QtGui.QAction(self)
        find.setShortcut(QtGui.QKeySequence(QtGui.QKeySequence.StandardKey.Find))
        find.triggered.connect(lambda *_: self.search.setFocus())
        self.addAction(find)
        layout.insertWidget(2, self.toolbar)

        self.search.textChanged.connect(self._filters_changed)
        self.severity.currentIndexChanged.connect(lambda *_: self._filters_changed())
        self.engine.currentIndexChanged.connect(lambda *_: self._filters_changed())
        self.show_info.toggled.connect(lambda *_: self._filters_changed())
        self.show_closed.toggled.connect(lambda *_: self._filters_changed())
        self._update_details()

    # ------------------------------------------------------------ loading

    def load(self, summary: dict[str, Any], options: dict[str, Any], targets: list[dict[str, Any]],
             detections: list[dict[str, Any]], definitions: dict[str, Any] | None = None) -> None:
        """``detections``: dicts as stored in history (with ``id``/``status``) or Detection dicts."""
        rows = []
        for item in detections:
            det = Detection.from_dict(item)
            status = item.get("status") or ("false_positive" if det.details.get("false_positive") else "open")
            rows.append({"det": det, "status": status, "id": item.get("id")})
        self.model.set_rows(rows)
        self.report_data = {"summary": summary, "options": options, "targets": targets,
                            "definitions": definitions or {}}
        files = sum(1 for r in rows if r["det"].engine not in CHECK_ENGINES)
        checks = sum(1 for r in rows if r["det"].engine in CHECK_ENGINES and not r["det"].inventory)
        inventory = sum(1 for r in rows if r["det"].inventory)
        when = fmt.iso(summary.get("started", 0)) if summary.get("started") else ""
        self.summary.setText(f"{summary.get('state', '?')} scan of {', '.join(options.get('volumes', []))} "
                             f"({options.get('mode', '?')}) {when}: {summary.get('files_scanned', 0)} files, "
                             f"{files} file detections, {checks} autostart/integrity findings, "
                             f"{inventory} informational entries, {summary.get('errors', 0)} errors.")
        self.table.resizeColumnsToContents()
        if self.proxy.rowCount():
            self.table.selectRow(0)
        self._update_details()

    def _filters_changed(self) -> None:
        begin = getattr(self.proxy, "beginFilterChange", None)          # Qt >= 6.10
        if begin is not None:
            begin()
        self.proxy.text = self.search.text().strip().lower()
        self.proxy.min_rank = int(self.severity.currentData())
        self.proxy.engines = ENGINE_GROUPS[self.engine.currentText()]
        self.proxy.show_info = self.show_info.isChecked()
        self.proxy.show_closed = self.show_closed.isChecked()
        if begin is not None:
            self.proxy.endFilterChange()
        else:
            self.proxy.invalidateFilter()
        self._update_details()

    # ------------------------------------------------------------ selection

    def current(self) -> tuple[int, dict[str, Any]] | None:
        index = self.table.currentIndex()
        if not index.isValid():
            return None
        row = self.proxy.mapToSource(index).row()
        return row, self.model.rows[row]

    def _update_details(self) -> None:
        cur = self.current()
        has = cur is not None
        det: Detection | None = cur[1]["det"] if cur else None
        for act in (self.act_copy_path, self.act_open, self.act_false):
            act.setEnabled(has)
        self.act_copy_hash.setEnabled(bool(det and det.sha256))
        target, why = remedy_target(det) if det else (None, "")
        open_state = bool(cur and cur[1]["status"] in ("open", "false_positive"))
        for act in (self.act_quarantine, self.act_delete):
            act.setEnabled(bool(target) and open_state and self.bridge.is_connected)
            act.setToolTip(f"Acts on {why}" if target else why)
        self.act_export.setEnabled(self.report_data is not None)
        if det is not None:
            self.act_false.setText("Remove &false-positive mark" if cur[1]["status"] == "false_positive"
                                   else "Mark as &false positive")
        self.details.setPlainText(self._details_text(cur[1]) if cur else "")

    def _details_text(self, row: dict[str, Any]) -> str:
        det: Detection = row["det"]
        d = det.details
        lines = [f"{det.severity.upper()}: {det.signature}", f"Volume: {det.volume}",
                 f"File: {names.display(det.path) if det.path else '–'}"]
        if det.engine in CHECK_ENGINES:
            lines.append(f"Where: {safe(d.get('location'), 1000)}")
            if d.get("value"):
                lines.append(f"Value: {safe(d.get('value'), 2000)}")
            if d.get("target"):
                lines.append(f"Starts: {safe(d.get('target'), 1000)}")
            if d.get("user"):
                lines.append(f"User: {safe(d.get('user'), 200)}")
            if d.get("installation"):
                lines.append(f"Installation: {safe(d.get('installation'), 200)}")
            for reason in d.get("reasons") or []:
                lines.append(f"  • {safe(reason, 500)}")
            if d.get("mitre"):
                lines.append(f"MITRE ATT&CK: {d['mitre']}")
            if d.get("package"):
                lines.append(f"Package: {safe(d['package'], 200)}")
        lines.append(f"Engine: {det.engine}" + (f" ({det.source})" if det.source else ""))
        if det.category:
            lines.append(f"Category: {det.category}")
        if det.sha256:
            lines.append(f"SHA-256: {det.sha256}")
        if det.size is not None:
            lines.append(f"Size: {fmt.size(det.size)}")
        for key, label in (("author", "Rule author"), ("description", "Description"), ("license", "Licence"),
                           ("reference", "Reference"), ("list", "List")):
            if d.get(key):
                lines.append(f"{label}: {safe(d[key], 1000)}")
        lines.append(f"Status: {STATUS_TEXT.get(row['status'], row['status']) or 'open'}")
        return "\n".join(safe_text(line, 4000) for line in lines)

    # ------------------------------------------------------------ actions

    def copy_hash(self) -> None:
        cur = self.current()
        if cur and cur[1]["det"].sha256:
            QtWidgets.QApplication.clipboard().setText(cur[1]["det"].sha256)
            self.status_message.emit("SHA-256 copied")

    def copy_path(self) -> None:
        cur = self.current()
        if cur:
            det = cur[1]["det"]
            QtWidgets.QApplication.clipboard().setText(f"{det.volume}:{names.display(det.path or '')}")
            self.status_message.emit("Path copied")

    def open_folder(self) -> None:
        cur = self.current()
        if not cur:
            return
        det: Detection = cur[1]["det"]
        folder = posixpath.dirname(det.path or "/")

        def done(result: Any, err: BaseException | None) -> None:
            if err is not None:
                error(self, "Cannot open the folder", str(err))
                return
            local = os.path.join(result["mountpoint"], os.fsdecode(names.from_wire(folder)).lstrip("/"))
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(local))
        self.bridge.call("volume.mount", {"volume": det.volume}, done)

    def toggle_false_positive(self) -> None:
        cur = self.current()
        if not cur or self.history is None:
            return
        row_index, row = cur
        det: Detection = row["det"]
        identity = det.identity
        if not identity:
            error(self, "Cannot mark this finding", "There is no file hash or entry fingerprint to remember.")
            return
        if row["status"] == "false_positive":
            self.history.unmark_false_positive(det.engine, det.signature, identity)
            self.model.update_status(row_index, "open")
        else:
            self.history.mark_false_positive(det.engine, det.signature, identity)
            self.model.update_status(row_index, "false_positive")
        self._update_details()

    def change(self, what: str) -> None:
        cur = self.current()
        if not cur:
            return
        row_index, row = cur
        det: Detection = row["det"]
        path, why = remedy_target(det)
        if path is None:
            info(self, "Nothing to remove", why)
            return

        def planned(p: Any, err: BaseException | None) -> None:
            if err is not None:
                error(self, "Cannot change this file", str(err))
                return
            lines = remediation.explain(p, what)
            lines.insert(1, f"This is {why}.")
            if not p.get("possible"):
                error(self, "Not possible", "\n".join(lines))
                return
            if det.sha256 and det.engine not in CHECK_ENGINES and p["sha256"] != det.sha256:
                lines.append("Note: the file's SHA-256 differs from the one scanned.")
            dialog = ConfirmChangeDialog(remediation.ACTIONS[what], lines, remediation.ACTIONS[what],
                                         p.get("needs_secret") or [], self)
            if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            self.status_message.emit("Changing the drive…")
            params = {"volume": p["volume"], "path": p["path"], "expect_sha256": p["sha256"], "action": what,
                      "confirm": True}
            secrets = dialog.secret_values()
            if secrets:
                params["secrets"] = secrets

            def applied(record: Any, err2: BaseException | None) -> None:
                if err2 is not None:
                    message = err2.message if isinstance(err2, RemoteError) else str(err2)
                    error(self, "The change was not made", message)
                    return
                status = "quarantined" if what == "quarantine" else "deleted"
                self.model.update_status(row_index, status)
                if self.history is not None and row.get("id") is not None:
                    self.history.set_status(int(row["id"]), status)
                self.status_message.emit(remediation.describe_record(record))
                if record.get("restore_errors"):
                    error(self, "Done, with a problem", remediation.describe_record(record))
                self._update_details()
            self.bridge.call("remedy.apply", params, applied)
        self.bridge.call("remedy.plan", {"volume": det.volume, "path": path}, planned)

    def export(self) -> None:
        if self.report_data is None:
            return
        path, chosen = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export report", os.path.expanduser("~/scan-report.html"),
            "HTML report (*.html);;JSON (*.json);;CSV (*.csv)")
        if not path:
            return
        kind = {"JSON (*.json)": "json", "CSV (*.csv)": "csv"}.get(chosen, "html")
        if not path.lower().endswith(f".{kind}"):
            path += f".{kind}"
        dets = []
        for row in self.model.rows:
            item = row["det"].to_dict()
            item["status"] = row["status"]
            dets.append(item)
        data = self.report_data
        report = reports.build(data["summary"], data["options"], data["targets"], dets, data["definitions"])
        try:
            reports.write(report, path, kind)
        except OSError as exc:
            error(self, "Could not save the report", str(exc))
            return
        self.status_message.emit(f"Report saved to {path}")
