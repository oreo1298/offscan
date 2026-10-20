"""History: past scans, the quarantine and the log of changes made to drives."""

from __future__ import annotations

from typing import Any

from ... import fmt, remediation
from ...history import History
from ...protocol import RemoteError
from ..bridge import Bridge
from ..qt import QtCore, QtWidgets, Signal
from ..widgets import ConfirmChangeDialog, ask, button, error, heading, info, plain_label, safe, safe_text

Qt = QtCore.Qt
ROLE = Qt.ItemDataRole.UserRole


def _table(columns: tuple[str, ...], name: str) -> QtWidgets.QTableWidget:
    table = QtWidgets.QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.setAccessibleName(name)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.setSortingEnabled(True)
    return table


def _fill(table: QtWidgets.QTableWidget, rows: list[tuple[Any, list[str]]]) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(0)
    for data, values in rows:
        r = table.rowCount()
        table.insertRow(r)
        for c, text in enumerate(values):
            item = QtWidgets.QTableWidgetItem(text)
            if c == 0:
                item.setData(ROLE, data)
            table.setItem(r, c, item)
    table.setSortingEnabled(True)
    table.resizeColumnsToContents()


def _selected(table: QtWidgets.QTableWidget) -> Any:
    row = table.currentRow()
    item = table.item(row, 0) if row >= 0 else None
    return item.data(ROLE) if item is not None else None


class HistoryPage(QtWidgets.QWidget):
    open_scan = Signal(object)              # scan record with detections

    def __init__(self, bridge: Bridge, history: History | None,
                 parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.bridge = bridge
        self.history = history
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("History"))
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setAccessibleName("History sections")
        layout.addWidget(self.tabs, 1)

        scans = QtWidgets.QWidget()
        sl = QtWidgets.QVBoxLayout(scans)
        self.scans = _table(("Started", "Volumes", "Mode", "Result", "Findings", "Duration"),
                            "Past scans")
        self.scans.itemActivated.connect(lambda *_: self._open())
        sl.addWidget(self.scans, 1)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(button("&Open results", self._open, ("document-open",), default=True))
        row.addWidget(button("&Delete from history", self._delete, ("edit-delete",)))
        row.addStretch(1)
        sl.addLayout(row)
        self.tabs.addTab(scans, "&Scans")

        quarantine = QtWidgets.QWidget()
        ql = QtWidgets.QVBoxLayout(quarantine)
        ql.addWidget(plain_label("Quarantined files are kept, scrambled, in a folder only the "
                                 "administrator can read. Restore puts a file back where it was."))
        self.quarantine = _table(("Quarantined", "Volume", "Path", "Size", "SHA-256"),
                                 "Quarantined files")
        ql.addWidget(self.quarantine, 1)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(button("&Refresh", self.refresh_remote, ("view-refresh",)))
        row.addWidget(button("R&estore…", self._restore, ("edit-undo",)))
        row.addWidget(button("Delete &permanently…", self._purge, ("edit-delete",)))
        row.addStretch(1)
        ql.addLayout(row)
        self.tabs.addTab(quarantine, "&Quarantine")

        changes = QtWidgets.QWidget()
        cl = QtWidgets.QVBoxLayout(changes)
        cl.addWidget(plain_label("Every change made to a drive (quarantine, delete, restore) is "
                                 "recorded here, with the file's hash and how the drive was mounted."))
        self.changes = _table(("When", "Action", "Volume", "Path", "Result"), "Change log")
        self.changes.currentCellChanged.connect(lambda *_: self._change_details())
        cl.addWidget(self.changes, 1)
        self.change_info = plain_label("", selectable=True)
        self.change_info.setAccessibleName("Details of the selected change")
        cl.addWidget(self.change_info)
        self.tabs.addTab(changes, "&Change log")
        self.tabs.currentChanged.connect(lambda index: self.refresh_remote() if index else None)
        self.refresh()

    # ------------------------------------------------------------ scans

    def refresh(self) -> None:
        if self.history is None:
            return
        rows = []
        for scan in self.history.scans():
            summary = scan.get("summary") or {}
            vols = ", ".join(t.get("volume", "?") for t in scan.get("targets") or []) or \
                ", ".join((scan.get("options") or {}).get("volumes", []))
            took = fmt.duration((scan.get("finished") or 0) - (scan.get("started") or 0))
            rows.append((scan, [fmt.iso(scan["started"]), safe(vols, 200), scan.get("mode", "?"),
                                scan.get("state", "?"), str(summary.get("detections", 0)), took]))
        _fill(self.scans, rows)

    def _open(self) -> None:
        scan = _selected(self.scans)
        if scan is None or self.history is None:
            return
        self.open_scan.emit({**scan, "detections": self.history.detections(int(scan["id"]))})

    def _delete(self) -> None:
        scan = _selected(self.scans)
        if scan is None or self.history is None:
            return
        if ask(self, "Delete from history",
               f"Delete the scan of {fmt.iso(scan['started'])} from the history? Reports you "
               "saved are not affected.", "Delete"):
            self.history.delete_scan(int(scan["id"]))
            self.refresh()

    # ------------------------------------------------------------ helper-side lists

    def refresh_remote(self) -> None:
        if not self.bridge.is_connected:
            return

        def got_entries(result: Any, err: BaseException | None) -> None:
            if err is not None:
                return
            rows = [(e, [fmt.iso(e.get("time", 0)), e.get("volume") or "?", safe(e.get("path"), 300),
                         fmt.size(e.get("size")), e.get("sha256", "")])
                    for e in result.get("entries", [])]
            _fill(self.quarantine, rows)

        def got_changes(result: Any, err: BaseException | None) -> None:
            if err is not None:
                return
            rows = []
            for c in reversed(result.get("changes", [])):
                status = "ok" if c.get("result") == "ok" else f"failed: {safe(c.get('error'), 200)}"
                rows.append((c, [fmt.iso(c.get("time", 0)), c.get("action", "?"), c.get("volume") or "?",
                                 safe(c.get("path"), 300), status]))
            _fill(self.changes, rows)
        self.bridge.call("quarantine.list", {}, got_entries)
        self.bridge.call("changes.list", {"limit": 500}, got_changes)

    def _change_details(self) -> None:
        c = _selected(self.changes)
        if not c:
            self.change_info.setText("")
            return
        mount = c.get("mount") or {}
        lines = [f"{c.get('action')} {c.get('path')} on {c.get('volume')} ({c.get('device')}, "
                 f"{c.get('fstype')}, UUID {c.get('uuid')})",
                 f"SHA-256 {c.get('sha256')}, {fmt.size(c.get('size'))}, mode "
                 f"{oct(int(c['mode']) & 0o7777) if c.get('mode') is not None else '?'}",
                 f"Mounted writable with {mount.get('driver')} ({', '.join(mount.get('options') or [])})"]
        if c.get("journal_replayed"):
            lines.append("The filesystem journal was replayed when it was mounted writable.")
        if c.get("quarantine_id"):
            lines.append(f"Quarantine id {c['quarantine_id']}")
        if c.get("error"):
            lines.append(f"Error: {c['error']}")
        self.change_info.setText(safe_text("\n".join(lines)))

    def _restore(self) -> None:
        entry = _selected(self.quarantine)
        if entry is None:
            return
        volume = entry.get("volume") or ""

        def planned(p: Any, err: BaseException | None) -> None:
            if err is not None:
                error(self, "Cannot restore", str(err))
                return
            if not p.get("possible"):
                error(self, "Not possible", p.get("reason", ""))
                return
            lines = [f"Restore {safe(entry['path'], 500)} to volume {volume}.",
                     f"{fmt.size(entry.get('size'))}, SHA-256 {entry['sha256']}",
                     "The volume is mounted read-write just for this change, then read-only again.",
                     *p.get("notes", []),
                     "The file comes back with its original permissions. It was quarantined for a "
                     "reason: restore it only if you are sure it is safe."]
            dialog = ConfirmChangeDialog("Restore from quarantine", lines, "Restore",
                                         p.get("needs_secret") or [], self)
            if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            params: dict[str, Any] = {"id": entry["id"], "volume": volume, "confirm": True}
            if dialog.secret_values():
                params["secrets"] = dialog.secret_values()

            def done(record: Any, err2: BaseException | None) -> None:
                if err2 is not None:
                    message = err2.message if isinstance(err2, RemoteError) else str(err2)
                    error(self, "The file was not restored", message)
                else:
                    info(self, "Restored", remediation.describe_record(record))
                self.refresh_remote()
            self.bridge.call("quarantine.restore", params, done)
        self.bridge.call("remedy.plan", {"volume": volume}, planned)

    def _purge(self) -> None:
        entry = _selected(self.quarantine)
        if entry is None:
            return
        if not ask(self, "Delete permanently",
                   f"Delete the quarantined copy of {safe(entry['path'], 500)} for good? It cannot "
                   "be restored afterwards.", "Delete"):
            return

        def done(_r: Any, err: BaseException | None) -> None:
            if err is not None:
                error(self, "Could not delete", str(err))
            self.refresh_remote()
        self.bridge.call("quarantine.purge", {"id": entry["id"], "confirm": True}, done)
