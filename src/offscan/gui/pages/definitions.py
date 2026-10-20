"""Definitions: sources, updates, rollback and offline bundles.

This page is the only part of the program that uses the network, and only
to download from the sources listed here.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from ... import fmt
from ...defs import bundle
from ...defs.updater import Updater
from ...settings import Settings
from ..bridge import Bridge
from ..qt import QtCore, QtWidgets, Signal
from ..widgets import Busy, ask, button, error, heading, info, plain_label, safe, safe_text

Qt = QtCore.Qt
ROLE = Qt.ItemDataRole.UserRole
COLUMNS = ("Use", "Source", "Kind", "Version", "Last update", "Status", "Licence")
BUNDLE_FILTER = "Definition bundles (*.offscan-bundle);;All files (*)"


class DefinitionsPage(QtWidgets.QWidget):
    changed = Signal()                      # active set changed

    def __init__(self, bridge: Bridge, settings: Settings, parent: QtWidgets.QWidget | None = None,
                 updater_factory: Any = None):
        super().__init__(parent)
        self.bridge = bridge
        self.settings = settings
        self.updater_factory = updater_factory or (lambda: Updater(settings=self.settings))
        self.cancel_event: threading.Event | None = None
        self.status: dict[str, Any] = {}
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("Definitions"))
        layout.addWidget(plain_label(
            "Malware definitions come from the public sources below. Updating downloads only from them; "
            "the program sends nothing else anywhere. On a computer without internet, import an offline "
            "bundle made on another one."))
        self.active = plain_label("", selectable=True)
        self.active.setAccessibleName("Active definition set")
        layout.addWidget(self.active)
        self.table = QtWidgets.QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setAccessibleName("Definition sources")
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemChanged.connect(self._item_changed)
        self.table.currentCellChanged.connect(lambda *_: self._show_source())
        layout.addWidget(self.table, 2)
        self.source_info = plain_label("", selectable=True)
        self.source_info.setAccessibleName("About the selected source")
        layout.addWidget(self.source_info)
        row = QtWidgets.QHBoxLayout()
        self.update_button = button("&Update now", lambda: self.update(force=False),
                                    ("system-software-update",), default=True, tip="Download what is due")
        self.force_button = button("Update &all", lambda: self.update(force=True), ("view-refresh",),
                                   tip="Check every enabled source now")
        self.cancel_button = button("&Cancel", self._cancel, ("process-stop",))
        self.rollback_button = button("&Roll back", self.rollback, ("edit-undo",),
                                      tip="Go back to the previous definition set")
        self.export_button = button("&Export bundle…", self.export_bundle, ("document-save-as",),
                                    tip="Save the definitions for a computer without internet")
        self.import_button = button("&Import bundle…", self.import_bundle, ("document-open",))
        for widget in (self.update_button, self.force_button, self.cancel_button, self.rollback_button,
                       self.export_button, self.import_button):
            row.addWidget(widget)
        row.addStretch(1)
        layout.addLayout(row)
        self.busy = Busy()
        layout.addWidget(self.busy)
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setAccessibleName("Update messages")
        self.log.setMaximumBlockCount(2000)
        layout.addWidget(self.log, 1)
        self._set_working(False)
        self.reload()

    # ------------------------------------------------------------ status

    def _set_working(self, working: bool) -> None:
        for widget in (self.update_button, self.force_button, self.rollback_button, self.export_button,
                       self.import_button, self.table):
            widget.setEnabled(not working)
        self.cancel_button.setEnabled(working)
        if not working:
            self.busy.stop()

    def reload(self) -> None:
        self.bridge.run_in_thread(lambda: self.updater_factory().status(), self._status_loaded, "defs-status")

    def _status_loaded(self, status: Any, err: BaseException | None) -> None:
        if err is not None:
            self.active.setText(f"Could not read the definition store: {safe(err)}")
            return
        self.status = status
        active = status.get("active")
        if active:
            self.active.setText(
                f"Active set {active['id']} from {fmt.iso(active.get('created') or 0)} "
                f"({fmt.age(active.get('created'))}): {active.get('yara_rules') or 0} YARA rules, "
                f"{active.get('hashes') or 0} hashes, {active.get('clamav_files') or 0} ClamAV files"
                + (" + system ClamAV signatures" if active.get("clamav_official") else "")
                + (f". Previous set {status['previous']} kept for rollback."
                   if status.get("previous") else ""))
        else:
            self.active.setText("No definitions are installed yet. Press “Update now”.")
        self.rollback_button.setEnabled(bool(status.get("previous")) and self.cancel_event is None)
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for src in status.get("sources", []):
            r = self.table.rowCount()
            self.table.insertRow(r)
            use = QtWidgets.QTableWidgetItem()
            use.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                         | Qt.ItemFlag.ItemIsSelectable)
            use.setCheckState(Qt.CheckState.Checked if src.get("enabled") else Qt.CheckState.Unchecked)
            use.setData(ROLE, src)
            use.setData(Qt.ItemDataRole.AccessibleTextRole, f"use {src['name']}")
            state = "error: " + safe(src["error"], 200) if src.get("error") else \
                "not set up: " + safe(src.get("configure_hint"), 200) if not src.get("configured") else \
                "waiting (rate limit)" if src.get("cooldown_until") else "ok" if src.get("version") else ""
            values = [safe(src["name"], 120), src.get("kind", ""), safe(src.get("version") or "–", 60),
                      fmt.age(src.get("updated")) if src.get("updated") else "never", state,
                      safe(src.get("license"), 80)]
            self.table.setItem(r, 0, use)
            for c, text in enumerate(values, start=1):
                self.table.setItem(r, c, QtWidgets.QTableWidgetItem(text))
        self.table.blockSignals(False)
        self.table.resizeColumnsToContents()
        self._show_source()

    def _source(self, row: int) -> dict[str, Any] | None:
        item = self.table.item(row, 0)
        return item.data(ROLE) if item is not None else None

    def _show_source(self) -> None:
        src = self._source(self.table.currentRow())
        if not src:
            self.source_info.setText("")
            return
        lines = [f"{src['name']} — {src.get('homepage', '')}", f"Licence: {src.get('license')} "
                 f"({src.get('license_url', '')})"]
        for key, label in (("terms", "Terms"), ("warning", "Note"), ("integrity", "Verification"),
                           ("size_hint", "Size")):
            if src.get(key):
                lines.append(f"{label}: {src[key]}")
        if src.get("next_check"):
            lines.append(f"Next check: {fmt.iso(src['next_check'])}")
        self.source_info.setText(safe_text("\n".join(lines)))

    def _item_changed(self, item: QtWidgets.QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        src = item.data(ROLE) or {}
        on = item.checkState() == Qt.CheckState.Checked
        if on and src.get("requires_acceptance") and not src.get("accepted_license"):
            text = (f"{src['name']} is published under {src.get('license')}.\n\n{src.get('terms', '')}\n\n"
                    f"{src.get('license_url', '')}\n\nAccept these terms and use this source?")
            if not ask(self, "Licence terms", text, "Accept"):
                self.table.blockSignals(True)
                item.setCheckState(Qt.CheckState.Unchecked)
                self.table.blockSignals(False)
                return
            self.settings.set_source(src["id"], accepted_license=True)
        if on and src.get("requires_secret") and not src.get("configured"):
            key, ok = QtWidgets.QInputDialog.getText(self, "Access key needed",
                                                     f"{src['name']} needs a personal key "
                                                     f"({src['requires_secret']}). Enter it:",
                                                     QtWidgets.QLineEdit.EchoMode.Password)
            if not ok or not key.strip():
                self.table.blockSignals(True)
                item.setCheckState(Qt.CheckState.Unchecked)
                self.table.blockSignals(False)
                return
            self.settings.set_secret(src["requires_secret"], key.strip())
        self.settings.set_source(src["id"], enabled=on)
        self.settings.save()
        self.reload()

    # ------------------------------------------------------------ work

    def _progress(self, sid: str, message: str) -> None:
        text = f"{sid}: {message}" if sid else message
        self.bridge.deliver(lambda _r, _e: (self.log.appendPlainText(safe(text, 1000)),
                                            self.busy.start(safe(text, 200))))

    def update(self, force: bool) -> None:
        self.cancel_event = threading.Event()
        self._set_working(True)
        self.busy.start("Updating definitions…")
        self.log.appendPlainText("— update started —")
        cancel = self.cancel_event

        def work() -> dict[str, Any]:
            return self.updater_factory().update(force=force, progress=self._progress, cancel=cancel)

        def done(report: Any, err: BaseException | None) -> None:
            self.cancel_event = None
            self._set_working(False)
            if err is not None:
                self.log.appendPlainText(f"Update failed: {safe(err, 1000)}")
                error(self, "Update failed", str(err))
            else:
                results = report.get("sources", {})
                for sid, result in results.items():
                    message = safe(result.get("message", ""), 300)
                    self.log.appendPlainText(f"{sid}: {result.get('result')} {message}")
                if report.get("set"):
                    self.log.appendPlainText(f"New definition set {report['set'].get('id')} is active.")
                    self.changed.emit()
            self.reload()
        self.bridge.run_in_thread(work, done, "defs-update")

    def _cancel(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.busy.start("Cancelling…")

    def rollback(self) -> None:
        if not ask(self, "Roll back", "Go back to the previous definition set?", "Roll back"):
            return

        def done(_r: Any, err: BaseException | None) -> None:
            if err is not None:
                error(self, "Rollback failed", str(err))
            else:
                self.changed.emit()
            self.reload()
        self.bridge.run_in_thread(lambda: self.updater_factory().rollback(), done, "defs-rollback")

    def export_bundle(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export offline bundle",
                                                        os.path.expanduser("~/definitions.offscan-bundle"),
                                                        BUNDLE_FILTER)
        if not path:
            return
        self._set_working(True)
        self.busy.start("Writing the bundle…")

        def done(result: Any, err: BaseException | None) -> None:
            self._set_working(False)
            if err is not None:
                error(self, "Export failed", str(err))
                return
            fpr = bundle.format_fingerprint(bundle.own_fingerprint())
            info(self, "Bundle saved", f"Saved to {path}.\n\nOn the other computer, trust this signing key "
                                       f"when asked:\n{fpr}")
        self.bridge.run_in_thread(lambda: bundle.export(Path(path), self.updater_factory()), done,
                                  "defs-export")

    def import_bundle(self, trust: str | None = None, path: str | None = None) -> None:
        if path is None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Import offline bundle",
                                                            os.path.expanduser("~"), BUNDLE_FILTER)
        if not path:
            return
        self._set_working(True)
        self.busy.start("Checking and importing the bundle…")

        def done(result: Any, err: BaseException | None) -> None:
            self._set_working(False)
            if isinstance(err, bundle.UntrustedKey):
                fpr = bundle.format_fingerprint(err.fingerprint)
                if ask(self, "Unknown signing key",
                       f"The bundle is signed by a key this computer does not know yet:\n\n{fpr}\n\n"
                       "Compare it with the fingerprint shown on the computer that made the bundle. "
                       "Trust it?", "Trust"):
                    self.import_bundle(trust=err.fingerprint, path=path)
                return
            if err is not None:
                error(self, "Import failed", str(err))
                return
            self.log.appendPlainText(f"Imported bundle {safe(path)}")
            self.changed.emit()
            self.reload()
        def work() -> dict[str, Any]:
            return bundle.import_bundle(Path(path), self.updater_factory(), trust=trust)
        self.bridge.run_in_thread(work, done, "defs-import")

    def own_fingerprint(self) -> str:
        return bundle.format_fingerprint(bundle.own_fingerprint())

