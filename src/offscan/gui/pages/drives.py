"""Drives: disks and volumes, unlocking, LVM, read-only mounting, choosing what to scan."""

from __future__ import annotations

from typing import Any

from ... import fmt
from ..bridge import Bridge
from ..qt import QtCore, QtGui, QtWidgets, Signal
from ..theme import icon
from ..widgets import Busy, SecretDialog, action, button, error, heading, plain_label, safe, safe_text

Qt = QtCore.Qt
ROLE = Qt.ItemDataRole.UserRole
SCANNABLE = ("filesystem",)


def _volume_title(vol: dict[str, Any]) -> str:
    label = vol.get("label")
    return f"{vol['device']}" + (f"  “{safe(label, 80)}”" if label else "")


def _os_text(vol: dict[str, Any]) -> str:
    os_info = vol.get("os") or {}
    if not os_info:
        return ""
    text = os_info.get("name") or ""
    if os_info.get("version"):
        text += f" {os_info['version']}"
    return safe(text, 120)


def _status(vol: dict[str, Any]) -> str:
    parts = []
    enc = vol.get("encryption")
    if enc:
        parts.append("unlocked" if enc.get("unlocked") else "locked")
    if vol.get("mountpoint"):
        parts.append("mounted read-only")
    if vol.get("system"):
        parts.append("running system")
    elif vol.get("host_mounts"):
        parts.append("in use by this computer")
    if (vol.get("hibernation") or {}).get("hibernated"):
        parts.append("hibernated")
    if vol.get("warnings"):
        parts.append(f"{len(vol['warnings'])} warning(s)")
    return ", ".join(parts)


class DrivesPage(QtWidgets.QWidget):
    scan_requested = Signal(list)              # [volume dicts]
    selection_changed = Signal(list)

    def __init__(self, bridge: Bridge, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.bridge = bridge
        self.disks: list[dict[str, Any]] = []
        self.checked: set[str] = set()
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(heading("Drives"))
        layout.addWidget(plain_label(
            "Drives are only ever mounted read-only. Pick the volumes to scan. Encrypted volumes need "
            "their passphrase or BitLocker recovery key."))
        self.connect_box = QtWidgets.QWidget()
        cbox = QtWidgets.QHBoxLayout(self.connect_box)
        cbox.setContentsMargins(0, 0, 0, 0)
        cbox.addWidget(plain_label("Reading drives needs administrator rights. You will be asked for "
                                   "your password once for this session."), 1)
        self.connect_button = button("&Continue", self.bridge.connect_helper,
                                     ("dialog-password", "system-lock-screen"), default=True)
        cbox.addWidget(self.connect_button)
        layout.addWidget(self.connect_box)

        self.toolbar = QtWidgets.QToolBar("Drive actions")
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.act_refresh = action(self, "&Refresh", self.refresh, ("view-refresh",),
                                  QtGui.QKeySequence.StandardKey.Refresh, "Look for drives again",
                                  QtWidgets.QStyle.StandardPixmap.SP_BrowserReload)
        self.act_unlock = action(self, "&Unlock…", self.unlock, ("changes-allow", "unlock"), "Ctrl+U",
                                 "Open an encrypted volume read-only")
        self.act_lock = action(self, "&Lock", self.lock, ("changes-prevent", "lock"), "Ctrl+L",
                               "Close an unlocked volume")
        self.act_lvm = action(self, "Activate &LVM", self.activate_lvm, ("drive-multidisk",), None,
                              "Open the logical volumes of an LVM physical volume (read-only)")
        self.act_mount = action(self, "&Mount", self.mount, ("media-mount",), "Ctrl+M",
                                "Mount read-only to look at the files")
        self.act_unmount = action(self, "U&nmount", self.unmount, ("media-eject",), None, "Unmount")
        self.act_open = action(self, "&Open folder", self.open_folder, ("folder-open",), "Ctrl+O",
                               "Show the read-only files in the file manager",
                               QtWidgets.QStyle.StandardPixmap.SP_DirOpenIcon)
        for act in (self.act_refresh, self.act_unlock, self.act_lock, self.act_lvm, self.act_mount,
                    self.act_unmount, self.act_open):
            self.toolbar.addAction(act)
            self.addAction(act)
        layout.addWidget(self.toolbar)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setAccessibleName("Drives and volumes")
        self.tree.setHeaderLabels(["Volume", "Size", "Filesystem", "System found", "Status"])
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemChanged.connect(self._item_changed)
        self.tree.currentItemChanged.connect(lambda *_: self._update_details())
        self.tree.itemActivated.connect(lambda item, _col: self._toggle(item))
        layout.addWidget(self.tree, 1)
        self.details = plain_label("", selectable=True)
        self.details.setAccessibleName("Details of the selected volume")
        layout.addWidget(self.details)
        bottom = QtWidgets.QHBoxLayout()
        self.busy = Busy()
        bottom.addWidget(self.busy, 1)
        self.scan_button = button("&Scan selected…", self._scan, ("system-search", "edit-find"),
                                  tip="Set up a scan of the ticked volumes (Ctrl+Enter)")
        self.scan_button.setShortcut(QtGui.QKeySequence("Ctrl+Return"))
        bottom.addWidget(self.scan_button)
        layout.addLayout(bottom)
        bridge.connected.connect(lambda _info: self._on_connected())
        bridge.connection_failed.connect(self._on_connect_failed)
        self._set_connected(bridge.is_connected)

    # ------------------------------------------------------------ state

    def _set_connected(self, on: bool) -> None:
        self.connect_box.setVisible(not on)
        for widget in (self.toolbar, self.tree, self.scan_button):
            widget.setEnabled(on)
        self._update_actions()

    def _on_connected(self) -> None:
        self._set_connected(True)
        self.connect_button.setEnabled(True)
        self.refresh()

    def _on_connect_failed(self, message: str) -> None:
        self.connect_button.setEnabled(True)
        self.busy.stop()
        error(self, "Could not get administrator rights", message)

    def refresh(self, probe: str = "cached") -> None:
        if not self.bridge.is_connected:
            self.bridge.connect_helper()
            return
        self.busy.start("Looking for drives…")
        self.act_refresh.setEnabled(False)

        def done(result: Any, err: BaseException | None) -> None:
            self.act_refresh.setEnabled(True)
            if err is not None:
                self.busy.stop()
                error(self, "Could not list drives", str(err))
                return
            self.set_disks(result["disks"])
            if probe == "cached":
                self.busy.start("Detecting installed systems…")
                self.refresh_probe()
            else:
                self.busy.stop()
        self.bridge.call("drives.list", {"probe": probe}, done)

    def refresh_probe(self) -> None:
        def done(result: Any, err: BaseException | None) -> None:
            self.busy.stop()
            if err is None:
                self.set_disks(result["disks"])
        self.bridge.call("drives.list", {"probe": "wait"}, done)

    def set_disks(self, disks: list[dict[str, Any]]) -> None:
        current = self.current_volume()
        self.disks = disks
        self.tree.blockSignals(True)
        self.tree.clear()
        present: set[str] = set()
        for disk in disks:
            title = " ".join(x for x in (disk.get("vendor"), disk.get("model")) if x) or disk["device"]
            flags = [f for f, on in (("removable", disk.get("removable")),
                                     ("running system", disk.get("system")),
                                     ("live USB", disk.get("live_medium"))) if on]
            item = QtWidgets.QTreeWidgetItem([safe(title, 120) + (f"  ({', '.join(flags)})" if flags else ""),
                                              fmt.size(disk.get("size"))])
            item.setIcon(0, icon("drive-removable-media" if disk.get("removable") else "drive-harddisk",
                                 fallback=QtWidgets.QStyle.StandardPixmap.SP_DriveHDIcon))
            item.setData(0, ROLE, {"kind": "disk", **disk})
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
            self.tree.addTopLevelItem(item)
            for vol in disk.get("volumes", []):
                self._add_volume(item, vol, present)
            item.setExpanded(True)
        self.checked &= present
        self.tree.blockSignals(False)
        for col in range(5):
            self.tree.resizeColumnToContents(col)
        if current:
            self._select(current["id"])
        self._update_details()
        self.selection_changed.emit(self.selected_volumes())

    def _add_volume(self, parent: QtWidgets.QTreeWidgetItem, vol: dict[str, Any], present: set[str]) -> None:
        fs = vol.get("fstype") or ""
        if vol.get("encryption"):
            fs = f"{fs} ({vol['encryption'].get('kind')})"
        item = QtWidgets.QTreeWidgetItem([_volume_title(vol), fmt.size(vol.get("size")), safe(fs, 40),
                                          _os_text(vol), _status(vol)])
        item.setData(0, ROLE, {"kind": "volume", **vol})
        names = {"luks": "drive-harddisk-encrypted", "bitlocker": "drive-harddisk-encrypted"}
        item.setIcon(0, icon(names.get(vol.get("role", ""), "drive-partition"), "drive-harddisk",
                             fallback=QtWidgets.QStyle.StandardPixmap.SP_DriveHDIcon))
        if vol.get("warnings"):
            item.setIcon(4, icon("dialog-warning",
                                 fallback=QtWidgets.QStyle.StandardPixmap.SP_MessageBoxWarning))
        if vol.get("role") in SCANNABLE:
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            state = Qt.CheckState.Checked if vol["id"] in self.checked else Qt.CheckState.Unchecked
            item.setCheckState(0, state)
            present.add(vol["id"])
        parent.addChild(item)
        for child in vol.get("children", []):
            self._add_volume(item, child, present)
        item.setExpanded(True)

    def _items(self) -> list[QtWidgets.QTreeWidgetItem]:
        out: list[QtWidgets.QTreeWidgetItem] = []

        def walk(item: QtWidgets.QTreeWidgetItem) -> None:
            out.append(item)
            for i in range(item.childCount()):
                walk(item.child(i))
        for i in range(self.tree.topLevelItemCount()):
            walk(self.tree.topLevelItem(i))
        return out

    def _select(self, volume_id: str) -> None:
        for item in self._items():
            data = item.data(0, ROLE) or {}
            if data.get("kind") == "volume" and data.get("id") == volume_id:
                self.tree.setCurrentItem(item)
                return

    def _item_changed(self, item: QtWidgets.QTreeWidgetItem, column: int) -> None:
        data = item.data(0, ROLE) or {}
        if column != 0 or data.get("kind") != "volume":
            return
        if item.checkState(0) == Qt.CheckState.Checked:
            self.checked.add(data["id"])
        else:
            self.checked.discard(data["id"])
        self.selection_changed.emit(self.selected_volumes())

    def _toggle(self, item: QtWidgets.QTreeWidgetItem) -> None:
        if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
            item.setCheckState(0, Qt.CheckState.Unchecked if item.checkState(0) == Qt.CheckState.Checked
                               else Qt.CheckState.Checked)

    def selected_volumes(self) -> list[dict[str, Any]]:
        out = []
        for item in self._items():
            data = item.data(0, ROLE) or {}
            if data.get("kind") == "volume" and data.get("id") in self.checked:
                out.append(data)
        return out

    def current_volume(self) -> dict[str, Any] | None:
        item = self.tree.currentItem()
        data = item.data(0, ROLE) if item is not None else None
        return data if data and data.get("kind") == "volume" else None

    def _update_details(self) -> None:
        vol = self.current_volume()
        self._update_actions()
        if vol is None:
            self.details.setText("")
            return
        lines = [f"{vol['device']}: {fmt.size(vol.get('size'))} {vol.get('fstype') or 'unknown contents'}"]
        if vol.get("uuid"):
            lines.append(f"UUID {vol['uuid']}")
        if vol.get("mountpoint"):
            lines.append(f"Mounted read-only at {vol['mountpoint']}")
        for warning in vol.get("warnings", []):
            lines.append("⚠ " + warning.get("message", ""))
        self.details.setText(safe_text("\n".join(lines)))

    def _update_actions(self) -> None:
        vol = self.current_volume() if self.bridge.is_connected else None
        role = (vol or {}).get("role")
        enc = (vol or {}).get("encryption") or {}
        self.act_unlock.setEnabled(bool(vol) and role in ("luks", "bitlocker") and not enc.get("unlocked"))
        self.act_lock.setEnabled(bool(vol) and role in ("luks", "bitlocker") and bool(enc.get("unlocked")))
        self.act_lvm.setEnabled(bool(vol) and role == "lvm_pv" and not (vol or {}).get("children"))
        mounted = bool((vol or {}).get("mountpoint"))
        self.act_mount.setEnabled(bool(vol) and role == "filesystem" and not mounted)
        self.act_unmount.setEnabled(mounted)
        self.act_open.setEnabled(mounted)

    # ------------------------------------------------------------ actions

    def _after(self, title: str, refresh: bool = True):
        def done(_result: Any, err: BaseException | None) -> None:
            self.busy.stop()
            if err is not None:
                error(self, title, str(err))
            if refresh:
                self.refresh()
        return done

    def unlock(self) -> None:
        vol = self.current_volume()
        if vol is None:
            return
        kind = (vol.get("encryption") or {}).get("kind", vol.get("role", ""))
        dialog = SecretDialog(vol["device"], kind, self)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        secret, kind = dialog.value()
        self.busy.start("Unlocking (read-only)…")
        self.bridge.call("volume.unlock", {"volume": vol["id"], "secret": secret, "secret_kind": kind},
                         self._after("Could not unlock"))

    def lock(self) -> None:
        vol = self.current_volume()
        if vol is not None:
            self.busy.start("Closing…")
            self.bridge.call("volume.lock", {"volume": vol["id"]}, self._after("Could not lock"))

    def activate_lvm(self) -> None:
        vol = self.current_volume()
        if vol is not None:
            self.busy.start("Opening logical volumes (read-only)…")
            self.bridge.call("volume.activate_lvm", {"volume": vol["id"]},
                             self._after("Could not activate LVM"))

    def mount(self) -> None:
        vol = self.current_volume()
        if vol is not None:
            self.busy.start("Mounting read-only…")
            self.bridge.call("volume.mount", {"volume": vol["id"]}, self._after("Could not mount"))

    def unmount(self) -> None:
        vol = self.current_volume()
        if vol is not None:
            self.busy.start("Unmounting…")
            self.bridge.call("volume.unmount", {"volume": vol["id"]}, self._after("Could not unmount"))

    def open_folder(self) -> None:
        vol = self.current_volume()
        if vol and vol.get("mountpoint"):
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(vol["mountpoint"]))

    def _scan(self) -> None:
        volumes = self.selected_volumes()
        if not volumes:
            current = self.current_volume()
            if current and current.get("role") in SCANNABLE:
                volumes = [current]
        if not volumes:
            error(self, "Nothing selected", "Tick at least one volume to scan.")
            return
        self.scan_requested.emit(volumes)
