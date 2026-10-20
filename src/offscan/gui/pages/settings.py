"""Settings and About."""

from __future__ import annotations

import platform
from typing import Any

from ... import appinfo
from ...settings import SECRET_KEYS, Settings
from ..qt import BINDING, BINDING_VERSION, QtCore, QtWidgets, Signal
from ..widgets import button, heading, plain_label

Qt = QtCore.Qt
CLAMAV_MODES = (
    ("auto", "Automatic: use the system's ClamAV signatures if they are kept up to date, "
             "otherwise download them"),
    ("system", "Always use the system's ClamAV signatures (/var/lib/clamav)"),
    ("private", "Download ClamAV's official signatures for this user (freshclam)"),
    ("off", "Do not use ClamAV's official signatures"),
)
SECRET_LABELS = {
    "abusech_auth_key": "abuse.ch Auth-Key (MalwareBazaar, URLhaus…)",
    "securiteinfo_id": "SecuriteInfo customer ID",
    "malshare_api_key": "MalShare API key",
    "github_token": "GitHub token (only to avoid rate limits)",
}
THIRD_PARTY = """\
This program is free software: GPL-3.0-or-later.

It uses, without bundling their data: ClamAV (GPL-2.0, run as a separate program, never linked),
YARA-X (BSD-3-Clause) or YARA (Apache-2.0), regipy (MIT), the Qt toolkit through PySide6 (LGPL-3.0)
or PyQt6 (GPL-3.0), cryptography (Apache-2.0/BSD), and the system's cryptsetup, LVM, ntfs-3g,
dislocker and util-linux tools.

Definitions are downloaded by you from their publishers and keep their own licences, shown on the
Definitions page.  YARA rules under the Detection Rule License (DRL 1.1) show their authors with
every match.

Optional, never bundled: chkrootkit (BSD-2-Clause), Hayabusa (AGPL-3.0), Chainsaw (GPL-3.0).
"""


class SettingsPage(QtWidgets.QWidget):
    changed = Signal()

    def __init__(self, settings: Settings, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.settings = settings
        outer = QtWidgets.QVBoxLayout(self)
        outer.addWidget(heading("Settings"))
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        body = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        clam = QtWidgets.QGroupBox("ClamAV signatures")
        cl = QtWidgets.QVBoxLayout(clam)
        self.clam_buttons: dict[str, QtWidgets.QRadioButton] = {}
        current = settings.data.get("clamav_official", "auto")
        for key, text in CLAMAV_MODES:
            radio = QtWidgets.QRadioButton(text)
            radio.setChecked(key == current)
            self.clam_buttons[key] = radio
            cl.addWidget(radio)
        layout.addWidget(clam)

        keys = QtWidgets.QGroupBox("Access keys for optional sources")
        kl = QtWidgets.QFormLayout(keys)
        kl.addRow(plain_label("Stored only on this computer, readable only by you."))
        self.secret_edits: dict[str, QtWidgets.QLineEdit] = {}
        for name in SECRET_KEYS:
            edit = QtWidgets.QLineEdit(settings.secret(name) or "")
            edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            edit.setAccessibleName(SECRET_LABELS.get(name, name))
            label = QtWidgets.QLabel(SECRET_LABELS.get(name, name) + ":")
            label.setBuddy(edit)
            kl.addRow(label, edit)
            self.secret_edits[name] = edit
        show = QtWidgets.QCheckBox("&Show keys")
        show.toggled.connect(self._show_keys)
        kl.addRow("", show)
        layout.addWidget(keys)

        bundles = QtWidgets.QGroupBox("Offline bundles")
        bl = QtWidgets.QVBoxLayout(bundles)
        self.restricted = QtWidgets.QCheckBox(
            "Include sources whose terms limit redistribution (for your own computers only)")
        self.restricted.setChecked(bool(settings.data.get("bundle_include_restricted", True)))
        bl.addWidget(self.restricted)
        layout.addWidget(bundles)

        tools = QtWidgets.QGroupBox("Optional tools")
        tl = QtWidgets.QFormLayout(tools)
        tl.addRow(plain_label("Leave empty to find them automatically (PATH, /opt)."))
        self.tool_edits: dict[str, QtWidgets.QLineEdit] = {}
        for tool in ("chkrootkit", "hayabusa", "chainsaw"):
            edit = QtWidgets.QLineEdit((settings.data.get("tools", {}).get(tool) or {}).get("path", ""))
            edit.setPlaceholderText(f"/path/to/{tool}")
            edit.setAccessibleName(f"Path of {tool}")
            tl.addRow(f"{tool}:", edit)
            self.tool_edits[tool] = edit
        layout.addWidget(tools)

        results = QtWidgets.QGroupBox("Results")
        rl = QtWidgets.QVBoxLayout(results)
        self.show_info = QtWidgets.QCheckBox("Show informational autostart entries by default")
        self.show_info.setChecked(bool(settings.data.get("ui", {}).get("show_info", False)))
        rl.addWidget(self.show_info)
        layout.addWidget(results)

        about = QtWidgets.QGroupBox(f"About {appinfo.DISPLAY_NAME}")
        al = QtWidgets.QVBoxLayout(about)
        al.addWidget(plain_label(
            f"{appinfo.DISPLAY_NAME} {appinfo.VERSION} — {appinfo.SUMMARY}\n"
            f"{appinfo.HOMEPAGE}\nLicence: {appinfo.LICENSE}\n"
            f"Qt {QtCore.qVersion()} via {BINDING} {BINDING_VERSION}, Python {platform.python_version()}",
            selectable=True))
        al.addWidget(button("Third-party &notices…", self._notices, ("help-about",)),
                     0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(about)
        layout.addStretch(1)

        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        self.save_button = button("&Save settings", self.save, ("document-save",), default=True)
        row.addWidget(self.save_button)
        outer.addLayout(row)

    def _show_keys(self, on: bool) -> None:
        mode = QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password
        for edit in self.secret_edits.values():
            edit.setEchoMode(mode)

    def _notices(self) -> None:
        box = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Icon.Information, "Third-party notices",
                                    THIRD_PARTY, QtWidgets.QMessageBox.StandardButton.Ok, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def values(self) -> dict[str, Any]:
        mode = next((k for k, radio in self.clam_buttons.items() if radio.isChecked()), "auto")
        return {"clamav_official": mode, "bundle_include_restricted": self.restricted.isChecked(),
                "tools": {t: {"path": e.text().strip()} for t, e in self.tool_edits.items()
                          if e.text().strip()},
                "show_info": self.show_info.isChecked()}

    def save(self) -> None:
        values = self.values()
        self.settings.data["clamav_official"] = values["clamav_official"]
        self.settings.data["bundle_include_restricted"] = values["bundle_include_restricted"]
        self.settings.data["tools"] = values["tools"]
        self.settings.data.setdefault("ui", {})["show_info"] = values["show_info"]
        for name, edit in self.secret_edits.items():
            self.settings.set_secret(name, edit.text().strip() or None)
        self.settings.save()
        self.changed.emit()

