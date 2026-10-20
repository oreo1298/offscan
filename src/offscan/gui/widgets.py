"""Small shared widgets and dialogs.

Every string that may come from a target (file names, registry values, rule
names from feeds) is shown as plain text: labels are forced to
``Qt.PlainText`` and passed through :func:`offscan.names.display`, which
escapes control and bidirectional characters.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from .. import names
from .qt import QtCore, QtGui, QtWidgets
from .theme import icon

Qt = QtCore.Qt


def plain_label(text: str = "", wrap: bool = True, selectable: bool = False) -> QtWidgets.QLabel:
    label = QtWidgets.QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    label.setText(text)
    if selectable:
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse
                                      | Qt.TextInteractionFlag.TextSelectableByKeyboard)
    return label


def safe(text: Any, limit: int = 2000) -> str:
    """One line of possibly hostile text, made harmless for display."""
    return names.display(str(text if text is not None else ""), limit, backslash=False)


def safe_text(text: Any, limit: int = 2000) -> str:
    """Several lines of possibly hostile text; real line breaks are kept."""
    lines = str(text if text is not None else "").splitlines() or [""]
    return "\n".join(safe(line, limit) for line in lines[:500])


def heading(text: str) -> QtWidgets.QLabel:
    label = plain_label(text, wrap=False)
    font = label.font()
    font.setPointSizeF(font.pointSizeF() * 1.3)
    font.setBold(True)
    label.setFont(font)
    label.setAccessibleName(text)
    return label


def action(parent: QtCore.QObject, text: str, slot: Callable[[], Any], icons: Sequence[str] = (),
           shortcut: str | QtGui.QKeySequence.StandardKey | None = None, tip: str = "",
           fallback: QtWidgets.QStyle.StandardPixmap | None = None) -> QtGui.QAction:
    act = QtGui.QAction(icon(*icons, fallback=fallback), text, parent)
    if shortcut is not None:
        act.setShortcut(QtGui.QKeySequence(shortcut))
    if tip:
        act.setToolTip(tip)
        act.setStatusTip(tip)
    act.triggered.connect(lambda *_: slot())
    return act


def button(text: str, slot: Callable[[], Any], icons: Sequence[str] = (), default: bool = False,
           tip: str = "") -> QtWidgets.QPushButton:
    btn = QtWidgets.QPushButton(icon(*icons), text)
    btn.clicked.connect(lambda *_: slot())
    btn.setAutoDefault(default)
    btn.setDefault(default)
    if tip:
        btn.setToolTip(tip)
    btn.setAccessibleName(text.replace("&", ""))
    return btn


def error(parent: QtWidgets.QWidget | None, title: str, text: str) -> None:
    box = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Icon.Warning, title, safe_text(text),
                                QtWidgets.QMessageBox.StandardButton.Ok, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.exec()


def info(parent: QtWidgets.QWidget | None, title: str, text: str) -> None:
    box = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Icon.Information, title, safe_text(text),
                                QtWidgets.QMessageBox.StandardButton.Ok, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.exec()


def ask(parent: QtWidgets.QWidget | None, title: str, text: str, yes: str = "OK") -> bool:
    box = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Icon.Question, title, safe_text(text),
                                QtWidgets.QMessageBox.StandardButton.NoButton, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    ok = box.addButton(yes, QtWidgets.QMessageBox.ButtonRole.AcceptRole)
    box.addButton(QtWidgets.QMessageBox.StandardButton.Cancel)
    box.exec()
    return box.clickedButton() is ok


class SecretDialog(QtWidgets.QDialog):
    """Passphrase / BitLocker recovery key entry."""

    def __init__(self, volume: str, kind: str, parent: QtWidgets.QWidget | None = None,
                 purpose: str = "read-only"):
        super().__init__(parent)
        self.setWindowTitle("Unlock encrypted volume")
        layout = QtWidgets.QVBoxLayout(self)
        what = "BitLocker" if kind == "bitlocker" else "LUKS"
        layout.addWidget(plain_label(f"{safe(volume)} is encrypted with {what}. Enter its passphrase"
                                     + (" or recovery key" if kind == "bitlocker" else "")
                                     + f" to open it ({purpose})."))
        form = QtWidgets.QFormLayout()
        self.secret = QtWidgets.QLineEdit()
        self.secret.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.secret.setAccessibleName("Passphrase")
        label = QtWidgets.QLabel("&Passphrase:")
        label.setBuddy(self.secret)
        form.addRow(label, self.secret)
        self.kind = QtWidgets.QComboBox()
        self.kind.setAccessibleName("Kind of secret")
        self.kind.addItem("Passphrase", "passphrase")
        if kind == "bitlocker":
            self.kind.addItem("Recovery key (48 digits)", "recovery_key")
            self.kind.addItem("Password", "password")
        else:
            self.kind.setEnabled(False)
        kind_label = QtWidgets.QLabel("&Type:")
        kind_label.setBuddy(self.kind)
        form.addRow(kind_label, self.kind)
        show = QtWidgets.QCheckBox("&Show")
        show.toggled.connect(lambda on: self.secret.setEchoMode(
            QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password))
        form.addRow("", show)
        layout.addLayout(form)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok
                                             | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> tuple[str, str]:
        return self.secret.text(), self.kind.currentData()


class ConfirmChangeDialog(QtWidgets.QDialog):
    """Shows exactly what a quarantine/delete/restore will do and asks for an explicit yes."""

    def __init__(self, title: str, lines: list[str], action_text: str, needs_secret: list[dict[str, str]],
                 parent: QtWidgets.QWidget | None = None, destructive: bool = True):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        layout = QtWidgets.QVBoxLayout(self)
        head = QtWidgets.QHBoxLayout()
        pix = QtWidgets.QLabel()
        pix.setPixmap(icon("dialog-warning", fallback=QtWidgets.QStyle.StandardPixmap.SP_MessageBoxWarning)
                      .pixmap(48, 48))
        head.addWidget(pix, 0, Qt.AlignmentFlag.AlignTop)
        text = QtWidgets.QPlainTextEdit("\n\n".join(safe_text(line, 4000) for line in lines))
        text.setReadOnly(True)
        text.setAccessibleName("What will happen")
        text.setMinimumHeight(180)
        head.addWidget(text, 1)
        layout.addLayout(head)
        self.secrets: dict[str, tuple[QtWidgets.QLineEdit, QtWidgets.QComboBox]] = {}
        if needs_secret:
            form = QtWidgets.QFormLayout()
            for item in needs_secret:
                edit = QtWidgets.QLineEdit()
                edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
                edit.setAccessibleName(f"Passphrase for {item['volume']}")
                kind = QtWidgets.QComboBox()
                kind.addItem("Passphrase", "passphrase")
                if item.get("kind") == "bitlocker":
                    kind.addItem("Recovery key", "recovery_key")
                row = QtWidgets.QHBoxLayout()
                row.addWidget(edit, 1)
                row.addWidget(kind)
                form.addRow(f"Passphrase for {safe(item['volume'])}:", row)
                self.secrets[item["volume"]] = (edit, kind)
            layout.addLayout(form)
        self.understood = QtWidgets.QCheckBox("I understand that this &changes the drive")
        self.understood.setAccessibleName("I understand that this changes the drive")
        layout.addWidget(self.understood)
        buttons = QtWidgets.QDialogButtonBox()
        self.go = buttons.addButton(action_text, QtWidgets.QDialogButtonBox.ButtonRole.DestructiveRole
                                    if destructive else QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setEnabled(False)
        self.go.setAutoDefault(False)
        cancel = buttons.addButton(QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        cancel.setDefault(True)
        self.understood.toggled.connect(self.go.setEnabled)
        self.go.clicked.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def secret_values(self) -> dict[str, dict[str, str]]:
        return {vol: {"secret": edit.text(), "kind": kind.currentData()}
                for vol, (edit, kind) in self.secrets.items()}


class Busy(QtWidgets.QWidget):
    """An indeterminate progress bar with a message, for work that runs in the background."""

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bar = QtWidgets.QProgressBar()
        self.bar.setRange(0, 0)
        self.bar.setMaximumWidth(160)
        self.bar.setAccessibleName("Working")
        self.text = plain_label("", wrap=False)
        layout.addWidget(self.bar)
        layout.addWidget(self.text, 1)
        self.hide()

    def start(self, text: str) -> None:
        self.text.setText(text)
        self.show()

    def stop(self) -> None:
        self.hide()
