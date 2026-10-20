"""Follow the desktop's look: colour scheme, accent colour, fonts and icons.

Qt already uses the system font, icon theme and HiDPI scaling.  Desktops
with a Qt platform theme (Plasma, qt6ct, the GTK/portal themes) also
supply the palette.  Elsewhere (GNOME, Cinnamon, Xfce without one) Qt
falls back to a light Fusion palette even when the user prefers dark.  So
we ask the XDG desktop portal for ``color-scheme`` and ``accent-color``
and adapt.  Colours are always derived from the style's own palette;
none are hard-coded.
"""

from __future__ import annotations

import os
from typing import Any

from .qt import QtCore, QtDBus, QtGui, QtWidgets, qt_at_least

PORTAL = ("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
          "org.freedesktop.portal.Settings")
NAMESPACE = "org.freedesktop.appearance"

ROLES = ("Window", "WindowText", "Base", "AlternateBase", "ToolTipBase", "ToolTipText", "PlaceholderText",
         "Text", "Button", "ButtonText", "BrightText", "Light", "Midlight", "Mid", "Dark", "Shadow",
         "Highlight", "HighlightedText", "Link", "LinkVisited")
GROUPS = ("Active", "Inactive", "Disabled")


def platform_supplies_palette(env: dict[str, str] | None = None) -> bool:
    """True when a platform theme (Plasma, qt6ct, gtk3, portal) already follows the desktop."""
    env = dict(os.environ) if env is None else env
    if env.get("QT_QPA_PLATFORMTHEME", "").strip():
        return True
    desktop = env.get("XDG_CURRENT_DESKTOP", "").lower()
    return "kde" in desktop or env.get("KDE_FULL_SESSION") == "true" or "lxqt" in desktop


def is_dark(palette: QtGui.QPalette) -> bool:
    window = palette.color(QtGui.QPalette.ColorRole.Window)
    text = palette.color(QtGui.QPalette.ColorRole.WindowText)
    return window.lightness() < text.lightness()


def _invert(color: QtGui.QColor) -> QtGui.QColor:
    h, s, l_, a = color.getHsl()
    out = QtGui.QColor()
    out.setHsl(max(h, 0), s, 255 - l_, a)
    return out


def derive_dark(light: QtGui.QPalette) -> QtGui.QPalette:
    """A dark palette made from the style's light one: same hues, inverted lightness."""
    dark = QtGui.QPalette(light)
    for group_name in GROUPS:
        group = getattr(QtGui.QPalette.ColorGroup, group_name)
        for role_name in ROLES:
            role = getattr(QtGui.QPalette.ColorRole, role_name, None)
            if role is None:
                continue
            color = light.color(group, role)
            if role_name in ("Highlight", "Link", "LinkVisited"):
                continue                     # accent colours keep their identity
            if role_name == "HighlightedText":
                continue
            dark.setColor(group, role, _invert(color))
    return dark


def contrast_text(background: QtGui.QColor, palette: QtGui.QPalette) -> QtGui.QColor:
    """Whichever of the palette's text and base colours reads better on ``background``."""
    candidates = [palette.color(QtGui.QPalette.ColorRole.Text), palette.color(QtGui.QPalette.ColorRole.Base)]

    def luminance(c: QtGui.QColor) -> float:
        def channel(v: float) -> float:
            return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
        return 0.2126 * channel(c.redF()) + 0.7152 * channel(c.greenF()) + 0.0722 * channel(c.blueF())

    bg = luminance(background)

    def ratio(c: QtGui.QColor) -> float:
        a, b = sorted((bg, luminance(c)), reverse=True)
        return (a + 0.05) / (b + 0.05)

    return max(candidates, key=ratio)


def with_accent(palette: QtGui.QPalette, accent: QtGui.QColor) -> QtGui.QPalette:
    out = QtGui.QPalette(palette)
    text = contrast_text(accent, palette)
    for group_name in ("Active", "Inactive"):
        group = getattr(QtGui.QPalette.ColorGroup, group_name)
        out.setColor(group, QtGui.QPalette.ColorRole.Highlight, accent)
        out.setColor(group, QtGui.QPalette.ColorRole.HighlightedText, text)
        accent_role = getattr(QtGui.QPalette.ColorRole, "Accent", None)        # Qt >= 6.6
        if accent_role is not None:
            out.setColor(group, accent_role, accent)
    return out


def parse_accent(value: Any) -> QtGui.QColor | None:
    """The portal's accent-color is (r, g, b) doubles in 0..1; out-of-range means "unset"."""
    try:
        r, g, b = (float(x) for x in value)
    except (TypeError, ValueError):
        return None
    if not all(0.0 <= x <= 1.0 for x in (r, g, b)):
        return None
    return QtGui.QColor.fromRgbF(r, g, b)


def _unwrap(value: Any) -> Any:
    for _ in range(4):                       # the portal nests QDBusVariant inside QVariant
        if QtDBus is not None and isinstance(value, QtDBus.QDBusVariant):
            value = value.variant()
        elif hasattr(value, "value") and callable(value.value) and type(value).__name__ == "QVariant":
            value = value.value()
        else:
            break
    return value


def read_portal(key: str) -> Any:
    """``org.freedesktop.appearance`` setting from the desktop portal, or None."""
    if QtDBus is None:
        return None
    try:
        bus = QtDBus.QDBusConnection.sessionBus()
        if not bus.isConnected():
            return None
        iface = QtDBus.QDBusInterface(*PORTAL, bus)
        iface.setTimeout(800)
        reply = iface.call("ReadOne", NAMESPACE, key)
        if reply.type() == QtDBus.QDBusMessage.MessageType.ErrorMessage:
            reply = iface.call("Read", NAMESPACE, key)          # older portals
        if reply.type() == QtDBus.QDBusMessage.MessageType.ErrorMessage:
            return None
        args = reply.arguments()
        return _unwrap(args[0]) if args else None
    except Exception:
        return None


class Theme(QtCore.QObject):
    """Applies and keeps following the desktop's colour scheme and accent."""

    def __init__(self, app: QtWidgets.QApplication, env: dict[str, str] | None = None):
        super().__init__(app)
        self.app = app
        self.env = env
        self.base_palette = QtGui.QPalette(app.palette())
        self.prefers_dark: bool | None = None
        self.accent: QtGui.QColor | None = None
        hints = app.styleHints()
        signal = getattr(hints, "colorSchemeChanged", None)                 # Qt >= 6.5
        if signal is not None:
            signal.connect(lambda *_: self.refresh())

    def refresh(self) -> None:
        scheme = read_portal("color-scheme")
        self.prefers_dark = {1: True, 2: False}.get(int(scheme), None) if isinstance(scheme, int) else None
        self.accent = parse_accent(read_portal("accent-color"))
        self.apply()

    def apply(self) -> None:
        if platform_supplies_palette(self.env):
            palette = QtGui.QPalette(self.app.palette())
        else:
            palette = QtGui.QPalette(self.base_palette)
            if self.prefers_dark and not is_dark(palette):
                if qt_at_least(6, 8) and hasattr(QtCore.Qt, "ColorScheme"):
                    self.app.styleHints().setColorScheme(QtCore.Qt.ColorScheme.Dark)
                    palette = QtGui.QPalette(self.app.palette())
                    if not is_dark(palette):
                        palette = derive_dark(self.base_palette)
                else:
                    palette = derive_dark(self.base_palette)
        if self.accent is not None and self.accent.isValid():
            palette = with_accent(palette, self.accent)
        self.app.setPalette(palette)


def icon(*names: str, fallback: QtWidgets.QStyle.StandardPixmap | None = None) -> QtGui.QIcon:
    """First available icon from the user's icon theme, else a style icon."""
    for name in names:
        if QtGui.QIcon.hasThemeIcon(name):
            return QtGui.QIcon.fromTheme(name)
    style = QtWidgets.QApplication.style()
    if fallback is not None and style is not None:
        return style.standardIcon(fallback)
    return QtGui.QIcon()


SP = QtWidgets.QStyle.StandardPixmap
SEVERITY_ICONS = {
    "high": (("security-low", "dialog-error"), SP.SP_MessageBoxCritical),
    "medium": (("security-medium", "dialog-warning"), SP.SP_MessageBoxWarning),
    "low": (("dialog-information",), SP.SP_MessageBoxInformation),
    "info": (("help-about", "dialog-information"), SP.SP_FileDialogInfoView),
}


def severity_icon(severity: str) -> QtGui.QIcon:
    names, fallback = SEVERITY_ICONS.get(severity, SEVERITY_ICONS["info"])
    return icon(*names, fallback=fallback)
