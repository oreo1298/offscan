"""The Qt shim must work with whichever binding is installed."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PROBE = (
    "from offscan.gui import qt\n"
    "app = qt.QtWidgets.QApplication([])\n"
    "class O(qt.QtCore.QObject):\n"
    "    changed = qt.Signal(int)\n"
    "o = O(); got = []\n"
    "o.changed.connect(got.append); o.changed.emit(7)\n"
    "assert got == [7]\n"
    "assert qt.QtGui.QPalette.ColorRole.Window is not None\n"
    "print(qt.BINDING, '.'.join(map(str, qt.QT_VERSION)))\n"
)


def _interpreters_with(binding: str) -> list[str]:
    found = []
    for exe in {sys.executable, "/usr/bin/python3", "/usr/bin/python3.12"}:
        if not Path(exe).exists():
            continue
        ok = subprocess.run([exe, "-c", f"from {binding} import QtCore"], capture_output=True).returncode == 0
        if ok:
            found.append(exe)
    return sorted(found)


@pytest.mark.gui
@pytest.mark.parametrize("binding", ["PySide6", "PyQt6"])
def test_shim_with_each_binding(binding: str) -> None:
    exes = _interpreters_with(binding)
    if not exes:
        pytest.skip(f"{binding} not installed for any interpreter here")
    for exe in exes:
        proc = subprocess.run(
            [exe, "-c", PROBE], capture_output=True, text=True,
            env={"PYTHONPATH": str(ROOT / "src"), "QT_QPA_PLATFORM": "offscreen",
                 "OFFSCAN_QT_API": binding.lower(), "PATH": "/usr/bin:/bin", "HOME": "/tmp"})
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.startswith(binding)


def test_shim_error_message_without_any_binding(tmp_path: Path) -> None:
    if importlib.util.find_spec("PySide6") is None and importlib.util.find_spec("PyQt6") is None:
        pytest.skip("no binding installed; message path covered implicitly")
    # Hide both bindings with a meta path blocker.
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in ('PySide6', 'PyQt6'):\n"
        "            raise ImportError('blocked')\n"
        "sys.meta_path.insert(0, Block())\n"
        "try:\n"
        "    import offscan.gui.qt\n"
        "except ImportError as e:\n"
        "    print('ERR', e)\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
    assert "Neither PySide6 nor PyQt6" in proc.stdout
