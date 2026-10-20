"""Shared pytest configuration.

Markers decide what runs where:

* default: pure unit tests, no privileges, no network;
* ``integration``: needs root + loop devices (``sudo -E .venv/bin/pytest -m integration``);
* ``devmapper``: additionally needs device-mapper (LUKS/LVM/BitLocker), e.g. in CI;
* ``gui``: needs a Qt binding; runs with ``QT_QPA_PLATFORM=offscreen``.

Tests never touch the network: the ``no_network`` fixture is applied
automatically and fails any attempt to open an internet socket.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> object:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, tuple) else address
            if host not in ("127.0.0.1", "::1", "localhost"):
                raise AssertionError(f"test tried to reach the network: {address!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture
def xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point all XDG and system directories into a temporary tree."""
    from offscan import appinfo
    for var, sub in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"),
                     ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state")):
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv(appinfo.env("SYSTEM_STATE_DIR"), str(tmp_path / "var-lib"))
    monkeypatch.setenv(appinfo.env("RUNTIME_DIR"), str(tmp_path / "run"))
    return tmp_path


def _have_root_and_loop() -> bool:
    return os.geteuid() == 0 and os.path.exists("/dev/loop-control")


def _have_devmapper() -> bool:
    return os.path.exists("/dev/mapper/control")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_root = pytest.mark.skip(reason="needs root and loop devices")
    skip_dm = pytest.mark.skip(reason="needs device-mapper (/dev/mapper/control)")
    for item in items:
        if "integration" in item.keywords and not _have_root_and_loop():
            item.add_marker(skip_root)
        if "devmapper" in item.keywords and not _have_devmapper():
            item.add_marker(skip_dm)
