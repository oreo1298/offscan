from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from offscan import appinfo
from offscan.client import HelperClient

from . import images

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def helper_env(tmp_path: Path) -> dict[str, str]:
    env = {
        appinfo.env("RUNTIME_DIR"): str(tmp_path / "run"),
        appinfo.env("SYSTEM_STATE_DIR"): str(tmp_path / "var-lib"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "PYTHONPATH": str(ROOT / "src"),
    }
    return env


@pytest.fixture
def helper(helper_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> Iterator[HelperClient]:
    for key, value in helper_env.items():
        monkeypatch.setenv(key, value)
    client = HelperClient(command=[sys.executable, "-m", "offscan.helper", "-v"], env=helper_env)
    client.start(timeout=60)
    try:
        yield client
    finally:
        client.close()


def loop_devices() -> set[str]:
    out = subprocess.run(["losetup", "--list", "--noheadings", "--output", "NAME"],
                         capture_output=True, text=True, env=images.ENV).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


@pytest.fixture
def no_leaks() -> Iterator[None]:
    before = loop_devices()
    yield
    leaked = loop_devices() - before
    for dev in leaked:   # clean up so later tests are not affected, then fail
        subprocess.run(["losetup", "-d", dev], env=images.ENV, check=False)
    assert not leaked, f"loop devices leaked: {leaked}"


def require(*tools: str) -> None:
    missing = [t for t in tools if not shutil.which(t, path=images.ENV["PATH"])]
    if missing:
        pytest.skip(f"missing tools: {', '.join(missing)}")


def require_fs(name: str) -> None:
    if not images.kernel_fs(name):
        subprocess.run(["modprobe", "-q", name], env=images.ENV, check=False)
    if not images.kernel_fs(name):
        pytest.skip(f"kernel lacks {name}")


@pytest.fixture(autouse=True)
def _root_only() -> None:
    if os.geteuid() != 0:
        pytest.skip("integration tests need root")
