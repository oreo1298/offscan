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
from offscan.helper import blockdev

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


BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"


@pytest.fixture(scope="session")
def dirty_disk(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.geteuid() != 0:
        pytest.skip("needs root")
    require("sfdisk", "mkfs.ext4", "mkfs.xfs", "mkntfs", "ntfs-3g", "losetup", "mkfs.vfat")
    require_fs("ext4")
    require_fs("xfs")
    work = tmp_path_factory.mktemp("disk")
    clean = work / "build.img"
    images.make_disk(clean, 560, [("L", 64), (BASIC_DATA, 64), ("L", 320), ("U", 0)])
    out = work / "dirty.img"
    with images.attached(clean, partscan=True) as dev:
        p1, p2, p3, p4 = (f"{dev}p{i}" for i in range(1, 5))
        images.run("mkfs.ext4", "-q", "-F", "-L", "linuxroot", p1)
        images.run("mkntfs", "-Q", "-F", "-L", "Windows", p2)
        images.run("mkfs.xfs", "-q", "-f", "-L", "xfsdata", p3)
        images.run("mkfs.vfat", "-n", "ESP", p4)
        with images.mounted(p2, "ntfs-3g") as mnt:
            images.populate_windows(mnt, hibernated=True)
        if images.kernel_fs("vfat"):
            with images.mounted(p4, "vfat") as mnt:
                (mnt / "EFI" / "Microsoft" / "Boot").mkdir(parents=True)
                (mnt / "EFI" / "fixture").mkdir(parents=True)
        with images.mounted(p3, "xfs") as xmnt:
            (xmnt / "stable.txt").write_text("written before the dirty phase\n")
        # ext4 and XFS: write while mounted, then copy the disk mid-flight.
        with images.mounted(p3, "xfs") as xmnt:
            (xmnt / "data.bin").write_bytes(os.urandom(1 << 20))
            (xmnt / "eicar.com").write_bytes(images.eicar())
            images.dirty_copy(p1, clean, out, "ext4", images.populate_linux)
    clean.unlink()
    return out


def find_disk(disks: list[dict], device: str) -> dict:
    for disk in disks:
        if disk["device"] == device:
            return disk
    raise AssertionError(f"{device} not listed: {[d['device'] for d in disks]}")


@pytest.fixture
def target_disk(dirty_disk: Path) -> Iterator[tuple[str, str]]:
    """Attach the dirty image as a simulated physical disk (read-write, like real hardware)."""
    before = images.sha256(dirty_disk)
    with images.attached(dirty_disk, partscan=True) as dev:
        yield dev, before
        assert not blockdev.get_ro(dev), "read-only flag of the disk was not restored"
        assert not blockdev.get_ro(f"{dev}p1"), "read-only flag of the partition was not restored"
    assert images.sha256(dirty_disk) == before, "THE TARGET IMAGE WAS MODIFIED"
