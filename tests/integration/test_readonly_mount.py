"""The never-write guarantee, tested on a disk image with dirty filesystems.

The fixture disk has a dirty ext4 (unreplayed journal + orphan inode), a
dirty XFS log, a hibernated NTFS "Windows" and an EFI partition.  We list,
probe, mount and read everything through the real helper and then check
that the image's SHA-256 has not changed.  A control test proves that a
plain ``mount -o ro`` *would* have changed it.
"""

from __future__ import annotations

import errno
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from offscan.helper import blockdev
from offscan.safefs import RootFS

from . import images
from .conftest import loop_devices, require, require_fs

pytestmark = [pytest.mark.integration, pytest.mark.slow]

BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"


@pytest.fixture(scope="module")
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


def test_fixture_really_is_dirty(dirty_disk: Path, tmp_path: Path) -> None:
    """Control: a naive read-only mount of a copy modifies the image."""
    copy = tmp_path / "copy.img"
    shutil.copyfile(dirty_disk, copy)
    before = images.sha256(copy)
    with images.attached(copy, partscan=True) as dev, images.mounted(f"{dev}p1", "ext4", "ro"):
        pass
    assert images.sha256(copy) != before, "ext4 did not replay; the fixture is not dirty"


def _find_disk(disks: list[dict], device: str) -> dict:
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


def test_list_probe_mount_read_never_writes(no_leaks, target_disk, helper, tmp_path: Path) -> None:
    dev, _ = target_disk
    loops_before = loop_devices()
    result = helper.call("drives.list", {"probe": "wait"}, timeout=600)
    disk = _find_disk(result["disks"], dev)
    vols = {v["device"]: v for v in disk["volumes"]}
    linux, windows, xfs, esp = (vols[f"{dev}p{i}"] for i in range(1, 5))

    assert linux["fstype"] == "ext4" and linux["os"]["name"] == "Fixture Linux 1.0"
    assert any(w["code"] == "needs_recovery" for w in linux["warnings"])
    assert windows["fstype"] == "ntfs" and windows["os"]["family"] == "windows"
    assert windows["hibernation"]["hibernated"] is True
    assert any(w["code"] == "hibernated" for w in windows["warnings"])
    assert xfs["fstype"] == "xfs"
    if images.kernel_fs("vfat"):
        assert esp["os"]["family"] == "efi"
        assert "Windows Boot Manager" in esp["os"]["details"]["loaders"]
    # Probing must leave nothing behind.
    assert loop_devices() == loops_before

    mounted = {}
    for vol in (linux, windows, xfs):
        info = helper.call("volume.mount", {"volume": vol["id"]}, timeout=300)
        mounted[vol["id"]] = info["mountpoint"]
        assert "ro" in info["options"] or info["driver"] == "ntfs-3g"
        # While mounted, the partition and the disk are read-only at the block layer.
        assert blockdev.get_ro(vol["device"])
    assert blockdev.get_ro(dev)

    linux_mp = Path(mounted[linux["id"]])
    with RootFS(linux_mp) as fs:
        assert fs.read_file("/home/user/eicar.com") == images.eicar()
        assert fs.read_file("/etc/os-release").startswith(b"NAME=")
        with pytest.raises(FileNotFoundError):     # absolute link must not reach the host
            fs.read_file("/home/user/escape-link")
    # Kernel-level: symlinks are not followed at all on our mounts.
    with pytest.raises(OSError) as err:
        open(linux_mp / "etc/os-release", "rb")
    assert err.value.errno == errno.ELOOP
    # Writes are refused.
    with pytest.raises(OSError) as err:
        (linux_mp / "new-file").write_bytes(b"x")
    assert err.value.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    with RootFS(mounted[windows["id"]]) as fs:
        assert fs.find_ci("users/alice/downloads/EICAR.COM") is not None
    with RootFS(mounted[xfs["id"]]) as fs:
        # norecovery: files that only exist in the unreplayed log are not
        # visible (that is the price of never writing); older data is.
        assert fs.read_file("/stable.txt").startswith(b"written before")

    for vol_id in mounted:
        helper.call("volume.unmount", {"volume": vol_id}, timeout=120)
    assert loop_devices() == loops_before


def test_helper_exit_cleans_up(no_leaks, target_disk, helper) -> None:
    dev, _ = target_disk
    disk = _find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
    vol = next(v for v in disk["volumes"] if v["fstype"] == "ext4")
    info = helper.call("volume.mount", {"volume": vol["id"]}, timeout=300)
    assert os.path.ismount(info["mountpoint"])
    helper.close()                       # helper must unmount and restore flags on exit
    assert not os.path.ismount(info["mountpoint"])


def test_keep_survives_helper_restart(no_leaks, target_disk, helper_env, monkeypatch) -> None:
    import sys

    from offscan.client import HelperClient
    for key, value in helper_env.items():
        monkeypatch.setenv(key, value)
    cmd = [sys.executable, "-m", "offscan.helper"]
    dev, _ = target_disk
    with HelperClient(command=cmd, env=helper_env) as client:
        disk = _find_disk(client.call("drives.list", {"probe": "none"})["disks"], dev)
        vol = next(v for v in disk["volumes"] if v["fstype"] == "xfs")
        info = client.call("volume.mount", {"volume": vol["id"], "keep": True}, timeout=300)
    assert os.path.ismount(info["mountpoint"])
    with HelperClient(command=cmd, env=helper_env) as client:
        listed = _find_disk(client.call("drives.list", {"probe": "none"})["disks"], dev)
        again = next(v for v in listed["volumes"] if v["id"] == vol["id"])
        assert again["mountpoint"] == info["mountpoint"]
        client.call("session.cleanup", {"include_kept": True}, timeout=300)
    assert not os.path.ismount(info["mountpoint"])


def test_sandbox_drops_privileges_and_network(helper) -> None:
    hello = helper.hello
    assert hello["network_isolated"] is True
    result = helper.call("helper.sandbox_check", timeout=60)
    assert result["uid"] != 0
    assert result["no_network"] is True
    assert result["data"] == ["sandbox-ok"]


def test_second_helper_is_refused(helper, helper_env) -> None:
    import sys

    from offscan.client import HelperClient, HelperStartError
    other = HelperClient(command=[sys.executable, "-m", "offscan.helper"], env=helper_env)
    with pytest.raises(HelperStartError, match="already running"):
        other.start(timeout=60)
