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
from pathlib import Path

import pytest

from offscan.helper import blockdev
from offscan.safefs import RootFS

from . import images
from .conftest import find_disk as _find_disk
from .conftest import loop_devices

pytestmark = [pytest.mark.integration, pytest.mark.slow]

def test_fixture_really_is_dirty(dirty_disk: Path, tmp_path: Path) -> None:
    """Control: a naive read-only mount of a copy modifies the image."""
    copy = tmp_path / "copy.img"
    shutil.copyfile(dirty_disk, copy)
    before = images.sha256(copy)
    with images.attached(copy, partscan=True) as dev, images.mounted(f"{dev}p1", "ext4", "ro"):
        pass
    assert images.sha256(copy) != before, "ext4 did not replay; the fixture is not dirty"


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
