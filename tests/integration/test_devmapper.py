"""LUKS2, LVM, BitLocker and Btrfs through the helper, image hash unchanged.

Needs device-mapper (and btrfs for the btrfs test), so this runs in CI.
BitLocker images come from cryptsetup's own test suite; CI downloads them
and points ``OFFSCAN_TEST_BITLK_DIR`` at the extracted directory.
"""

from __future__ import annotations

import configparser
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from offscan.helper import blockdev
from offscan.safefs import RootFS

from . import images
from .conftest import require, require_fs

pytestmark = [pytest.mark.integration, pytest.mark.devmapper, pytest.mark.slow]

PASSPHRASE = "correct horse battery staple"


def _vol(helper, dev: str) -> dict:
    for disk in helper.call("drives.list", {"probe": "none"}, timeout=120)["disks"]:
        for vol in disk["volumes"]:
            if vol["device"] == dev:
                return vol
    raise AssertionError(f"{dev} not listed")


@pytest.fixture(scope="module")
def luks_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    require("cryptsetup", "mkfs.ext4")
    img = tmp_path_factory.mktemp("luks") / "luks.img"
    with open(img, "wb") as fh:
        fh.truncate(64 << 20)
    with images.attached(img) as dev:
        images.run("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
                   "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
                   "--key-file", "-", dev, input=PASSPHRASE.encode())
        images.run("cryptsetup", "open", "--key-file", "-", dev, "fixture-luks",
                   input=PASSPHRASE.encode())
        try:
            images.run("mkfs.ext4", "-q", "/dev/mapper/fixture-luks")
            with images.mounted("/dev/mapper/fixture-luks", "ext4") as mnt:
                images.populate_linux(mnt, "Encrypted Linux")
        finally:
            images.run("cryptsetup", "close", "fixture-luks")
    return img


def test_luks_unlock_mount_lock(luks_image: Path, no_leaks, helper) -> None:
    before = images.sha256(luks_image)
    with images.attached(luks_image) as dev:
        vol = _vol(helper, dev)
        assert vol["role"] == "luks" and vol["encryption"]["unlocked"] is False
        with pytest.raises(Exception) as err:
            helper.call("volume.unlock", {"volume": vol["id"], "secret": "wrong"}, timeout=120)
        assert getattr(err.value, "code", "") == "not_permitted"
        res = helper.call("volume.unlock", {"volume": vol["id"], "secret": PASSPHRASE}, timeout=120)
        assert blockdev.get_ro(res["device"])
        listed = _vol(helper, dev)
        assert listed["encryption"]["unlocked"] is True
        child = listed["children"][0]
        assert child["id"] == res["unlocked"] and child["fstype"] == "ext4"
        probed = helper.call("volume.probe", {"volume": child["id"]}, timeout=120)
        assert probed["os"]["name"] == "Encrypted Linux"
        info = helper.call("volume.mount", {"volume": child["id"]}, timeout=120)
        with RootFS(info["mountpoint"]) as fs:
            assert fs.read_file("/home/user/eicar.com") == images.eicar()
        helper.call("volume.lock", {"volume": vol["id"]}, timeout=120)
        assert not os.path.exists(res["device"])
        assert not blockdev.get_ro(dev)
    assert images.sha256(luks_image) == before


@pytest.fixture(scope="module")
def lvm_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    require("lvm", "mkfs.ext4")
    img = tmp_path_factory.mktemp("lvm") / "lvm.img"
    with open(img, "wb") as fh:
        fh.truncate(128 << 20)
    cfg = 'devices { use_devicesfile = 0 }'
    with images.attached(img) as dev:
        images.run("lvm", "pvcreate", "-q", "--config", cfg, dev)
        images.run("lvm", "vgcreate", "-q", "--config", cfg, "fixturevg", dev)
        images.run("lvm", "lvcreate", "-q", "--config", cfg, "-y", "-L", "48M", "-n", "root", "fixturevg")
        images.run("lvm", "lvcreate", "-q", "--config", cfg, "-y", "-L", "16M", "-n", "data", "fixturevg")
        try:
            images.run("mkfs.ext4", "-q", "/dev/fixturevg/root")
            with images.mounted("/dev/fixturevg/root", "ext4") as mnt:
                images.populate_linux(mnt, "LVM Linux")
        finally:
            images.run("lvm", "vgchange", "-q", "--config", cfg, "-an", "fixturevg")
    return img


def _host_deactivate() -> None:
    # Desktop/CI udev may auto-activate the fixture VG on the test's own loop
    # device; that is the host's doing, not ours, so undo it for the test.
    images.run("lvm", "vgchange", "-q", "--config", "devices { use_devicesfile = 0 }", "-an",
               "fixturevg", check=False)


def test_lvm_readonly_activation(lvm_image: Path, no_leaks, helper) -> None:
    before = images.sha256(lvm_image)
    with images.attached(lvm_image) as dev:
        import time
        time.sleep(1)
        _host_deactivate()
        vol = _vol(helper, dev)
        assert vol["role"] == "lvm_pv"
        res = helper.call("volume.activate_lvm", {"volume": vol["id"]}, timeout=120)
        names = {lv["name"]: lv for lv in res["activated"]}
        assert set(names) == {"fixturevg/root", "fixturevg/data"}
        for lv in names.values():
            assert blockdev.get_ro(lv["device"])
            assert os.path.basename(lv["device"]).startswith("offscan-lvm-")
        info = helper.call("volume.mount", {"volume": names["fixturevg/root"]["volume"]}, timeout=120)
        with RootFS(info["mountpoint"]) as fs:
            assert fs.read_file("/etc/os-release").startswith(b"NAME=")
        helper.call("session.cleanup", {}, timeout=120)
        assert not os.path.exists(names["fixturevg/root"]["device"])
        _host_deactivate()
    assert images.sha256(lvm_image) == before


@pytest.fixture(scope="module")
def btrfs_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    require("mkfs.btrfs", "btrfs")
    require_fs("btrfs")
    img = tmp_path_factory.mktemp("btrfs") / "btrfs.img"
    with open(img, "wb") as fh:
        fh.truncate(256 << 20)
    with images.attached(img) as dev:
        images.run("mkfs.btrfs", "-q", "-f", dev)
        with images.mounted(dev, "btrfs") as mnt:
            images.run("btrfs", "subvolume", "create", str(mnt / "@"))
            images.run("btrfs", "subvolume", "create", str(mnt / "@home"))
            images.populate_linux(mnt / "@", "Btrfs Linux")
            (mnt / "@home" / "notes.txt").write_text("in a subvolume\n")
    return img


def test_btrfs_subvolumes_visible(btrfs_image: Path, no_leaks, helper) -> None:
    before = images.sha256(btrfs_image)
    with images.attached(btrfs_image) as dev:
        vol = _vol(helper, dev)
        info = helper.call("volume.mount", {"volume": vol["id"]}, timeout=120)
        assert any(o.startswith("subvolid=5") for o in info["options"])
        with RootFS(info["mountpoint"]) as fs:
            assert fs.read_file("/@home/notes.txt") == b"in a subvolume\n"
            assert fs.read_file("/@/etc/os-release").startswith(b"NAME=")
        helper.call("volume.unmount", {"volume": vol["id"]}, timeout=120)
    assert images.sha256(btrfs_image) == before


def _bitlk_dir() -> Path:
    path = os.environ.get("OFFSCAN_TEST_BITLK_DIR")
    if not path or not Path(path, "images.conf").exists():
        pytest.skip("BitLocker test images not available (set OFFSCAN_TEST_BITLK_DIR)")
    return Path(path)


@pytest.fixture
def bitlk(tmp_path: Path) -> Iterator[tuple[Path, configparser.SectionProxy]]:
    directory = _bitlk_dir()
    conf = configparser.ConfigParser()
    conf.read(directory / "images.conf")
    name = "bitlk-aes-xts-128"
    src = directory / f"{name}.img"
    img = tmp_path / f"{name}.img"
    img.write_bytes(src.read_bytes())
    yield img, conf[name]


@pytest.mark.parametrize("kind", ["password", "recovery_key"])
def test_bitlocker_unlock(bitlk, kind: str, no_leaks, helper) -> None:
    img, conf = bitlk
    secret = conf["PW"] if kind == "password" else conf["RP"].replace("-", " ")
    before = images.sha256(img)
    with images.attached(img) as dev:
        vol = _vol(helper, dev)
        assert vol["role"] == "bitlocker"
        res = helper.call("volume.unlock", {"volume": vol["id"], "secret": secret,
                                            "secret_kind": kind}, timeout=180)
        assert blockdev.get_ro(res["device"])
        # Same check as cryptsetup's own test suite: the decrypted device must
        # match the known plaintext hash.  (The test images' NTFS contents are
        # not complete enough to mount.)
        assert images.sha256(Path(res["device"])) == conf["SHA256SUM"]
        child = _vol(helper, dev)["children"][0]
        assert child["fstype"] == "ntfs"
        helper.call("volume.lock", {"volume": vol["id"]}, timeout=120)
    assert images.sha256(img) == before


def test_luks_quarantine_needs_the_passphrase(luks_image: Path, no_leaks, helper, tmp_path: Path) -> None:
    """Changes inside LUKS reopen it writable with the passphrase, then read-only again."""
    import hashlib
    import shutil

    from offscan.protocol import RemoteError
    copy = tmp_path / "luks-copy.img"
    shutil.copyfile(luks_image, copy)
    sha = hashlib.sha256(images.eicar()).hexdigest()
    with images.attached(copy) as dev:
        vol = _vol(helper, dev)
        unlocked = helper.call("volume.unlock", {"volume": vol["id"], "secret": PASSPHRASE}, timeout=120)
        child = unlocked["unlocked"]
        helper.call("volume.mount", {"volume": child}, timeout=120)
        plan = helper.call("remedy.plan", {"volume": child, "path": "/home/user/eicar.com"}, timeout=120)
        assert plan["possible"] and plan["needs_secret"] == [{"volume": vol["id"], "kind": "luks"}]
        request = {"volume": child, "path": "/home/user/eicar.com", "expect_sha256": sha,
                   "action": "quarantine", "confirm": True}
        with pytest.raises(RemoteError) as err:
            helper.call("remedy.apply", request, timeout=300)
        assert err.value.details["needs_secret"] == [{"volume": vol["id"], "kind": "luks"}]
        record = helper.call("remedy.apply", {**request, "secrets": {vol["id"]: {"secret": PASSPHRASE}}},
                             timeout=300)
        assert record["result"] == "ok" and not record["restore_errors"], record
        new_child = record["renamed"].get(child, child)
        listed = _vol(helper, dev)
        assert listed["encryption"]["unlocked"] and listed["children"][0]["id"] == new_child
        mountpoint = listed["children"][0]["mountpoint"]
        assert mountpoint and blockdev.get_ro(listed["children"][0]["device"])
        with RootFS(mountpoint) as fs:
            assert not fs.exists("/home/user/eicar.com")
        helper.call("volume.lock", {"volume": vol["id"]}, timeout=120)
