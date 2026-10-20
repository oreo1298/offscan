"""Root-helper hardening: mount visibility, trusted mount sources, the running system's boot partitions."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from offscan import paths
from offscan.drives import mountinfo, system
from offscan.helper import acl


def test_acl_encoding_round_trips() -> None:
    data = acl.encode(0o7, {1000: 0o5, 1001: 0o4})
    entries = acl.decode(data)
    tags = [e[0] for e in entries]
    assert tags == [acl.USER_OBJ, acl.USER, acl.USER, acl.GROUP_OBJ, acl.MASK, acl.OTHER]
    assert (acl.USER, 0o5, 1000) in entries and (acl.MASK, 0o5, acl.UNDEFINED_ID) in entries
    assert entries[-1] == (acl.OTHER, 0, acl.UNDEFINED_ID)
    with pytest.raises(ValueError):
        acl.decode(b"\x01\x00\x00\x00")


def _can_enter(path: Path, uid: int) -> bool:
    result = subprocess.run(["/bin/ls", str(path)], user=uid, group=uid, extra_groups=[],
                            capture_output=True, check=False)
    return result.returncode == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to act as other users")
def test_mount_root_admits_only_the_invoking_user() -> None:
    import pwd
    nobody = pwd.getpwnam("nobody").pw_uid
    other = next(uid for uid in range(60000, 60100) if uid != nobody)
    base = Path(tempfile.mkdtemp(dir="/var/tmp"))
    try:
        os.chmod(base, 0o755)
        root = base / "mnt"
        root.mkdir()
        (root / "volume").mkdir()
        os.chmod(root / "volume", 0o755)              # like a mounted filesystem's root
        if not acl.restrict_to(str(root), [nobody]):
            pytest.skip("no ACL support here")
        assert _can_enter(root / "volume", nobody)
        assert not _can_enter(root / "volume", other)  # every other local account is kept out
    finally:
        shutil.rmtree(base)


def test_our_mounts(xdg_home: Path) -> None:
    assert paths.is_our_mount(str(paths.mount_root() / "sdb1"))
    assert paths.is_our_mount(str(paths.private_root() / "rw-sdb1"))
    assert not paths.is_our_mount("/media/user/disk")
    assert not paths.is_our_mount(str(paths.runtime_dir()) + "-other/x")


def _entry(fstype: str, source: str, majmin: str = "0:55", super_options: str = "rw") -> mountinfo.MountEntry:
    return mountinfo.MountEntry(1, 0, majmin, "/", "/media/x", ("rw",), fstype, source,
                                tuple(super_options.split(",")))


def test_user_fuse_mounts_cannot_claim_a_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system, "kname_for_majmin", lambda majmin: None)
    monkeypatch.setattr(system, "kname_for_path", lambda path: "sdb1")
    # any user can start a FUSE mount that calls itself /dev/sdb1
    assert system.mount_kname(_entry("fuse.sshfs", "/dev/sdb1", super_options="user_id=1000")) is None
    assert system.mount_kname(_entry("fuseblk", "/dev/sdb1", super_options="user_id=1000")) is None
    # root's ntfs-3g mount of the device is believed
    assert system.mount_kname(_entry("fuseblk", "/dev/sdb1", super_options="user_id=0,group_id=0")) == "sdb1"


def test_automounted_esp_counts_as_system(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fstab = tmp_path / "fstab"
    fstab.write_text("UUID=1234-ABCD  /boot/efi  vfat  umask=0077,x-systemd.automount  0 1\n")
    seen = []
    monkeypatch.setattr(system, "kname_for_path", lambda path: seen.append(path) or "nvme0n1p1")
    assert system._fstab_kname("/boot/efi", str(fstab)) == "nvme0n1p1"
    assert seen == ["/dev/disk/by-uuid/1234-ABCD"]
    assert system._fstab_kname("/home", str(fstab)) is None
