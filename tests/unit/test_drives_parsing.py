import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from offscan.drives import hibernation, lsblk, mountinfo, osdetect, superblock
from offscan.safefs import RootFS, UnsafePath

LSBLK_JSON = {
    "blockdevices": [
        {"name": "sda", "kname": "sda", "path": "/dev/sda", "maj:min": "8:0", "type": "disk",
         "size": 500107862016, "model": "Samsung SSD 860", "vendor": "ATA     ", "serial": "S3Z",
         "tran": "sata", "rm": False, "hotplug": False, "ro": False, "fstype": None,
         "pkname": None, "mountpoints": [None],
         "children": [
             {"name": "sda1", "kname": "sda1", "path": "/dev/sda1", "maj:min": "8:1",
              "type": "part", "size": 272629760, "fstype": "vfat", "fsver": "FAT32",
              "label": "SYSTEM", "uuid": "1234-ABCD", "rm": False, "hotplug": False, "ro": False,
              "pkname": "sda", "mountpoints": [None]},
             {"name": "sda3", "kname": "sda3", "path": "/dev/sda3", "maj:min": "8:3",
              "type": "part", "size": 499000000000, "fstype": "BitLocker", "fsver": "2",
              "rm": "0", "hotplug": "0", "ro": "0", "pkname": "sda", "mountpoints": [None]},
             {"name": "sda4", "kname": "sda4", "path": "/dev/sda4", "maj:min": "8:4",
              "type": "part", "size": 1000, "fstype": "crypto_LUKS", "pkname": "sda",
              "mountpoints": [None],
              "children": [{"name": "luks-x", "kname": "dm-0", "path": "/dev/mapper/luks-x",
                            "maj:min": "253:0", "type": "crypt", "size": 900, "fstype": "ext4",
                            "pkname": "sda4", "mountpoints": ["/", "/home"]}]},
         ]},
    ]
}


def test_lsblk_parse_and_flatten() -> None:
    roots = lsblk.parse(json.dumps(LSBLK_JSON))
    flat = lsblk.flatten(roots)
    assert set(flat) == {"sda", "sda1", "sda3", "sda4", "dm-0"}
    assert flat["sda"].vendor == "ATA" and flat["sda"].mountpoints == []
    assert flat["sda3"].fstype == "BitLocker" and flat["sda3"].removable is False
    assert flat["dm-0"].mountpoints == ["/", "/home"]
    assert flat["sda1"].label == "SYSTEM"


def test_lsblk_old_mountpoint_field() -> None:
    data = {"blockdevices": [{"name": "sdb", "kname": "sdb", "type": "disk", "size": "10",
                              "mountpoint": "/mnt/x"}]}
    (dev,) = lsblk.parse(json.dumps(data))
    assert dev.mountpoints == ["/mnt/x"] and dev.size == 10 and dev.path == "/dev/sdb"


MOUNTINFO = """\
22 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/luks-x rw
30 22 8:1 / /boot/efi rw,relatime shared:2 - vfat /dev/sda1 rw,fmask=0077
41 22 8:17 / /media/me/My\\040Disk rw,nosuid,nodev - fuseblk /dev/sdb1 rw,user_id=0
50 22 7:3 / /run/offscan/mnt/sdc1 ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/loop3 ro,norecovery
"""


def test_mountinfo_parse() -> None:
    entries = mountinfo.parse(MOUNTINFO)
    assert [e.mountpoint for e in entries] == ["/", "/boot/efi", "/media/me/My Disk",
                                               "/run/offscan/mnt/sdc1"]
    assert entries[2].fstype == "fuseblk" and entries[2].source == "/dev/sdb1"
    assert entries[3].readonly and "nosymfollow" in entries[3].options
    assert not entries[0].readonly


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None or os.path.exists(f"/usr/sbin/{tool}")


@pytest.mark.skipif(not _have("mkfs.ext4"), reason="mkfs.ext4 missing")
def test_ext4_superblock_clean(tmp_path: Path) -> None:
    img = tmp_path / "x.img"
    img.write_bytes(b"\0" * (8 << 20))
    subprocess.run(["mkfs.ext4", "-q", "-F", str(img)], check=True,
                   env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin"})
    state = superblock.probe(str(img), "ext4")
    assert state is not None and state.clean is True and not state.needs_recovery


def test_ext4_superblock_flags() -> None:
    sb = bytearray(1024)
    struct.pack_into("<H", sb, 0x38, superblock.EXT4_MAGIC)
    struct.pack_into("<H", sb, 0x3A, superblock.EXT4_STATE_VALID)
    struct.pack_into("<I", sb, 0x60, superblock.EXT4_INCOMPAT_RECOVER)
    struct.pack_into("<I", sb, 0xE8, 12)
    state = superblock.ext4_state(bytes(sb))
    assert state and state.needs_recovery and state.orphans and state.clean is False
    assert superblock.ext4_state(b"\0" * 1024) is None


def test_btrfs_superblock_log_root() -> None:
    sb = bytearray(4096)
    sb[0x40:0x48] = superblock.BTRFS_MAGIC
    assert superblock.btrfs_state(bytes(sb)).needs_recovery is False
    struct.pack_into("<Q", sb, 0x60, 30408704)
    assert superblock.btrfs_state(bytes(sb)).needs_recovery is True


def test_bitlocker_signature() -> None:
    assert superblock.looks_like_bitlocker(b"\xeb\x58\x90-FVE-FS-" + b"\0" * 100)
    assert not superblock.looks_like_bitlocker(b"\xeb\x52\x90NTFS    " + b"\0" * 100)


@pytest.mark.parametrize("header,size,hibernated", [
    (b"HIBR" + b"\0" * 100, 1 << 30, True),
    (b"hibr" + b"\0" * 100, 1 << 30, True),
    (b"wake" + b"\0" * 100, 1 << 30, False),
    (b"RSTR" + b"\0" * 100, 1 << 30, False),
    (b"\0" * 4096, 1 << 30, False),
    (b"", 0, False),
    (b"\x01\x02\x03\x04", 1 << 30, True),
])
def test_hibernation_header(header: bytes, size: int, hibernated: bool) -> None:
    state = hibernation.classify_header(header, size)
    assert state.hibernated is hibernated
    if hibernated:
        assert "Shift" in state.explain()


def test_os_release_parsing() -> None:
    text = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n# c\nBAD LINE\nID=ubuntu\n' \
           "X='$(rm -rf /)'\n"
    info = osdetect.parse_os_release(text)
    assert info["PRETTY_NAME"] == "Ubuntu 24.04.1 LTS" and info["ID"] == "ubuntu"
    assert info["X"] == "$(rm -rf /)"   # stored as plain text, never evaluated


@pytest.mark.parametrize("values,name,version,build", [
    ({"ProductName": "Windows 10 Pro", "CurrentBuild": "22631", "UBR": 4317,
      "DisplayVersion": "23H2", "EditionID": "Professional"}, "Windows 11 Pro", "23H2", "22631.4317"),
    ({"ProductName": "Windows 10 Home", "CurrentBuild": "19045", "UBR": 5011,
      "DisplayVersion": "22H2"}, "Windows 10 Home", "22H2", "19045.5011"),
    ({"ProductName": "Windows 7 Professional", "CurrentBuildNumber": "7601",
      "CSDVersion": "Service Pack 1"}, "Windows 7 Professional", "Service Pack 1", "7601"),
    ({}, "Windows", None, None),
])
def test_windows_version_mapping(values: dict, name: str, version: str | None, build: str | None) -> None:
    info = osdetect.windows_version_from_values(values)
    assert (info.name, info.version, info.build) == (name, version, build)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/os-release").write_text('PRETTY_NAME="Target OS"\n')
    os.symlink("../usr/lib/os-release", root / "etc/os-release")
    os.symlink("/usr/lib/os-release", root / "etc/abs-link")
    os.symlink("/etc/hostname", root / "etc/host-escape")
    os.symlink("../../../../../../etc/passwd", root / "etc/dotdot-escape")
    os.symlink("loop2", root / "loop1")
    os.symlink("loop1", root / "loop2")
    os.mkfifo(root / "fifo")
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SOFTWARE").write_bytes(b"regf")
    (root / "hiberfil.sys").write_bytes(b"HIBR" + b"\0" * 4092)
    return root


def test_rootfs_resolves_inside_root(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    with RootFS(root) as fs:
        assert fs.read_file("/etc/os-release") == b'PRETTY_NAME="Target OS"\n'
        assert fs.read_file("etc/abs-link") == b'PRETTY_NAME="Target OS"\n'
        assert fs.realpath("/etc/os-release") == b"/usr/lib/os-release"
        # Absolute and ../ links must stay inside the target, never reach the host.
        with pytest.raises(FileNotFoundError):
            fs.read_file("/etc/host-escape")
        with pytest.raises(FileNotFoundError):
            fs.read_file("/etc/dotdot-escape")
        assert fs.realpath("/etc/dotdot-escape") == b"/etc/passwd"
        with pytest.raises(UnsafePath):
            fs.read_file("/loop1")
        with pytest.raises(UnsafePath):
            fs.read_file("/fifo")
        assert fs.find_ci("windows/system32/CONFIG/software") == b"/Windows/System32/config/SOFTWARE"
        assert fs.find_ci("nope/x") is None


def test_os_and_hibernation_detection(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    with RootFS(root) as fs:
        assert osdetect.detect_linux(fs).name == "Target OS"
        assert osdetect.windows_hive(fs) == b"/Windows/System32/config/SOFTWARE"
        hib = hibernation.detect(fs)
        assert hib is not None and hib.hibernated
