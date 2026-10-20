"""Quarantine, delete and restore: the one confirmed exception to read-only.

* Refused or mismatched requests never mount the volume writable (image unchanged).
* A confirmed quarantine removes exactly that file, keeps a scrambled copy, logs the
  change and leaves the volume mounted read-only again.
* Restore writes the file back with its mode; delete removes it.
* Hibernated Windows volumes are refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from offscan import appinfo
from offscan.helper import blockdev
from offscan.protocol import RemoteError
from offscan.safefs import RootFS

from . import images
from .conftest import find_disk, require

pytestmark = [pytest.mark.integration]

EICAR_SHA = hashlib.sha256(images.eicar()).hexdigest()


@pytest.fixture
def ext4_image(tmp_path: Path) -> Path:
    require("mkfs.ext4")
    src = tmp_path / "src"
    (src / "bad").mkdir(parents=True)
    (src / "bad/eicar.com").write_bytes(images.eicar())
    os.chmod(src / "bad/eicar.com", 0o750)
    (src / "bad/second.com").write_bytes(images.eicar() + b"\n")
    (src / "keep.txt").write_text("keep me\n")
    os.symlink("/bad/eicar.com", src / "link")
    img = tmp_path / "ext4.img"
    with open(img, "wb") as fh:
        fh.truncate(32 << 20)
    images.run("mkfs.ext4", "-q", "-F", "-d", str(src), str(img))
    return img


def _volume(helper, dev: str) -> str:
    disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
    return disk["volumes"][0]["id"]


def _apply(helper, vol: str, path: str, action: str, sha: str = EICAR_SHA, **extra) -> dict:
    return helper.call("remedy.apply", {"volume": vol, "path": path, "expect_sha256": sha,
                                        "action": action, "confirm": True, **extra}, timeout=300)


def test_quarantine_restore_delete(ext4_image: Path, no_leaks, helper, helper_env) -> None:
    state = Path(helper_env[appinfo.env("SYSTEM_STATE_DIR")])
    with images.attached(ext4_image) as dev:
        vol = _volume(helper, dev)
        before = images.sha256(ext4_image)
        plan = helper.call("remedy.plan", {"volume": vol, "path": "/bad/eicar.com"}, timeout=120)
        assert plan["possible"] is True and plan["sha256"] == EICAR_SHA and plan["size"] == 68
        assert plan["needs_secret"] == [] and plan["fstype"] == "ext4"
        with pytest.raises(RemoteError):                       # symlinks are never acted on
            helper.call("remedy.plan", {"volume": vol, "path": "/link"}, timeout=120)
        with pytest.raises(RemoteError) as err:
            helper.call("remedy.apply", {"volume": vol, "path": "/bad/eicar.com", "expect_sha256": EICAR_SHA,
                                         "action": "delete", "confirm": False}, timeout=120)
        assert err.value.code == "invalid_params"
        with pytest.raises(RemoteError) as err:
            _apply(helper, vol, "/bad/eicar.com", "delete", sha="0" * 64)
        assert err.value.code == "not_permitted"
        assert images.sha256(ext4_image) == before, "a refused request touched the disk"

        record = _apply(helper, vol, "/bad/eicar.com", "quarantine")
        assert record["result"] == "ok" and record["sha256"] == EICAR_SHA and record["quarantine_id"]
        assert record["fstype"] == "ext4" and "rw" in record["mount"]["options"]
        assert "noexec" in record["mount"]["options"] and "nosuid" in record["mount"]["options"]
        mountpoint = helper.call("volume.mount", {"volume": vol}, timeout=120)["mountpoint"]
        with RootFS(mountpoint) as fs:                         # read-only view again, file gone
            assert not fs.exists("/bad/eicar.com")
            assert fs.read_file("/keep.txt") == b"keep me\n"
            assert fs.read_file("/bad/second.com") == images.eicar() + b"\n"
        entries = helper.call("quarantine.list", {}, timeout=60)["entries"]
        (entry,) = [e for e in entries if e["id"] == record["quarantine_id"]]
        assert entry["path"] == "/bad/eicar.com" and entry["volume"] == vol
        stored = (state / "quarantine" / entry["id"] / "data").read_bytes()
        assert len(stored) == 68 and b"EICAR" not in stored        # scrambled
        assert stat.S_IMODE((state / "quarantine" / entry["id"]).stat().st_mode) == 0o700
        changes = [json.loads(line) for line in (state / "changes.jsonl").read_text().splitlines()]
        assert changes[-1]["action"] == "quarantine" and changes[-1]["path"] == "/bad/eicar.com"
        assert changes[-1]["uuid"] and changes[-1]["result"] == "ok"

        restored = helper.call("quarantine.restore", {"id": entry["id"], "volume": vol, "confirm": True},
                               timeout=300)
        assert restored["result"] == "ok"
        mountpoint = helper.call("volume.mount", {"volume": vol}, timeout=120)["mountpoint"]
        with RootFS(mountpoint) as fs:
            assert fs.read_file("/bad/eicar.com") == images.eicar()
            assert stat.S_IMODE(fs.lstat("/bad/eicar.com").st_mode) == 0o750
        assert not (state / "quarantine" / entry["id"]).exists()

        deleted = _apply(helper, vol, "/bad/second.com", "delete",
                         sha=hashlib.sha256(images.eicar() + b"\n").hexdigest())
        assert deleted["result"] == "ok" and "quarantine_id" not in deleted
        with RootFS(helper.call("volume.mount", {"volume": vol}, timeout=120)["mountpoint"]) as fs:
            assert not fs.exists("/bad/second.com") and fs.exists("/bad/eicar.com")
        listed = helper.call("changes.list", {"limit": 10}, timeout=60)["changes"]
        assert [c["action"] for c in listed[-3:]] == ["quarantine", "restore", "delete"]
        helper.call("volume.unmount", {"volume": vol}, timeout=120)
    # Outside the helper: the filesystem is consistent and has exactly those changes.
    proc = images.run("e2fsck", "-fn", str(ext4_image), check=False)
    assert proc.returncode == 0, proc.stdout.decode()[-2000:]


def test_restore_goes_back_only_where_it_came_from(tmp_path: Path, no_leaks, helper) -> None:
    """A quarantined file cannot be planted on another filesystem, and loses setuid/setgid."""
    require("mkfs.ext4")
    imgs = []
    for name in ("a", "b"):
        src = tmp_path / f"src-{name}"
        (src / "bin").mkdir(parents=True)
        (src / "bin/tool").write_bytes(images.eicar())
        os.chmod(src / "bin/tool", 0o6755)
        img = tmp_path / f"{name}.img"
        with open(img, "wb") as fh:
            fh.truncate(32 << 20)
        images.run("mkfs.ext4", "-q", "-F", "-d", str(src), str(img))
        imgs.append(img)
    with images.attached(imgs[0]) as dev_a, images.attached(imgs[1]) as dev_b:
        vol_a, vol_b = _volume(helper, dev_a), _volume(helper, dev_b)
        record = _apply(helper, vol_a, "/bin/tool", "quarantine")
        before_b = images.sha256(imgs[1])
        with pytest.raises(RemoteError) as err:
            helper.call("quarantine.restore", {"id": record["quarantine_id"], "volume": vol_b,
                                               "path": "/bin/planted", "confirm": True}, timeout=300)
        assert err.value.code == "not_permitted" and "came from" in err.value.message
        assert images.sha256(imgs[1]) == before_b, "the other filesystem was touched"
        restored = helper.call("quarantine.restore", {"id": record["quarantine_id"], "volume": vol_a,
                                                      "confirm": True}, timeout=300)
        assert restored["result"] == "ok"
        with RootFS(helper.call("volume.mount", {"volume": vol_a}, timeout=120)["mountpoint"]) as fs:
            mode = fs.lstat("/bin/tool").st_mode
        assert stat.S_IMODE(mode) == 0o755                      # setuid and setgid are gone
        helper.call("volume.unmount", {"volume": vol_a}, timeout=120)


def test_hibernated_windows_is_refused(target_disk, helper) -> None:
    dev, _ = target_disk
    disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
    windows = {v["device"]: v["id"] for v in disk["volumes"]}[f"{dev}p2"]
    helper.call("volume.probe", {"volume": windows}, timeout=120)
    plan = helper.call("remedy.plan", {"volume": windows, "path": "/Users/Alice/Downloads/eicar.com"},
                       timeout=120)
    assert plan["possible"] is False and "hibernated" in plan["reason"]
    with pytest.raises(RemoteError):
        _apply(helper, windows, "/Users/Alice/Downloads/eicar.com", "delete")
    # target_disk asserts afterwards that the image is byte-for-byte unchanged.


def test_other_partition_stays_protected(tmp_path: Path, no_leaks, helper) -> None:
    """A writable session on p1 must not expose p2, which shares the disk-wide read-only flag."""
    require("sfdisk", "mkfs.ext4")
    img = tmp_path / "two.img"
    images.make_disk(img, 80, [("L", 32), ("L", 0)])
    with images.attached(img, partscan=True) as dev:
        images.run("mkfs.ext4", "-q", "-F", f"{dev}p1")
        images.run("mkfs.ext4", "-q", "-F", f"{dev}p2")
        with images.mounted(f"{dev}p1", "ext4") as mnt:
            (mnt / "eicar.com").write_bytes(images.eicar())
    with images.attached(img, partscan=True) as dev:
        disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
        vols = {v["device"]: v["id"] for v in disk["volumes"]}
        p1, p2 = vols[f"{dev}p1"], vols[f"{dev}p2"]
        helper.call("volume.mount", {"volume": p2}, timeout=120)
        helper.call("volume.mount", {"volume": p1}, timeout=120)
        assert blockdev.get_ro(dev)                          # disk-wide flag (no host use)
        record = _apply(helper, p1, "/eicar.com", "quarantine")
        assert record["result"] == "ok" and not record["restore_errors"]
        assert blockdev.get_ro(dev) and blockdev.get_ro(f"{dev}p2")      # protection is back
        listed = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
        mounted = {v["id"]: v["mountpoint"] for v in listed["volumes"]}
        assert mounted[p1] and mounted[p2]                   # both read-only mounts restored
        helper.call("session.cleanup", {}, timeout=120)
        assert not blockdev.get_ro(dev) and not blockdev.get_ro(f"{dev}p2")


def test_cli_quarantine_restore(ext4_image: Path, no_leaks, helper_env, tmp_path: Path) -> None:
    """The same flow through the command line (it starts its own helper)."""
    import subprocess
    import sys

    env = {**os.environ, **helper_env, "PYTHONPATH": helper_env["PYTHONPATH"]}

    def cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "offscan", *args], env=env, input=stdin, text=True,
                              capture_output=True, timeout=300, check=False)

    with images.attached(ext4_image) as dev:
        vol = os.path.basename(dev)
        refused = cli("delete", vol, "/bad/eicar.com", stdin="no\n")
        assert refused.returncode == 4 and "nothing was changed" in refused.stdout
        done = cli("quarantine", vol, "/bad/eicar.com", "--yes")
        assert done.returncode == 0, done.stderr
        assert "moved to quarantine" in done.stdout and EICAR_SHA in done.stdout
        entries = json.loads(cli("quarantined", "--json").stdout)
        assert [e["path"] for e in entries] == ["/bad/eicar.com"]
        restored = cli("restore", entries[0]["id"], "--yes")
        assert restored.returncode == 0, restored.stderr
        changes = json.loads(cli("changes", "--json").stdout)
        assert [c["action"] for c in changes] == ["quarantine", "restore"]
