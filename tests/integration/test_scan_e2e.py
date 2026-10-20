"""End-to-end scans through the real helper with all three engines.

* The dirty fixture disk: EICAR on ext4 and NTFS must be found by the hash
  matcher, YARA and ClamAV, and the image must stay byte-for-byte unchanged.
* A hostile ext4 image (symlink loops, absolute links to host files, device
  nodes, FIFOs, non-UTF-8 and newline filenames, a sparse 5 GiB file, a zip
  bomb, EICAR hidden in a zip) must scan to completion without escaping,
  hanging or crashing.
"""

from __future__ import annotations

import io
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from offscan import names, reports
from offscan.client import HelperClient
from offscan.defs import testset
from offscan.history import History
from offscan.scan.options import ScanOptions
from offscan.scanning import ScanSession

from . import images
from .conftest import find_disk, require

pytestmark = [pytest.mark.integration, pytest.mark.slow]


@pytest.fixture(scope="module")
def test_defs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    pytest.importorskip("yara_x")
    out = tmp_path_factory.mktemp("defs") / "set"
    testset.build_test_set(out)
    # Unprivileged engines must be able to read the set through hard links.
    for path in out.rglob("*"):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    return out


def _engines_found(dets: list, path_suffix: str) -> set[str]:
    return {d.engine for d in dets if d.path.lower().endswith(path_suffix)}


def _clamav_available() -> bool:
    return shutil.which("clamd", path=images.ENV["PATH"]) is not None


def test_scan_dirty_disk_all_engines(target_disk, helper, test_defs, tmp_path) -> None:
    dev, _ = target_disk
    disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
    vols = {v["device"]: v["id"] for v in disk["volumes"]}
    targets = [vols[f"{dev}p1"], vols[f"{dev}p2"]]
    events: list[tuple[str, object]] = []
    history = History(tmp_path / "history.sqlite3")
    session = ScanSession(helper, ScanOptions(volumes=targets, mode="full", workers=2), test_defs,
                          on_event=lambda e, d: events.append((e, d)), history=history)
    summary = session.run()
    assert summary["state"] == "finished", summary
    assert summary["files_scanned"] >= 4
    expected = {"hash", "yara"} | ({"clamav"} if _clamav_available() else set())
    assert _engines_found(session.detections, "/home/user/eicar.com") == expected
    assert _engines_found(session.detections, "/users/alice/downloads/eicar.com") == expected
    kinds = {e for e, _ in events}
    assert {"scan.progress", "scan.detection", "scan.status"} <= kinds
    from offscan import appinfo
    assert not list(Path("/tmp").glob(f"{appinfo.NAME}-scan-*")), "runtime dir not cleaned up"
    # History and reports.
    (record,) = history.scans()
    counted = record["summary"]["detections"] + record["summary"]["inventory"]
    assert counted == len(session.detections)
    report = reports.build(summary, session.options.to_dict(), session.targets,
                           [d.to_dict() for d in session.detections], session.definitions)
    for kind in ("html", "json", "csv"):
        out = tmp_path / f"report.{kind}"
        reports.write(report, str(out))
        assert "eicar.com" in out.read_text().lower()
    # Quick mode finds the same files (.com is an executable extension).
    quick = ScanSession(helper, ScanOptions(volumes=targets, mode="quick"), test_defs)
    quick.run()
    assert _engines_found(quick.detections, "/home/user/eicar.com") == expected


def test_persistence_and_integrity(target_disk, helper, test_defs, tmp_path) -> None:
    """Autostart entries and package checks on the fixture disk, in quick mode."""
    dev, _ = target_disk
    disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
    vols = {v["device"]: v["id"] for v in disk["volumes"]}
    linux, windows = vols[f"{dev}p1"], vols[f"{dev}p2"]
    session = ScanSession(helper, ScanOptions(volumes=[linux, windows], mode="quick", workers=2), test_defs)
    summary = session.run()
    assert summary["state"] == "finished", summary
    found = {(d.volume, d.details.get("check"), d.severity) for d in session.detections
             if d.engine in ("persistence", "integrity")}
    # The cron entry is "low": the program it starts lives in a hidden folder.
    for check, severity in (("linux.cron", "low"), ("linux.systemd", "high"), ("linux.ld_preload", "high"),
                            ("linux.ssh_key", "info"), ("integrity.package_modified", "high"),
                            ("integrity.setid", "high")):
        assert (linux, check, severity) in found, (check, sorted(found))
    assert (windows, "windows.run_key", "high") in found                 # Alice's encoded PowerShell
    # Programs started by autostart entries are scanned even in folders quick scans skip.
    forced = {(d.volume, d.path) for d in session.detections if d.engine == "hash"}
    assert (linux, "/usr/share/doc/.cache/helper") in forced
    assert (windows, "/Windows/Fonts/fontcache.dat") in forced
    modified = next(d for d in session.detections if d.details.get("check") == "integrity.package_modified")
    assert modified.path == "/usr/bin/ls" and modified.details["package"] == "coreutils"
    checks = summary["checks"]
    assert checks[linux]["integrity"]["manager"] == "dpkg"
    assert checks[windows]["kind"] == "windows" and checks[windows]["persistence"]["findings"] >= 2
    assert summary["inventory"] >= 2 and summary["detections"] >= 8
    report = reports.build(summary, session.options.to_dict(), session.targets,
                           [d.to_dict() for d in session.detections], session.definitions)
    page = reports.to_html(report)
    assert "Persistence and integrity" in page and "/etc/ld.so.preload" in page
    # Opting out skips the checks.
    opts = ScanOptions(volumes=[linux], mode="quick", persistence=False, integrity=False)
    plain = ScanSession(helper, opts, test_defs)
    plain_summary = plain.run()
    assert not [d for d in plain.detections if d.engine in ("persistence", "integrity")]
    assert not plain_summary["checks"]


def _zip_bytes(members: dict[str, bytes], compress: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture(scope="module")
def hostile_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    require("mkfs.ext4")
    work = tmp_path_factory.mktemp("hostile")
    src = work / "src"
    src.mkdir()
    (src / "etc").mkdir()
    os.symlink("/etc/shadow", src / "etc" / "shadow-link")
    os.symlink("/", src / "root-link")
    os.symlink("loop-b", src / "loop-a")
    os.symlink("loop-a", src / "loop-b")
    os.symlink("..", src / "etc" / "up")
    os.mkfifo(src / "fifo")
    os.mknod(src / "null-dev", 0o600 | 0o020000, os.makedev(1, 3))
    weird = os.fsdecode(b"bad\nname\xff\xfe\x1b[31m.exe")
    (src / weird).write_bytes(testset.eicar())
    (src / "inside.zip").write_bytes(_zip_bytes({"docs/readme.txt": b"hello",
                                                 "payload/eicar.com": testset.eicar()}))
    zeros = _zip_bytes({"zeros.bin": b"\0" * (64 << 20)})
    layer = zeros
    for i in range(20):                       # deep nesting
        layer = _zip_bytes({f"level{i}.zip": layer})
    (src / "bomb.zip").write_bytes(_zip_bytes({f"part{i}.zip": zeros for i in range(16)}))
    (src / "deep.zip").write_bytes(layer)
    with open(src / "huge-sparse.img", "wb") as fh:
        fh.truncate(5 << 30)
    img = work / "hostile.img"
    with open(img, "wb") as fh:
        fh.truncate(96 << 20)
    images.run("mkfs.ext4", "-q", "-F", "-d", str(src), str(img))
    return img


def test_scan_hostile_filesystem(hostile_image: Path, no_leaks, helper: HelperClient,
                                 test_defs: Path) -> None:
    before = images.sha256(hostile_image)
    with images.attached(hostile_image) as dev:
        disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
        vol = disk["volumes"][0]["id"]
        session = ScanSession(helper, ScanOptions(volumes=[vol], mode="full", workers=2), test_defs)
        summary = session.run()
    assert summary["state"] == "finished", summary
    paths = {names.from_wire(d.path) for d in session.detections}
    assert b"/bad\nname\xff\xfe\x1b[31m.exe" in paths            # exact bytes survive
    assert not any(b"shadow" in p or p.startswith(b"/root-link") for p in paths)
    if _clamav_available():
        zip_hits = [d for d in session.detections if d.path == "/inside.zip"]
        assert zip_hits and zip_hits[0].engine == "clamav"     # found inside the archive
    # The 5 GiB sparse file is over the hash limit: skipped, not read.
    assert summary["files_skipped"] >= 1
    assert images.sha256(hostile_image) == before


@pytest.fixture(scope="module")
def many_files_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    require("mkfs.ext4")
    work = tmp_path_factory.mktemp("many")
    src = work / "src"
    for i in range(100):
        d = src / f"dir{i:02d}"
        d.mkdir(parents=True)
        for j in range(200):
            (d / f"file{j:03d}.bin").write_bytes(os.urandom(1024))
    img = work / "many.img"
    with open(img, "wb") as fh:
        fh.truncate(128 << 20)
    images.run("mkfs.ext4", "-q", "-F", "-N", "30000", "-d", str(src), str(img))
    return img


def test_pause_resume_cancel(many_files_image: Path, no_leaks, helper: HelperClient,
                             test_defs: Path) -> None:
    import threading
    import time as _time
    progress: list[dict] = []
    started = threading.Event()

    def on_event(event: str, data: object) -> None:
        if event == "scan.progress" and isinstance(data, dict):
            progress.append(data)
            if data["files_done"] > 0:
                started.set()

    with images.attached(many_files_image) as dev:
        disk = find_disk(helper.call("drives.list", {"probe": "none"})["disks"], dev)
        vol = disk["volumes"][0]["id"]
        session = ScanSession(helper, ScanOptions(volumes=[vol], mode="full", workers=1,
                                                  engines=["hashes", "yara"]),
                              test_defs, on_event=on_event)
        result: dict = {}
        thread = threading.Thread(target=lambda: result.update(session.run() or {}))
        thread.start()
        assert started.wait(120), "scan did not start"
        session.pause()
        _time.sleep(1.5)
        frozen = progress[-1]["files_done"]
        _time.sleep(1.5)
        assert progress[-1]["files_done"] <= frozen + 2      # in-flight files may finish
        assert progress[-1]["paused"] is True
        session.resume()
        deadline = _time.monotonic() + 60
        while progress[-1]["files_done"] <= frozen + 2 and _time.monotonic() < deadline:
            _time.sleep(0.01)
        session.pause()                                       # cancel while paused: deterministic
        assert progress[-1]["files_done"] > frozen
        session.cancel()
        thread.join(120)
        assert not thread.is_alive()
    assert result["state"] == "cancelled"
    assert 0 < result["files_scanned"] < 20000
