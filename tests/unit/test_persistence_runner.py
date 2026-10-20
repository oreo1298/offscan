"""Finding installations on a volume, the checks runner, and how findings reach history and reports."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from offscan import reports
from offscan.history import History
from offscan.persistence import runner
from offscan.scan.results import Detection
from support.linuxroot import build_linux_root
from support.regwriter import Key, write_hive


def _windows(root: Path) -> Path:
    (root / "Windows/System32/config").mkdir(parents=True)
    hive = Key("ROOT")
    hive.key("Microsoft\\Windows\\CurrentVersion\\Run").set("x", "C:\\Users\\Public\\x.exe")
    write_hive(hive, root / "Windows/System32/config/SOFTWARE", "SOFTWARE")
    return root


def test_find_roots(tmp_path: Path) -> None:
    win = _windows(tmp_path / "win")
    assert [(r.kind, r.prefix) for r in runner.find_roots("w", str(win))] == [("windows", b"")]

    plain = build_linux_root(tmp_path / "plain")
    assert [(r.kind, r.prefix, r.name) for r in runner.find_roots("p", str(plain))] == \
        [("linux", b"", "Debian GNU/Linux 13")]

    btrfs = tmp_path / "btrfs"
    build_linux_root(btrfs / "@")
    (btrfs / "@home/alice/.config").mkdir(parents=True)
    (btrfs / "@snapshots").mkdir()
    assert [(r.kind, r.prefix) for r in runner.find_roots("b", str(btrfs))] == \
        [("linux", b"/@"), ("linux_home", b"/@home")]

    home = tmp_path / "home"
    (home / "bob/.local").mkdir(parents=True)
    assert [(r.kind, r.prefix) for r in runner.find_roots("h", str(home))] == [("linux_home", b"")]

    data = tmp_path / "data"
    (data / "photos").mkdir(parents=True)
    assert runner.find_roots("d", str(data)) == []


def test_subvolume_link_cannot_escape(tmp_path: Path) -> None:
    vol = tmp_path / "vol"
    vol.mkdir()
    (vol / "@").symlink_to("/")                   # would be the host's root if followed naively
    roots = runner.find_roots("v", str(vol))
    assert roots == [] or all(r.prefix != b"/@" for r in roots)


def _dpkg(root: Path, packaged: bytes, actual: bytes) -> None:
    (root / "var/lib/dpkg/info").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text("Package: coreutils\nStatus: install ok installed\n\n")
    (root / "var/lib/dpkg/info/coreutils.md5sums").write_text(
        f"{hashlib.md5(packaged).hexdigest()}  usr/bin/ls\n")
    (root / "usr/bin/ls").write_bytes(actual)


def test_runner_end_to_end(tmp_path: Path) -> None:
    vol = tmp_path / "vol"
    build_linux_root(vol / "@")
    _dpkg(vol / "@", b"real ls", b"trojaned ls")
    emitted: list[Detection] = []
    statuses: list[str] = []
    checks = runner.ChecksRunner({"vol1": str(vol)}, "quick", [], None, emitted.append,
                                 lambda phase, msg, extra: statuses.append(phase), threading.Event())
    checks.discover()
    checks.persistence()
    setid = {"vol1": [{"path": b"/@/tmp/.x/rootshell", "mode": 0o104755, "uid": 0},
                      {"path": b"/elsewhere/s", "mode": 0o104755, "uid": 0}]}
    checks.integrity(setid)
    by_check: dict[str, list[Detection]] = {}
    for det in emitted:
        by_check.setdefault(det.details["check"], []).append(det)
    cron = next(d for d in by_check["linux.cron"] if "198.51.100.7" in d.details["value"])
    assert cron.engine == "persistence" and cron.severity == "high"
    assert cron.path == "/@/etc/crontab" and cron.details["root"] == "/@"
    assert cron.details["installation"] == "Debian GNU/Linux 13"
    assert b"/@/tmp/.x/payload" in checks.targets["vol1"]               # volume-relative
    modified = by_check["integrity.package_modified"][0]
    assert modified.path == "/@/usr/bin/ls" and modified.severity == "high"
    assert modified.engine == "integrity" and modified.source == "dpkg"
    setid_paths = [d.path for d in by_check["integrity.setid"]]
    assert setid_paths == ["/@/tmp/.x/rootshell"]
    info = checks.summary["vol1:/@"]
    assert info["integrity"]["manager"] == "dpkg" and info["integrity"]["modified"] == 1
    assert info["persistence"]["findings"] > 10
    assert {"persistence", "integrity"} <= set(statuses)
    # Two scans of the same tree give the same fingerprints (false-positive marks stick).
    again: list[Detection] = []
    second = runner.ChecksRunner({"vol1": str(vol)}, "quick", [], None, again.append,
                                 lambda *a: None, threading.Event())
    second.discover()
    second.persistence()
    assert sorted(d.identity for d in again) == sorted(d.identity for d in emitted
                                                        if d.engine == "persistence")


def test_cancel_stops_checks(tmp_path: Path) -> None:
    vol = build_linux_root(tmp_path / "vol")
    stop = threading.Event()
    stop.set()
    emitted: list[Detection] = []
    checks = runner.ChecksRunner({"v": str(vol)}, "quick", [], None, emitted.append, lambda *a: None, stop)
    checks.discover()
    checks.persistence()
    checks.integrity({})
    assert emitted == []


def test_false_positive_by_fingerprint(tmp_path: Path) -> None:
    history = History(tmp_path / "h.sqlite3")
    det = Detection("v", "/etc/crontab", "persistence", "Scheduled command (root)", "medium",
                    details={"fingerprint": "ab" * 32, "location": "/etc/crontab:3"})
    assert det.identity == "ab" * 32 and not det.inventory
    assert not history.is_false_positive(det)
    history.mark_false_positive(det.engine, det.signature, det.identity)
    assert history.is_false_positive(det)
    info = Detection("v", "/etc/crontab", "persistence", "x", "info", details={"location": "a"})
    assert info.inventory
    assert info.key != Detection("v", "/etc/crontab", "persistence", "x", "info",
                                 details={"location": "b"}).key
    history.close()


def test_reports_show_findings(tmp_path: Path) -> None:
    dets = [
        Detection("v", "/etc/crontab", "persistence", "Scheduled <b>command</b>", "high",
                  category="linux.cron",
                  details={"location": "/etc/crontab:4", "value": "curl x | sh <script>",
                           "check": "linux.cron", "reasons": ["downloads and runs a script"],
                           "mitre": "T1053.003"}).to_dict(),
        Detection("v", "/etc/cron.d/x", "persistence", "Scheduled command", "info",
                  details={"location": "/etc/cron.d/x:1", "value": "/usr/bin/true"}).to_dict(),
        Detection("v", "/eicar.com", "hash", "EICAR", "info", sha256="0" * 64).to_dict(),
    ]
    summary = {"state": "finished", "started": 1, "finished": 2, "checks": {
        "v": {"installation": "Debian", "persistence": {"findings": 2},
              "integrity": {"manager": "dpkg", "checked": 10, "packages": 3, "modified": 0}}}}
    report = reports.build(summary, {"mode": "quick"}, [], dets)
    page = reports.to_html(report)
    assert "Persistence and integrity" in page and "T1053.003" in page
    assert "<script>" not in page and "&lt;script&gt;" in page and "&lt;b&gt;" in page
    assert "Informational autostart entries (1)" in page
    assert "dpkg: 10 files of 3 packages verified" in page
    csv_text = reports.to_csv(report)
    assert "/etc/crontab:4" in csv_text and "downloads and runs a script" in csv_text
