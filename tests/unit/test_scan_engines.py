import hashlib
import json
import os
import shutil
import signal
import stat
import threading
import time
from pathlib import Path

import pytest

from offscan.defs import layout, testset
from offscan.safefs import RootFS
from offscan.scan import clamd, hashdb, runtime, selection, walker, worker, yara_engine
from offscan.scan.options import Limits, ScanOptions, parse_size
from offscan.scan.results import clamav_severity, yara_severity

EICAR = testset.eicar()


def test_hashdb_roundtrip(tmp_path: Path) -> None:
    digests = [hashlib.sha256(str(i).encode()).digest() for i in range(5000)]
    entries = [(d, "a") for d in digests] + [(digests[7], "b"), (digests[7], "a")]
    count = hashdb.build(tmp_path / "x.ofh", entries)
    assert count == 5001
    db = hashdb.HashDB(tmp_path / "x.ofh")
    assert len(db) == 5001
    assert db.lookup(digests[0]) == ["a"]
    assert sorted(db.lookup(digests[7])) == ["a", "b"]
    assert db.lookup(b"\0" * 32) == [] and db.lookup(b"\xff" * 32) == []
    assert digests[4999] in db


def test_hashdb_rejects_corruption(tmp_path: Path) -> None:
    path = tmp_path / "x.ofh"
    hashdb.build(path, [(b"\1" * 32, "s")])
    data = path.read_bytes()
    path.write_bytes(data[:-3])
    with pytest.raises(hashdb.HashDBError):
        hashdb.HashDB(path)
    path.write_bytes(b"NOTAHASH" + data[8:])
    with pytest.raises(hashdb.HashDBError):
        hashdb.HashDB(path)


def test_parse_hex_lines() -> None:
    good = "a" * 64
    lines = ["# comment", "", good, f"{good.upper()}  file.exe", f'"{good}",x']
    assert len(list(hashdb.parse_hex_lines(lines))) == 3
    with pytest.raises(hashdb.HashDBError):
        list(hashdb.parse_hex_lines(["nothex"]))
    assert list(hashdb.parse_hex_lines(["nothex", good], strict=False)) == [bytes.fromhex(good)]


@pytest.mark.parametrize("engine", ["yara-x", "yara"])
def test_yara_compile_skips_broken_and_scans(tmp_path: Path, engine: str) -> None:
    if engine == "yara-x":
        pytest.importorskip("yara_x")
    else:
        pytest.importorskip("yara")
    sources = [
        ("t", "good.yar", testset.yara_rule()),
        ("t", "broken.yar", "rule broken { condition: nonsense( }"),
        ("t", "external.yar", 'rule uses_external { condition: filename == "evil.exe" }'),
    ]
    out = tmp_path / yara_engine.compiled_filename(engine)
    result = yara_engine.compile_sources(sources, out, engine)
    assert result.skipped_files == ["broken.yar"] and result.rules == 2
    scanner = yara_engine.Scanner(out, engine, timeout=10)
    matches = scanner.scan(b"xx" + EICAR + b"yy", "/Users/a/Downloads/evil.exe")
    assert {m.rule for m in matches} == {testset.YARA_RULE, "uses_external"}
    meta = next(m for m in matches if m.rule == testset.YARA_RULE).meta
    assert meta["author"].endswith("self-test")
    assert scanner.scan(b"clean", "/x/clean.txt") == []


def test_severity_mapping() -> None:
    assert clamav_severity("Win.Trojan.Agent-1.UNOFFICIAL") == ("high", "malware")
    assert clamav_severity("PUA.Win.Tool.X")[0] == "low"
    assert clamav_severity("Heuristics.Encrypted.Zip")[0] == "medium"
    assert clamav_severity("Eicar-Test-Signature")[0] == "info"
    assert yara_severity({"score": 85})[0] == "high"
    assert yara_severity({"score": 65})[0] == "medium"
    assert yara_severity({"score": 10})[0] == "low"
    assert yara_severity({"category": "INFO"})[0] == "info"
    assert yara_severity({})[0] == "medium"


def test_clamd_reply_parsing() -> None:
    assert clamd.parse_reply(b"stream: Win.Test.EICAR_HDB-1 FOUND\0").signature == "Win.Test.EICAR_HDB-1"
    assert clamd.parse_reply(b"stream: OK\0").status == "OK"
    reply = clamd.parse_reply(b"INSTREAM size limit exceeded. ERROR\0")
    assert reply.status == "ERROR" and "limit" in reply.message


@pytest.mark.parametrize("path,head,expected", [
    ("/Windows/System32/notepad.exe", b"MZ", True),
    ("/home/u/script", b"#!/bin/sh\n", True),
    ("/usr/bin/ls", b"\x7fELF", True),
    ("/home/u/photo.jpg", b"\xff\xd8\xff", False),
    ("/Users/a/Downloads/photo.jpg", b"\xff\xd8\xff", True),
    ("/home/u/notes.txt", b"hello", False),
    ("/home/u/report.docm", b"PK\x03\x04", True),
])
def test_quick_selection(path: str, head: bytes, expected: bool) -> None:
    assert selection.interesting(path, head) is expected


def test_prune() -> None:
    assert selection.prune("/Windows/WinSxS", "quick")
    assert not selection.prune("/Windows/WinSxS", "full")
    assert selection.prune("/proc", "full")


def test_options_validation() -> None:
    assert parse_size("100M") == 100 * 1024 * 1024 and parse_size("1g") == 1024 ** 3
    ScanOptions(volumes=["sdb1"]).validate()
    for bad in (ScanOptions(volumes=[]), ScanOptions(volumes=["a"], mode="nope"),
                ScanOptions(volumes=["a"], mode="custom"), ScanOptions(volumes=["a"], engines=["x"]),
                ScanOptions(volumes=["a"], limits=Limits(max_file_size=10))):
        with pytest.raises(ValueError):
            bad.validate()
    roundtrip = ScanOptions.from_dict(ScanOptions(volumes=["a"], mode="full").to_dict())
    assert roundtrip.mode == "full"


def _hostile_tree(root: Path) -> None:
    (root / "dir").mkdir()
    (root / "dir" / "eicar.com").write_bytes(EICAR)
    (root / b"weird\nname\xff.exe".decode("utf-8", "surrogateescape")).write_bytes(EICAR)
    os.symlink("/etc/shadow", root / "dir" / "abs-link")
    os.symlink("..", root / "dir" / "loop-link")
    os.mkfifo(root / "dir" / "fifo")
    deep = root
    for i in range(140):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)


def test_walker_is_safe(tmp_path: Path) -> None:
    root = tmp_path / "t"
    root.mkdir()
    _hostile_tree(root)
    stats = walker.WalkStats()
    with RootFS(root) as fs:
        items = list(walker.walk(fs, b"/", "full", threading.Event(), stats))
    try:
        paths = {i.relpath for i in items}
        assert paths == {b"/dir/eicar.com", b"/weird\nname\xff.exe"}
        for item in items:
            assert stat.S_ISREG(os.fstat(item.fd).st_mode)
        assert stats.symlinks == 2 and stats.skipped_special == 1
        assert any(b"too deep" in m.encode() for _, m in stats.errors)
    finally:
        for item in items:
            os.close(item.fd)
    with RootFS(root) as fs:   # custom path pointing at a file
        (one,) = list(walker.walk(fs, b"/dir/eicar.com", "custom", threading.Event()))
        os.close(one.fd)
        assert one.relpath == b"/dir/eicar.com"


def _runtime(tmp_path: Path, **kwargs) -> Path:
    set_dir = tmp_path / "set"
    testset.build_test_set(set_dir, **kwargs)
    return runtime.prepare(set_dir, ScanOptions(volumes=["x"]), os.geteuid(), os.getegid(),
                           base=str(tmp_path))


def test_runtime_prepare_layout(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    assert stat.S_IMODE(rt.stat().st_mode) == 0o700
    manifest = layout.load_manifest(rt)
    assert manifest["yara"]["rules"] == 1
    assert (rt / "clamd.conf").read_text().count("LocalSocket ") == 1
    assert (rt / "hashes" / "malware.ofh").exists()
    runtime.cleanup(rt)
    assert not rt.exists()


def test_worker_process_detects_with_hash_and_yara(tmp_path: Path) -> None:
    pytest.importorskip("yara_x")
    rt = _runtime(tmp_path, with_clamav=False)
    config = {"runtime": str(rt), "engines": ["yara", "hashes"], "mode": "full",
              "limits": vars(Limits()), "clamd": False}
    engines = worker.Engines(rt, config)
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    fd = os.open(sample, os.O_RDONLY)
    try:
        result = worker.process(engines, {"id": 1, "path": "/eicar.com", "mode": "full"}, fd)
    finally:
        os.close(fd)
    got = {(d["engine"], d["signature"]) for d in result["detections"]}
    assert got == {("hash", testset.HASH_SIGNATURE), ("yara", testset.YARA_RULE)}
    assert result["sha256"] == hashlib.sha256(EICAR).hexdigest()
    clean = tmp_path / "clean.txt"
    clean.write_text("hello")
    fd = os.open(clean, os.O_RDONLY)
    try:
        quick = worker.process(engines, {"id": 2, "path": "/clean.txt", "mode": "quick"}, fd)
        full = worker.process(engines, {"id": 3, "path": "/clean.txt", "mode": "full"}, fd)
    finally:
        os.close(fd)
    assert quick["skipped"] and full["detections"] == []


@pytest.mark.clamav
@pytest.mark.skipif(shutil.which("clamd", path="/usr/sbin:/usr/bin") is None, reason="clamd missing")
def test_private_clamd_instream(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, with_yara=False, with_hashes=False)
    proc = clamd.start(rt, None, None)
    try:
        client = clamd.Client(str(rt / clamd.SOCKET_NAME), timeout=30)
        assert client.wait_ready(timeout=120, alive=lambda: proc.poll() is None), \
            (rt / "clamd.log").read_text() if (rt / "clamd.log").exists() else "no log"
        stream = client.open_stream()
        stream.feed(b"padding " + EICAR)
        reply = stream.finish()
        assert reply.status == "FOUND"
        assert reply.signature.removesuffix(".UNOFFICIAL") in testset.CLAMAV_SIGNATURES
        stream = client.open_stream()
        stream.feed(b"nothing to see")
        assert stream.finish().status == "OK"
    finally:
        clamd.stop(proc)


def test_pool_survives_crashing_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that dies mid-file is replaced and the file is reported as an error."""
    from offscan.scan import pool as pool_mod
    rt = _runtime(tmp_path, with_clamav=False)
    config = {"runtime": str(rt), "engines": ["hashes"], "mode": "full",
              "limits": vars(Limits()), "clamd": False}
    p = pool_mod.WorkerPool(1, config, None, hard_timeout=60)
    p.start()
    p.wait_ready(60)
    victim = p.workers[0]
    sample = tmp_path / "f"
    sample.write_bytes(b"data")
    fd = os.open(sample, os.O_RDONLY)
    os.kill(victim.proc.pid, signal.SIGSTOP)        # file is "in flight" when the engine dies
    try:
        p.submit(victim, 1, {"path": "/f", "mode": "full"}, fd, "item")
    finally:
        os.close(fd)
    victim.proc.kill()
    deadline = time.monotonic() + 30
    results = []
    while time.monotonic() < deadline and not results:
        results = p.poll(0.5)
    assert results and results[0]["errors"]
    p.wait_ready(60)
    assert p.workers and p.workers[0] is not victim
    p.shutdown()


def test_manifest_json_is_valid(tmp_path: Path) -> None:
    set_dir = tmp_path / "s"
    manifest = testset.build_test_set(set_dir)
    assert json.loads((set_dir / "manifest.json").read_text())["id"] == manifest["id"] == "selftest"
