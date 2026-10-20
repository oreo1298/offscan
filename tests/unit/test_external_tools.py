"""Optional external checkers: output parsing, and a real chkrootkit run when it is installed."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from offscan.persistence import external
from support.linuxroot import build_linux_root

CHKROOTKIT_OUTPUT = """/usr/bin/find: '/mnt/t/bin': No such file or directory
WARNING: Possible Linux.Xor.DDoS installed:
/mnt/t/tmp/payload
/mnt/t/tmp/other

RTNETLINK answers: Invalid argument
Checking `ls'... INFECTED
"""


def test_parse_chkrootkit() -> None:
    findings = external.parse_chkrootkit(CHKROOTKIT_OUTPUT, "/mnt/t/")
    assert [f.severity for f in findings] == ["medium", "high"]
    assert findings[0].title == "chkrootkit: Possible Linux.Xor.DDoS installed"
    assert findings[0].file == "/tmp/payload" and findings[0].extra["files"] == ["/tmp/payload", "/tmp/other"]
    assert "INFECTED" in findings[1].value


def test_parse_hayabusa() -> None:
    lines = [
        {"Timestamp": "2026-01-02 03:04:05.000 +00:00", "RuleTitle": "Defender Disabled", "Level": "high",
         "Computer": "PC1", "Channel": "Sec", "EventID": 5001, "RecordID": 9, "Details": {"Cmd": "x"},
         "RuleID": "abc"},
        {"RuleTitle": "Logon", "Level": "info", "Channel": "Sec", "EventID": 4624},
        {"RuleTitle": "Crit", "Level": "crit"},
    ]
    text = "\n".join(json.dumps(x) for x in lines) + "\nnot json\n"
    findings = external.parse_hayabusa(text)
    assert [f.severity for f in findings] == ["high", "info", "high"]
    assert findings[0].title == "Event log: Defender Disabled"
    assert findings[0].location == "Sec event 5001 record 9"
    assert findings[0].extra["computer"] == "PC1"


def test_parse_chainsaw() -> None:
    data = [{"name": "Suspicious Service", "level": "critical", "timestamp": "2026-01-01T00:00:00Z",
             "document": {"data": {"Event": {"System": {"Channel": "System", "EventID": 7045,
                                                         "Computer": "PC1"}}}}},
            "garbage", {"title": "Other", "level": "low"}]
    findings = external.parse_chainsaw(data)
    assert [(f.title, f.severity) for f in findings] == [("Event log: Suspicious Service", "high"),
                                                         ("Event log: Other", "low")]
    assert findings[0].location == "System event 7045"
    assert external.parse_chainsaw({"not": "a list"}) == []


def test_missing_tools_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(external, "find_tool", lambda name, configured=None: None)
    assert external.run_hayabusa("/x", None)[1]["error"] == "Hayabusa is not installed"
    assert external.run_chainsaw("/x", None)[1]["error"] == "Chainsaw is not installed"
    assert external.run_chkrootkit("/x", None)[1]["error"] == "chkrootkit is not installed"


def test_restricted_command_shape() -> None:
    if shutil.which("setpriv") is None:
        pytest.skip("setpriv missing")
    if shutil.which("prlimit") is None:
        pytest.skip("prlimit missing")
    argv = external.restricted(["/bin/true"], None)
    assert "--no-new-privs" in argv and "--bounding-set=-all" in argv and "--inh-caps=-all" in argv
    assert not any("dac_read_search" in a or "ambient" in a for a in argv)      # no capability at all
    assert argv[-1] == "/bin/true" and "--reuid=65534" in argv
    assert any(a.startswith("--fsize=") for a in argv)


def test_only_root_owned_tools_are_used(tmp_path: Path) -> None:
    tool = tmp_path / "chkrootkit"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    # /tmp (above tmp_path) is writable by everyone, so nothing below it is trusted
    assert external.find_tool("chkrootkit", str(tool)) is None
    assert external.trusted_binary("/bin/sh") or not Path("/bin/sh").exists()
    assert not external.trusted_binary("/nonexistent/tool")


def injection_names(canary: Path) -> list[str]:
    """File names that create ``canary`` if a shell ever evaluates them (no '/' allowed in names)."""
    octal = str(canary).replace("/", "\\057")
    make = f"touch \"$(printf '{octal}')\""
    return [f"x$({make})", f"y`{make}`", f"z;{make};"]


@pytest.mark.integration
@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("chkrootkit", path="/usr/sbin:/usr/bin")
                    or not shutil.which("setpriv"), reason="needs root, setpriv and chkrootkit")
def test_chkrootkit_runs_read_only() -> None:
    import tempfile
    base = Path(tempfile.mkdtemp(dir="/var/tmp"))        # the checker has no capability: it must
    base.chmod(0o777)                                    # walk to the target itself (and could
                                                         # create the canary if injected)
    try:
        root = build_linux_root(base / "t")
        secret = root / "root/.secret"
        secret.write_text("x")
        secret.chmod(0o600)
        (root / "tmp/.uua").write_text("")              # chkrootkit's Scalper worm marker
        canary = base / "PWNED"
        for name in injection_names(canary):
            (root / "tmp" / name).write_text("#!/bin/sh\n")
        before = sorted((p, p.stat().st_mtime_ns) for p in root.rglob("*") if not p.is_symlink())
        findings, info = external.run_chkrootkit(str(root), None, timeout=600)
        assert "error" not in info, info
        assert any("Scalper" in f.title for f in findings), [f.title for f in findings]
        assert not canary.exists()                      # file names from the target never run
        after = sorted((p, p.stat().st_mtime_ns) for p in root.rglob("*") if not p.is_symlink())
        assert before == after
    finally:
        shutil.rmtree(base)
