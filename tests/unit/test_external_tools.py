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
    argv = external.restricted(["/bin/true"], None)
    assert "--no-new-privs" in argv and "--bounding-set=-all,+dac_read_search" in argv
    assert argv[-1] == "/bin/true" and "--reuid=65534" in argv


@pytest.mark.integration
@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("chkrootkit", path="/usr/sbin:/usr/bin")
                    or not shutil.which("setpriv"), reason="needs root, setpriv and chkrootkit")
def test_chkrootkit_runs_read_only(tmp_path: Path) -> None:
    root = build_linux_root(tmp_path / "t")
    secret = root / "root/.secret"
    secret.write_text("x")
    secret.chmod(0o600)
    tmp_path.chmod(0o700)                     # the checker reads with CAP_DAC_READ_SEARCH only
    before = sorted((p, p.stat().st_mtime_ns) for p in root.rglob("*") if not p.is_symlink())
    findings, info = external.run_chkrootkit(str(root), None, timeout=600)
    assert "error" not in info, info
    assert any(f.file == "/tmp/payload" for f in findings), [f.title for f in findings]
    after = sorted((p, p.stat().st_mtime_ns) for p in root.rglob("*") if not p.is_symlink())
    assert before == after
