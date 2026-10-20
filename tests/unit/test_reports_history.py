import csv
import io
import json
import time
from pathlib import Path

from offscan import reports
from offscan.history import History
from offscan.scan.results import Detection

EVIL_PATH = "/Users/a/<script>alert(1)</script>\n=cmd|' /C calc'!A0.exe"


def _summary() -> dict:
    now = time.time()
    return {"job": 1, "state": "finished", "started": now - 5, "finished": now, "files_scanned": 3,
            "bytes_scanned": 100, "files_skipped": 1, "errors": 1, "detections": 1,
            "error_samples": [{"path": "/x\n<b>", "message": "read error"}], "engines": {}}


def _det(**kw) -> Detection:
    base = dict(volume="sdb2", path=EVIL_PATH, engine="yara", signature="=HYPERLINK(\"x\")",
                severity="high", sha256="ab" * 32, size=10, source="yara-forge",
                details={"author": "<img src=x onerror=alert(1)>"})
    base.update(kw)
    return Detection(**base)


def test_html_report_escapes_everything() -> None:
    rep = reports.build(_summary(), {"mode": "full"}, [{"volume": "sdb2", "label": "<i>"}],
                        [_det().to_dict()])
    text = reports.to_html(rep)
    assert "<script>" not in text and "<img" not in text and "<i>" not in text
    assert "&lt;script&gt;" in text
    assert "\\n" in text                  # newline in a path is shown escaped, never raw
    assert "Content-Security-Policy" in text


def test_csv_neutralises_formulas() -> None:
    rep = reports.build(_summary(), {"mode": "full"}, [], [_det().to_dict()])
    rows = list(csv.reader(io.StringIO(reports.to_csv(rep))))
    header, row = rows[0], rows[1]
    sig = row[header.index("signature")]
    assert sig.startswith("'=")
    assert "\n" not in row[header.index("path")]


def test_json_report_roundtrip() -> None:
    rep = reports.build(_summary(), {"mode": "full"}, [], [_det().to_dict(), _det(severity="low").to_dict()])
    data = json.loads(reports.to_json(rep))
    assert [d["severity"] for d in data["detections"]] == ["high", "low"]


def test_history_and_false_positives(tmp_path: Path) -> None:
    hist = History(tmp_path / "h.sqlite3")
    det = _det(engine="clamav", signature="Win.Test")
    scan_id = hist.add_scan(_summary(), {"mode": "quick"}, [{"volume": "sdb2"}], [det])
    assert hist.scans()[0]["id"] == scan_id
    (row,) = hist.detections(scan_id)
    assert row["status"] == "open" and row["details"]["author"].startswith("<img")
    hist.mark_false_positive("clamav", "Win.Test", det.sha256)
    assert hist.detections(scan_id)[0]["status"] == "false_positive"
    assert hist.is_false_positive(det)
    second = hist.add_scan(_summary(), {"mode": "quick"}, [], [det])
    assert hist.detections(second)[0]["status"] == "false_positive"
    hist.unmark_false_positive("clamav", "Win.Test", det.sha256)
    assert not hist.is_false_positive(det)
    hist.delete_scan(scan_id)
    assert len(hist.scans()) == 1
