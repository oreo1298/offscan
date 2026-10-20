"""Scan reports: JSON, CSV and a self-contained HTML page.

All target-controlled strings (paths, signature names from feeds, rule
metadata) are escaped for the output format; CSV cells that could be read
as formulas by spreadsheet programs are neutralised.
"""

from __future__ import annotations

import csv
import html
import io
import json
import platform
from typing import Any

from . import appinfo, fmt, names
from .scan.results import SEVERITY_RANK

FIELDS = ("severity", "volume", "path", "engine", "signature", "sha256", "size", "source",
          "category", "status", "author")


def build(summary: dict[str, Any], options: dict[str, Any], targets: list[dict[str, Any]],
          detections: list[dict[str, Any]], definitions: dict[str, Any] | None = None) -> dict[str, Any]:
    ordered = sorted(detections, key=lambda d: (SEVERITY_RANK.get(d.get("severity", "high"), 9),
                                                d.get("volume", ""), d.get("path", "")))
    for det in ordered:
        if not det.get("status"):
            fp = (det.get("details") or {}).get("false_positive")
            det["status"] = "false_positive" if fp else "open"
    return {"generator": f"{appinfo.NAME} {appinfo.VERSION}", "host": platform.node(),
            "summary": summary, "options": options, "targets": targets,
            "definitions": definitions or {}, "detections": ordered}


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = names.display(text) if isinstance(value, str) else text
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(FIELDS)
    for det in report["detections"]:
        row = dict(det)
        row["author"] = (det.get("details") or {}).get("author")
        writer.writerow([_csv_cell(row.get(f)) for f in FIELDS])
    return buf.getvalue()


_CSS = """
:root { color-scheme: light dark; --fg: CanvasText; --bg: Canvas; --muted: GrayText; }
body { font-family: system-ui, sans-serif; margin: 2rem; color: var(--fg); background: var(--bg); }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { border-bottom: 1px solid color-mix(in srgb, var(--fg) 20%, transparent);
         padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }
th { position: sticky; top: 0; background: var(--bg); }
code { font-family: ui-monospace, monospace; word-break: break-all; }
.muted { color: var(--muted); }
.sev-high { font-weight: 700; }
dl { display: grid; grid-template-columns: max-content auto; gap: 0.2rem 1rem; }
dt { font-weight: 600; }
"""


def to_html(report: dict[str, Any]) -> str:
    e = html.escape
    s = report["summary"]
    rows = []
    for det in report["detections"]:
        details = det.get("details") or {}
        extra = []
        for key in ("author", "description", "license"):
            if details.get(key):
                extra.append(f"{key}: {e(str(details[key]))}")
        rows.append(
            "<tr>"
            f"<td class='sev-{e(det.get('severity', ''))}'>{e(det.get('severity', ''))}</td>"
            f"<td>{e(det.get('volume', ''))}</td>"
            f"<td><code>{e(names.display(det.get('path', '')))}</code></td>"
            f"<td>{e(det.get('engine', ''))}</td>"
            f"<td>{e(det.get('signature', ''))}<div class='muted'>{'<br>'.join(extra)}</div></td>"
            f"<td><code>{e(det.get('sha256') or '')}</code></td>"
            f"<td>{e(det.get('status', 'open'))}</td>"
            "</tr>")
    targets = "".join(
        f"<li>{e(t.get('volume', ''))} {e(t.get('device', ''))} {e(t.get('label') or '')} "
        f"{e((t.get('os') or {}).get('name', '') if isinstance(t.get('os'), dict) else '')}</li>"
        for t in report["targets"])
    errors = "".join(f"<li><code>{e(names.display(x.get('path', '')))}</code>: {e(x.get('message', ''))}</li>"
                     for x in s.get("error_samples", [])[:100])
    started = fmt.iso(s["started"]) if s.get("started") else "?"
    duration = fmt.duration((s.get("finished") or 0) - (s.get("started") or 0))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{e(appinfo.DISPLAY_NAME)} scan report {e(started)}</title><style>{_CSS}</style></head>
<body>
<h1>{e(appinfo.DISPLAY_NAME)} scan report</h1>
<dl>
<dt>Started</dt><dd>{e(started)} ({e(duration)})</dd>
<dt>Result</dt><dd>{e(s.get('state', '?'))}{(' – ' + e(s['message'])) if s.get('message') else ''}</dd>
<dt>Mode</dt><dd>{e(report['options'].get('mode', '?'))}</dd>
<dt>Files</dt><dd>{s.get('files_scanned', 0)} scanned, {s.get('files_skipped', 0)} skipped,
{e(fmt.size(s.get('bytes_scanned', 0)))}</dd>
<dt>Detections</dt><dd>{len(report['detections'])}</dd>
<dt>Errors</dt><dd>{s.get('errors', 0)}</dd>
<dt>Generator</dt><dd>{e(report['generator'])} on {e(report['host'])}</dd>
</dl>
<h2>Targets</h2><ul>{targets}</ul>
<h2>Detections</h2>
<table><thead><tr><th>Severity</th><th>Volume</th><th>Path</th><th>Engine</th><th>Signature</th>
<th>SHA-256</th><th>Status</th></tr></thead><tbody>
{''.join(rows) or '<tr><td colspan="7">Nothing found.</td></tr>'}
</tbody></table>
{f'<h2>Errors (first 100)</h2><ul>{errors}</ul>' if errors else ''}
</body></html>
"""


WRITERS = {"json": to_json, "csv": to_csv, "html": to_html}


def write(report: dict[str, Any], path: str, kind: str | None = None) -> str:
    kind = kind or path.rsplit(".", 1)[-1].lower()
    if kind not in WRITERS:
        raise ValueError(f"unknown report format {kind!r} (use json, csv or html)")
    text = WRITERS[kind](report)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return kind
