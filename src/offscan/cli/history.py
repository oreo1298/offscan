"""``offscan history``: past scans, their detections and false-positive marks."""

from __future__ import annotations

import argparse
import json

from .. import fmt, names, reports
from ..history import History


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("history", help="past scans, detections and false-positive marks")
    hsub = p.add_subparsers(dest="history_command", metavar="ACTION")
    q = hsub.add_parser("list", help="list past scans")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_list)
    q = hsub.add_parser("show", help="show the detections of one scan")
    q.add_argument("scan_id", type=int)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_show)
    q = hsub.add_parser("report", help="write a report for a past scan")
    q.add_argument("scan_id", type=int)
    q.add_argument("file", help="output file (.html, .json or .csv)")
    q.set_defaults(func=cmd_report)
    q = hsub.add_parser("delete", help="delete a scan from the history")
    q.add_argument("scan_id", type=int)
    q.set_defaults(func=cmd_delete)
    q = hsub.add_parser("false-positive", help="mark (or unmark) a detection as a false positive")
    q.add_argument("engine")
    q.add_argument("signature")
    q.add_argument("sha256")
    q.add_argument("--remove", action="store_true")
    q.set_defaults(func=cmd_fp)
    p.set_defaults(func=cmd_list, json=False)


def cmd_list(args: argparse.Namespace) -> int:
    scans = History().scans()
    if args.json:
        print(json.dumps(scans, indent=2))
        return 0
    for scan in scans:
        s = scan["summary"]
        targets = ", ".join(t.get("volume", "?") for t in scan["targets"]) or "?"
        print(f"#{scan['id']:<5} {fmt.iso(scan['started'])}  {scan['mode']:<6} {s.get('state', '?'):<9} "
              f"{s.get('detections', 0):>4} found  {targets}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    dets = History().detections(args.scan_id)
    if args.json:
        print(json.dumps(dets, indent=2))
        return 0
    for d in dets:
        print(f"[{d['severity']:6}] {d['status']:<14} {d['volume']}:{names.display(d['path'])}  "
              f"{d['engine']}: {d['signature']}  {d['sha256'] or ''}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    hist = History()
    scan = next((s for s in hist.scans(10000) if s["id"] == args.scan_id), None)
    if scan is None:
        print(f"error: no scan #{args.scan_id}")
        return 2
    rep = reports.build(scan["summary"], scan["options"], scan["targets"],
                        hist.detections(args.scan_id), scan["definitions"])
    reports.write(rep, args.file)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    History().delete_scan(args.scan_id)
    return 0


def cmd_fp(args: argparse.Namespace) -> int:
    hist = History()
    if args.remove:
        hist.unmark_false_positive(args.engine, args.signature, args.sha256)
    else:
        hist.mark_false_positive(args.engine, args.signature, args.sha256)
    return 0
