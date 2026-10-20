"""``offscan scan``: scan target volumes and write a report."""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Any

from .. import fmt, names, reports
from ..history import History
from ..protocol import RemoteError
from ..scan.options import ENGINES, Limits, ScanOptions, parse_size
from ..scanning import ScanSession
from .common import start_helper, volume_arg

EXIT_OK, EXIT_DETECTIONS, EXIT_ERROR, EXIT_INCOMPLETE = 0, 1, 2, 3


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("scan", help="scan volumes for malware (read-only)",
                       description="Mounts the given volumes read-only (if not already) and scans them.")
    p.add_argument("volumes", nargs="+", help="volumes to scan, e.g. sdb2 or /dev/sdb2")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", dest="mode", action="store_const", const="quick",
                      help="executables, scripts and high-risk folders (default)")
    mode.add_argument("--full", dest="mode", action="store_const", const="full", help="every file")
    mode.add_argument("--path", dest="paths", action="append", metavar="PATH",
                      help="scan only this path inside the volume (repeatable)")
    p.add_argument("--engines", default=",".join(ENGINES),
                   help=f"comma-separated engines to use (default: {','.join(ENGINES)})")
    p.add_argument("--max-file-size", default="100M", help="largest file to scan fully (default 100M)")
    p.add_argument("--max-scan-size", default="400M", help="ClamAV: data scanned per file incl. archives")
    p.add_argument("--archive-depth", type=int, default=17, help="maximum archive nesting (default 17)")
    p.add_argument("--workers", type=int, default=0, help="parallel scan processes (default: auto)")
    p.add_argument("--pua", action="store_true", help="also report potentially unwanted applications")
    p.add_argument("--definitions", type=Path, help="use this definition set instead of the active one")
    p.add_argument("--report", action="append", default=[], metavar="FILE",
                   help="write a report (.html, .json or .csv; repeatable)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--no-history", action="store_true", help="do not record this scan in the history")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    p.set_defaults(func=cmd_scan, mode=None)


def _options(args: argparse.Namespace) -> ScanOptions:
    mode = "custom" if args.paths else (args.mode or "quick")
    limits = Limits(max_file_size=parse_size(args.max_file_size),
                    max_scan_size=parse_size(args.max_scan_size), archive_depth=args.archive_depth)
    limits.max_hash_size = max(limits.max_hash_size, limits.max_file_size)
    opts = ScanOptions(volumes=[volume_arg(v) for v in args.volumes], mode=mode,
                       paths=args.paths or [], engines=[e for e in args.engines.split(",") if e],
                       limits=limits, workers=args.workers, detect_pua=args.pua)
    opts.validate()
    return opts


class Printer:
    def __init__(self, quiet: bool):
        self.quiet = quiet
        self.tty = sys.stderr.isatty()
        self.last_len = 0

    def __call__(self, event: str, data: Any) -> None:
        if self.quiet:
            return
        if event == "scan.detection":
            self._clear()
            print(f"[{data['severity'].upper():6}] {data['volume']}:{names.display(data['path'])}  "
                  f"{data['engine']}: {data['signature']}", flush=True)
        elif event == "scan.status":
            self._line(data.get("message", ""))
        elif event == "scan.progress" and self.tty:
            total = data.get("files_total")
            done = data.get("files_done", 0)
            share = f"{done}/{total}" if total else f"{done}"
            eta = f" ETA {fmt.duration(data['eta'])}" if data.get("eta") is not None else ""
            cur = names.display(data.get("current", ""), 60)
            self._line(f"{share} files, {data.get('rate_files', 0):.0f}/s, "
                       f"{data.get('detections', 0)} found{eta}  {cur}")

    def _line(self, text: str) -> None:
        if not self.tty:
            print(text, file=sys.stderr)
            return
        text = text[:150]
        sys.stderr.write("\r" + text + " " * max(0, self.last_len - len(text)))
        sys.stderr.flush()
        self.last_len = len(text)

    def _clear(self) -> None:
        if self.tty and self.last_len:
            sys.stderr.write("\r" + " " * self.last_len + "\r")
            self.last_len = 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        options = _options(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    printer = Printer(quiet=args.json)
    history = None if args.no_history else History()
    with start_helper(args) as client:
        session = ScanSession(client, options, args.definitions, printer, history)
        previous = signal.getsignal(signal.SIGINT)

        def interrupt(signum: int, frame: object) -> None:
            print("\ncancelling…", file=sys.stderr)
            session.cancel()
        signal.signal(signal.SIGINT, interrupt)
        try:
            summary = session.run()
        except RemoteError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return EXIT_ERROR
        finally:
            signal.signal(signal.SIGINT, previous)
    printer._clear()
    dets = [d.to_dict() for d in session.detections]
    report = reports.build(summary, options.to_dict(), session.targets, dets, session.definitions)
    for path in args.report:
        kind = reports.write(report, path)
        print(f"wrote {kind} report to {path}", file=sys.stderr)
    if args.json:
        print(reports.to_json(report))
    else:
        print(f"{summary['state']}: {summary['files_scanned']} files scanned "
              f"({fmt.size(summary['bytes_scanned'])}), {summary['files_skipped']} skipped, "
              f"{len(dets)} detections, {summary['errors']} errors, "
              f"{fmt.duration(summary['finished'] - summary['started'])}")
        for name, info in summary.get("engines", {}).items():
            if isinstance(info, dict) and info.get("error"):
                print(f"warning: {name}: {info['error']}", file=sys.stderr)
        if summary.get("message"):
            print(summary["message"], file=sys.stderr)
    if summary["state"] == "failed":
        return EXIT_ERROR
    real = [d for d in dets if not d.get("details", {}).get("false_positive")]
    if real:
        return EXIT_DETECTIONS
    return EXIT_INCOMPLETE if summary["state"] != "finished" or summary["errors"] else EXIT_OK


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=2)
