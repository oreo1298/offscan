"""``offscan`` command-line entry point.

Exit codes (see ``offscan --help``):
  0  success, nothing found
  1  scan finished and found detections
  2  error
  3  scan finished incomplete (cancelled, or some files could not be read)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence

from .. import appinfo, log

EXIT_OK = 0
EXIT_DETECTIONS = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3

Handler = Callable[[argparse.Namespace], int]


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"{appinfo.NAME} {appinfo.VERSION}")
    return EXIT_OK


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .. import selftest
    report = selftest.collect()
    if args.engines:
        report["engine_check"] = selftest.engines_check()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(selftest.format_text(report))
        for name, res in report.get("engine_check", {}).items():
            print(f"EICAR via {name:8} {'OK  ' if res['ok'] else 'FAIL'} {res.get('detail', '')}")
    if args.engines and not all(r["ok"] for r in report["engine_check"].values()):
        return EXIT_ERROR
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=appinfo.NAME,
        description=f"{appinfo.DISPLAY_NAME}: {appinfo.SUMMARY}. "
                    "Target drives are always mounted read-only.",
        epilog="exit codes: 0 clean/success, 1 detections found, 2 error, 3 incomplete scan")
    parser.add_argument("--version", action="version", version=f"%(prog)s {appinfo.VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("version", help="print the version")
    p.set_defaults(func=_cmd_version)

    p = sub.add_parser("selftest", help="show available engines, drivers and tools")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--engines", action="store_true",
                   help="also check that every engine detects the EICAR test file")
    p.set_defaults(func=_cmd_selftest)

    for register in _command_modules():
        register(sub)
    return parser


def _command_modules() -> list[Callable[[argparse._SubParsersAction], None]]:
    """Sub-command groups contributed by other modules (added per milestone)."""
    registrars: list[Callable[[argparse._SubParsersAction], None]] = []
    for name in ("drives", "scan", "defs", "history"):
        try:
            module = __import__(f"{__package__}.{name}", fromlist=["register"])
        except ImportError:
            continue
        registrars.append(module.register)
    return registrars


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    log.setup("cli", verbose=args.verbose)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INCOMPLETE
    except Exception as exc:  # last-resort: report, don't dump a traceback
        logger = log.get("cli")
        logger.debug("unhandled error", exc_info=True)
        print(f"error: {log.redact(str(exc))}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
