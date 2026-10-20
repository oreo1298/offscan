"""``offscan defs ...``: definition sources, updates, rollback and offline bundles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import fmt
from ..defs import bundle
from ..defs.updater import UpdateError, Updater
from ..settings import SECRET_KEYS, Settings


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("defs", help="definition sources, updates and offline bundles")
    dsub = p.add_subparsers(dest="defs_command", metavar="ACTION")

    q = dsub.add_parser("status", help="show the active set and every source")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_status)

    q = dsub.add_parser("update", help="download due sources, then build and activate a new set")
    q.add_argument("sources", nargs="*", help="only these sources")
    q.add_argument("--force", action="store_true",
                   help="ignore our own check intervals (server rate limits still apply)")
    q.add_argument("--rebuild", action="store_true", help="rebuild the set even if nothing changed")
    q.set_defaults(func=cmd_update)

    q = dsub.add_parser("sources", help="list all sources with their licences and terms")
    q.set_defaults(func=cmd_sources)

    q = dsub.add_parser("enable", help="enable a source")
    q.add_argument("source")
    q.add_argument("--accept-license", action="store_true",
                   help="accept the source's licence (required for some sources)")
    q.set_defaults(func=cmd_enable)

    q = dsub.add_parser("disable", help="disable a source")
    q.add_argument("source")
    q.set_defaults(func=cmd_disable)

    q = dsub.add_parser("option", help="set a source option (e.g. yara-forge tier extended)")
    q.add_argument("source")
    q.add_argument("key")
    q.add_argument("value")
    q.set_defaults(func=cmd_option)

    q = dsub.add_parser("set-key", help=f"store an API key or ID ({', '.join(SECRET_KEYS)})")
    q.add_argument("name", choices=SECRET_KEYS)
    q.add_argument("value", nargs="?", help="omit to read from stdin; empty string removes it")
    q.set_defaults(func=cmd_set_key)

    q = dsub.add_parser("rollback", help="go back to the previous definition set")
    q.set_defaults(func=cmd_rollback)

    q = dsub.add_parser("export", help="write a signed offline bundle (e.g. to a USB stick)")
    q.add_argument("file", type=Path)
    q.add_argument("--no-restricted", action="store_true",
                   help="leave out sources whose terms restrict redistribution")
    q.set_defaults(func=cmd_export)

    q = dsub.add_parser("import", help="install definitions from a signed offline bundle")
    q.add_argument("file", type=Path)
    q.add_argument("--trust", metavar="FINGERPRINT",
                   help="trust the bundle's signing key (compare with 'defs fingerprint' on the "
                        "exporting machine)")
    q.add_argument("--yes", action="store_true", help="trust an unknown key without asking")
    q.set_defaults(func=cmd_import)

    q = dsub.add_parser("fingerprint", help="show this installation's bundle signing key")
    q.set_defaults(func=cmd_fingerprint)
    p.set_defaults(func=cmd_status, json=False)


def _updater() -> Updater:
    return Updater(settings=Settings())


def cmd_status(args: argparse.Namespace) -> int:
    status = _updater().status()
    if args.json:
        print(json.dumps(status, indent=2))
        return 0
    active = status["active"]
    if active:
        print(f"Active set {active['id']} (built {fmt.age(active['created'])}): "
              f"{active['yara_rules'] or 0} YARA rules ({active['yara_engine'] or 'no engine'}), "
              f"{active['hashes'] or 0} hashes, {active['clamav_files']} ClamAV files"
              f"{', official ClamAV from the system' if active['clamav_official'] == 'system' else ''}")
    else:
        print("No definitions yet: run 'defs update'.")
    if status["previous"]:
        print(f"Previous set {status['previous']} (rollback available)")
    print()
    for s in status["sources"]:
        state = "on " if s["enabled"] else "off"
        line = f"[{state}] {s['id']:<20} {s['version'] or '-':<24} {fmt.age(s['updated']):<14}"
        if s["size"]:
            line += f" {fmt.size(s['size']):>9}"
        print(line)
        if s["enabled"] and not s["configured"]:
            print(f"       ! {s['configure_hint']}")
        if s["error"]:
            print(f"       ! last error: {s['error']}")
        if s["cooldown_until"]:
            print(f"       ! rate limited until {fmt.iso(s['cooldown_until'])}")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    def progress(sid: str, message: str) -> None:
        print(f"{sid + ': ' if sid else ''}{message}", file=sys.stderr)
    try:
        report = _updater().update(args.sources or None, force=args.force, progress=progress,
                                   rebuild=args.rebuild)
    except UpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    failed = 0
    for sid, result in report["sources"].items():
        extra = result.get("version") or result.get("message") or ""
        print(f"{sid:<20} {result['result']:<13} {extra}")
        failed += result["result"] == "failed"
    if report["set"]:
        s = report["set"]
        print(f"activated set {s['id']}: {s['rules']} YARA rules, {s['hashes']} hashes, "
              f"{s['clamav_files']} ClamAV files")
    return 1 if failed else 0


def cmd_sources(args: argparse.Namespace) -> int:
    for s in _updater().status()["sources"]:
        flags = []
        if s["default_enabled"]:
            flags.append("default")
        if s["requires_secret"]:
            flags.append(f"needs {s['requires_secret']}" + (" (optional)" if s["secret_optional"] else ""))
        if s["requires_acceptance"]:
            flags.append("licence must be accepted")
        print(f"{s['id']} – {s['name']} [{', '.join(flags) or 'opt-in'}]")
        print(f"    licence: {s['license']} <{s['license_url']}>")
        print(f"    {s['terms']}")
        print(f"    integrity: {s['integrity']}; size: {s['size_hint']}")
        if s["warning"]:
            print(f"    note: {s['warning']}")
    return 0


def _find(updater: Updater, sid: str):
    for source in updater.sources:
        if source.id == sid:
            return source
    raise SystemExit(f"error: unknown source {sid!r} (see 'defs sources')")


def cmd_enable(args: argparse.Namespace) -> int:
    updater = _updater()
    source = _find(updater, args.source)
    if source.info.requires_acceptance and not args.accept_license:
        print(f"{source.info.name} is licensed under {source.info.license}:\n  {source.info.terms}\n"
              f"  {source.info.license_url}\nRe-run with --accept-license to accept it.")
        return 2
    values = {"enabled": True}
    if args.accept_license:
        values["accepted_license"] = True
    updater.settings.set_source(source.id, **values)
    updater.settings.save()
    if source.info.requires_secret and not updater.settings.secret(source.info.requires_secret) \
            and not source.info.secret_optional:
        print(f"note: also run 'defs set-key {source.info.requires_secret} ...'")
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    updater = _updater()
    source = _find(updater, args.source)
    updater.settings.set_source(source.id, enabled=False)
    updater.settings.save()
    return 0


def cmd_option(args: argparse.Namespace) -> int:
    updater = _updater()
    source = _find(updater, args.source)
    value: object = args.value
    if args.value.isdigit():
        value = int(args.value)
    updater.settings.set_source(source.id, **{args.key: value})
    updater.settings.save()
    return 0


def cmd_set_key(args: argparse.Namespace) -> int:
    settings = Settings()
    value = args.value if args.value is not None else sys.stdin.readline().strip()
    settings.set_secret(args.name, value or None)
    settings.save()
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    path = _updater().rollback()
    print(f"active set is now {path.name}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    result = bundle.export(args.file, _updater(), include_restricted=not args.no_restricted)
    print(f"wrote {result['path']}: {len(result['sources'])} sources, {result['files']} files")
    for notice in result["notices"]:
        print(f"  note: {notice}")
    print(f"signing key fingerprint: {bundle.format_fingerprint(result['fingerprint'])}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    updater = _updater()
    try:
        result = bundle.import_bundle(args.file, updater, trust=args.trust)
    except bundle.UntrustedKey as exc:
        print(f"The bundle is signed by {bundle.format_fingerprint(exc.fingerprint)}.")
        print("Compare this with 'defs fingerprint' on the machine that exported it.")
        if not args.yes:
            if not sys.stdin.isatty():
                print("error: untrusted key (use --trust FINGERPRINT)", file=sys.stderr)
                return 2
            if input("Trust this key? [y/N] ").strip().lower() not in ("y", "yes"):
                return 2
        bundle.trust_key(exc.fingerprint, str(args.file.name))
        result = bundle.import_bundle(args.file, updater)
    except bundle.BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"imported {', '.join(result['sources'])}; activated set {result['set']['id']}")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    print(bundle.format_fingerprint(bundle.own_fingerprint()))
    return 0
