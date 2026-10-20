"""``offscan quarantine|delete|restore|quarantined|purge|changes``.

The only commands that change a target volume.  Each one shows exactly what
will happen and asks for confirmation (type the action's name) unless
``--yes`` is given.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .. import fmt, names, remediation
from ..protocol import RemoteError
from .common import read_secret, start_helper, volume_arg

EXIT_OK, EXIT_ERROR, EXIT_REFUSED = 0, 2, 4


def register(sub: argparse._SubParsersAction) -> None:
    for action, text in (("quarantine", "move a file on a target volume to the quarantine"),
                         ("delete", "delete a file on a target volume permanently")):
        p = sub.add_parser(action, help=text, description=text + ". The volume is mounted read-write "
                           "only for this change; every change is logged.")
        p.add_argument("volume", help="volume, e.g. sdb2")
        p.add_argument("path", help="path inside the volume, e.g. /Users/x/Downloads/bad.exe")
        _common(p)
        p.set_defaults(func=cmd_change, action=action)
    p = sub.add_parser("restore", help="put a quarantined file back")
    p.add_argument("id", help="quarantine id (see 'quarantined')")
    p.add_argument("--volume", help="volume to restore to (default: the original one)")
    p.add_argument("--path", help="restore under another path")
    _common(p)
    p.set_defaults(func=cmd_restore)
    p = sub.add_parser("quarantined", help="list quarantined files")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    p.set_defaults(func=cmd_list)
    p = sub.add_parser("purge", help="delete a quarantined copy for good")
    p.add_argument("id")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    p.set_defaults(func=cmd_purge)
    p = sub.add_parser("changes", help="show the log of changes made to target volumes")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    p.set_defaults(func=cmd_changes)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--secret-file", help="read the passphrase/key of an encrypted volume from this file")
    p.add_argument("--recovery-key", action="store_true", help="the secret is a BitLocker recovery key")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")


def _confirm(word: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("refusing to change a target without confirmation; use --yes", file=sys.stderr)
        return False
    answer = input(f"Type '{word}' to go ahead: ")
    return answer.strip().lower() == word


def _secrets(args: argparse.Namespace, needed: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    out = {}
    kind = "recovery_key" if args.recovery_key else "passphrase"
    for item in needed:
        secret = read_secret(f"Passphrase or key for {item['volume']} ({item['kind']}): ", args.secret_file)
        out[item["volume"]] = {"secret": secret, "kind": kind}
    return out


def cmd_change(args: argparse.Namespace) -> int:
    volume = volume_arg(args.volume)
    with start_helper(args) as client:
        try:
            p = remediation.plan(client, volume, args.path)
        except RemoteError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return EXIT_ERROR
        for line in remediation.explain(p, args.action):
            print(line)
        if not p.get("possible"):
            return EXIT_REFUSED
        if not _confirm(args.action, args.yes):
            print("nothing was changed")
            return EXIT_REFUSED
        secrets = _secrets(args, p.get("needs_secret") or [])
        try:
            record = remediation.apply(client, p, args.action, secrets)
        except RemoteError as exc:
            print(f"error: {exc.message} (nothing was changed unless the change log says so)",
                  file=sys.stderr)
            return EXIT_ERROR
    print(remediation.describe_record(record))
    return EXIT_OK if not record.get("restore_errors") else EXIT_ERROR


def cmd_restore(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        entries = {e["id"]: e for e in client.call("quarantine.list", {}, timeout=120)["entries"]}
        entry = entries.get(args.id)
        if entry is None:
            print(f"error: no quarantine entry {args.id}", file=sys.stderr)
            return EXIT_ERROR
        volume = volume_arg(args.volume) if args.volume else entry["volume"]
        try:
            p = remediation.plan(client, volume, None)
        except RemoteError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return EXIT_ERROR
        if not p.get("possible"):
            print(f"Not possible: {p.get('reason')}", file=sys.stderr)
            return EXIT_REFUSED
        path = args.path or entry["path"]
        print(f"Restore {names.display(path)} ({fmt.size(entry['size'])}, SHA-256 {entry['sha256']}) "
              f"to volume {volume}. The volume is mounted read-write just for this change.")
        for note in p.get("notes", []):
            print(note)
        if not _confirm("restore", args.yes):
            print("nothing was changed")
            return EXIT_REFUSED
        secrets = _secrets(args, p.get("needs_secret") or [])
        try:
            record = remediation.restore(client, args.id, volume, args.path, secrets)
        except RemoteError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return EXIT_ERROR
    print(remediation.describe_record(record))
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        entries = client.call("quarantine.list", {}, timeout=120)["entries"]
    if args.json:
        print(json.dumps(entries, indent=2))
        return EXIT_OK
    if not entries:
        print("the quarantine is empty")
    for e in entries:
        print(f"{e['id']}  {fmt.iso(e['time'])}  {e.get('volume', '?')}:{names.display(e['path'], 200)}  "
              f"{fmt.size(e['size'])}  {e['sha256'][:16]}…")
    return EXIT_OK


def cmd_purge(args: argparse.Namespace) -> int:
    if not _confirm("purge", args.yes):
        print("nothing was changed")
        return EXIT_REFUSED
    with start_helper(args) as client:
        try:
            client.call("quarantine.purge", {"id": args.id, "confirm": True}, timeout=120)
        except RemoteError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return EXIT_ERROR
    print("removed from the quarantine")
    return EXIT_OK


def cmd_changes(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        reply = client.call("changes.list", {"limit": args.limit}, timeout=120)
    changes: list[dict[str, Any]] = reply["changes"]
    if args.json:
        print(json.dumps(changes, indent=2))
        return EXIT_OK
    for c in changes:
        status = "ok" if c.get("result") == "ok" else f"FAILED: {c.get('error', '?')}"
        print(f"{fmt.iso(c.get('time', 0))}  {c.get('action', '?'):10} {c.get('volume', '?')}:"
              f"{names.display(c.get('path', '?'), 200)}  {status}")
    return EXIT_OK
