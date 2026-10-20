"""``offscan drives ...``: list, unlock, mount and unmount target volumes."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .. import fmt, names
from ..protocol import RemoteError
from .common import read_secret, start_helper, volume_arg


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("drives", help="list, unlock and mount target drives (read-only)")
    p.add_argument("--sudo", action="store_true", help="use sudo instead of pkexec")
    dsub = p.add_subparsers(dest="drives_command", metavar="ACTION")

    q = dsub.add_parser("list", help="show disks, partitions, detected OS and encryption")
    q.add_argument("--json", action="store_true")
    q.add_argument("--no-probe", action="store_true",
                   help="do not mount volumes briefly to detect the OS")
    q.set_defaults(func=cmd_list)

    q = dsub.add_parser("unlock", help="unlock a LUKS or BitLocker volume (read-only)")
    q.add_argument("volume")
    kind = q.add_mutually_exclusive_group()
    kind.add_argument("--recovery-key", action="store_true",
                      help="the secret is a 48-digit BitLocker recovery key")
    kind.add_argument("--password", action="store_true", help="the secret is a BitLocker password")
    q.add_argument("--secret-file", help="read the passphrase/key from this file")
    q.set_defaults(func=cmd_unlock)

    q = dsub.add_parser("lock", help="close an unlocked volume")
    q.add_argument("volume")
    q.set_defaults(func=cmd_lock)

    q = dsub.add_parser("lvm", help="activate the logical volumes on an LVM physical volume (read-only)")
    q.add_argument("volume")
    q.set_defaults(func=cmd_lvm)

    q = dsub.add_parser("mount", help="mount a volume read-only and keep it mounted")
    q.add_argument("volume")
    q.set_defaults(func=cmd_mount)

    q = dsub.add_parser("unmount", help="unmount a volume mounted by this program")
    q.add_argument("volume", nargs="?")
    q.add_argument("--all", action="store_true", help="unmount and close everything")
    q.set_defaults(func=cmd_unmount)
    p.set_defaults(func=cmd_list, json=False, no_probe=False)


def _print_disks(disks: list[dict[str, Any]]) -> None:
    for disk in disks:
        title = " ".join(x for x in (disk.get("vendor"), disk.get("model")) if x) or disk["device"]
        flags = []
        if disk.get("transport"):
            flags.append(disk["transport"])
        if disk.get("removable"):
            flags.append("removable")
        if disk.get("system"):
            flags.append("RUNNING SYSTEM")
        if disk.get("live_medium"):
            flags.append("live medium")
        print(f"{disk['device']}  {names.display(title)}  {fmt.size(disk['size'])}"
              + (f"  [{', '.join(flags)}]" if flags else ""))
        _print_volumes(disk["volumes"], 1)


def _print_volumes(volumes: list[dict[str, Any]], depth: int) -> None:
    for vol in volumes:
        label = f" \"{names.display(vol['label'])}\"" if vol.get("label") else ""
        summary = fmt.volume_summary(vol)
        print(f"{'  ' * depth}{vol['id']:<10} {vol.get('fstype') or '-':<12} "
              f"{fmt.size(vol['size']):>9}{label}" + (f"  {summary}" if summary else ""))
        for warning in vol.get("warnings", []):
            print(f"{'  ' * depth}  ! {warning['message']}")
        _print_volumes(vol.get("children", []), depth + 1)


def cmd_list(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        result = client.call("drives.list", {"probe": "none" if args.no_probe else "wait"})
    if args.json:
        print(json.dumps(result["disks"], indent=2))
    else:
        _print_disks(result["disks"])
    return 0


def _secret_kind(args: argparse.Namespace) -> str:
    if args.recovery_key:
        return "recovery_key"
    if args.password:
        return "password"
    return "passphrase"


def cmd_unlock(args: argparse.Namespace) -> int:
    kind = _secret_kind(args)
    prompt = {"recovery_key": "BitLocker recovery key: ", "password": "BitLocker password: ",
              "passphrase": "Passphrase: "}[kind]
    secret = read_secret(prompt, args.secret_file)
    with start_helper(args) as client:
        try:
            result = client.call("volume.unlock", {"volume": volume_arg(args.volume),
                                                   "secret": secret, "secret_kind": kind,
                                                   "keep": True})
        except RemoteError as exc:
            print(f"error: {exc.message}")
            return 2
    print(f"unlocked {args.volume} as {result['unlocked']} ({result['device']}), read-only")
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        client.call("volume.lock", {"volume": volume_arg(args.volume)})
    return 0


def cmd_lvm(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        result = client.call("volume.activate_lvm", {"volume": volume_arg(args.volume), "keep": True})
    for lv in result["activated"]:
        print(f"{lv['name']}: {lv['volume']} ({lv['device']}), read-only")
    for lv in result["skipped"]:
        print(f"{lv['name']}: skipped ({lv['reason']})")
    return 0


def cmd_mount(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        try:
            info = client.call("volume.mount", {"volume": volume_arg(args.volume), "keep": True})
        except RemoteError as exc:
            print(f"error: {exc.message}")
            for attempt in (exc.details or {}).get("attempts") or []:
                print(f"  tried {attempt}")
            return 2
    print(f"{info['mountpoint']}  (read-only, driver {info['driver']})")
    return 0


def cmd_unmount(args: argparse.Namespace) -> int:
    with start_helper(args) as client:
        if args.all:
            client.call("session.cleanup", {"include_kept": True})
        elif args.volume:
            client.call("volume.unmount", {"volume": volume_arg(args.volume)})
        else:
            print("error: give a volume or --all")
            return 2
    return 0
