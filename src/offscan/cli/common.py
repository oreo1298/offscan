"""Helpers shared by CLI sub-commands."""

from __future__ import annotations

import getpass
import os
import sys
from typing import Any

from .. import names
from ..client import HelperClient, HelperStartError


def volume_arg(value: str) -> str:
    """Accept ``sdb2``, ``/dev/sdb2`` or ``/dev/mapper/name``; return the kernel name."""
    if value.startswith("/dev/"):
        real = os.path.realpath(value)
        return os.path.basename(real)
    return value


def start_helper(args: Any) -> HelperClient:
    def on_event(event: str, data: Any, job: int | None) -> None:
        if getattr(args, "verbose", False):
            print(f"[{event}] {names.display(str(data), 200)}", file=sys.stderr)

    client = HelperClient(on_event=on_event)
    try:
        client.start(prefer_sudo=getattr(args, "sudo", False))
    except HelperStartError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return client


def read_secret(prompt: str, path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().rstrip("\n")
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass(prompt)
