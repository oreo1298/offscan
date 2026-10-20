"""Client side of quarantine/delete/restore, shared by the CLI and the GUI.

The helper does the work; this module turns its plan into the explanation the
user confirms, so both front ends say exactly the same thing.
"""

from __future__ import annotations

from typing import Any

from . import fmt, names
from .client import HelperClient

ACTIONS = {
    "quarantine": "Move to quarantine",
    "delete": "Delete permanently",
    "restore": "Restore from quarantine",
}


def plan(client: HelperClient, volume: str, path: str | None) -> dict[str, Any]:
    """The helper's plan for changing ``path`` (or, with None, for any change on the volume)."""
    params: dict[str, Any] = {"volume": volume}
    if path is not None:
        params["path"] = path
    return client.call("remedy.plan", params, timeout=600)


def explain(p: dict[str, Any], action: str) -> list[str]:
    """What will happen, in the order it happens (shown before the user confirms)."""
    path = names.display(p["path"], 500)
    lines = [f"{ACTIONS.get(action, action)}: {path}",
             f"Volume {p['volume']} ({p.get('fstype') or '?'}), {fmt.size(p.get('size', 0))}, "
             f"SHA-256 {p.get('sha256', '?')}"]
    if not p.get("possible", False):
        lines.append(f"Not possible: {p.get('reason', 'unknown reason')}")
        return lines
    lines.append("The volume is mounted read-write just for this change (still without running "
                 "programs from it), then read-only again.")
    if p.get("needs_secret"):
        vols = ", ".join(n["volume"] for n in p["needs_secret"])
        lines.append(f"The encrypted volume ({vols}) is opened writable with its passphrase or key.")
    if action == "quarantine":
        lines.append("A scrambled copy is kept in the quarantine (root only) so it can be restored.")
    elif action == "delete":
        lines.append("The file is deleted; there is no copy to restore.")
    for note in p.get("notes", []):
        lines.append(note)
    lines.append("Every change is written to the change log.")
    return lines


def apply(client: HelperClient, p: dict[str, Any], action: str,
          secrets: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"volume": p["volume"], "path": p["path"], "expect_sha256": p["sha256"],
                              "action": action, "confirm": True}
    if secrets:
        params["secrets"] = secrets
    return client.call("remedy.apply", params, timeout=1800)


def restore(client: HelperClient, entry_id: str, volume: str, path: str | None = None,
            secrets: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"id": entry_id, "volume": volume, "confirm": True}
    if path:
        params["path"] = path
    if secrets:
        params["secrets"] = secrets
    return client.call("quarantine.restore", params, timeout=1800)


def describe_record(record: dict[str, Any]) -> str:
    what = {"quarantine": "moved to quarantine", "delete": "deleted", "restore": "restored",
            "purge": "removed from quarantine"}.get(record.get("action", ""), record.get("action", ""))
    text = f"{names.display(record.get('path', '?'), 300)} {what}"
    if record.get("quarantine_id") and record.get("action") == "quarantine":
        text += f" (quarantine id {record['quarantine_id']})"
    if record.get("restore_errors"):
        text += "; could not restore the read-only view: " + "; ".join(record["restore_errors"])
    return text
