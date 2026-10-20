"""The per-user definitions store: built sets and the active pointer.

::

    <definitions>/sets/<set-id>/      immutable definition sets
    <definitions>/active  -> sets/<set-id>     (symlink, swapped atomically)
    <definitions>/previous -> sets/<set-id>    (rollback target)
    <definitions>/sources/<source-id>/         downloaded material + state (M3)

Root without a user (``sudo -i``, live session as root) uses the system
store under /var/lib so unprivileged scan processes can read it.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import paths
from . import layout


def store_dir() -> Path:
    if os.geteuid() == 0 and not os.environ.get("SUDO_UID") and not os.environ.get("PKEXEC_UID"):
        return paths.system_state_dir() / "definitions"
    return paths.definitions_dir()


def sets_dir(base: Path | None = None) -> Path:
    return (base or store_dir()) / "sets"


def active_set(base: Path | None = None) -> Path | None:
    link = (base or store_dir()) / "active"
    try:
        target = link.resolve(strict=True)
    except OSError:
        return None
    if not (target / layout.MANIFEST).exists():
        return None
    return target


def _swap_link(link: Path, target: Path) -> None:
    tmp = link.with_name(link.name + ".new")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    os.symlink(os.path.relpath(target, link.parent), tmp)
    os.replace(tmp, link)


def activate(set_path: Path, base: Path | None = None) -> None:
    """Atomically make ``set_path`` active; the old active set becomes 'previous'."""
    base = base or store_dir()
    layout.load_manifest(set_path)                 # refuse broken sets
    current = active_set(base)
    if current is not None and current != set_path.resolve():
        _swap_link(base / "previous", current)
    _swap_link(base / "active", set_path)


def rollback(base: Path | None = None) -> Path:
    base = base or store_dir()
    try:
        previous = (base / "previous").resolve(strict=True)
    except OSError as exc:
        raise layout.LayoutError("there is no previous definition set to roll back to") from exc
    current = active_set(base)
    _swap_link(base / "active", previous)
    if current is not None:
        _swap_link(base / "previous", current)
    return previous
