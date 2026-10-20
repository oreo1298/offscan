"""The one exception to read-only: a short writable session for a confirmed change.

Quarantine, delete and restore need to change one file on a target volume.
For that, and only while the change is made, the volume is mounted
read-write:

1. Every check that can refuse is done first: the running system, volumes
   the host has mounted or stacked, write-protected devices, hibernated
   Windows, dislocker-opened BitLocker, and unsupported filesystems all
   refuse.
2. The read-only stack of the volume (and everything else stacked on the
   same device) is torn down; two mounts of one filesystem must never
   coexist.
3. A writable chain is built: the raw device, writable crypt/LVM mappings
   (re-unlocked with the passphrase the user just gave) and a
   ``rw,nosuid,nodev,noexec`` mount.  Its layers are recorded in the state
   file under the owner ``rw:<root>``, so a crash leaves nothing behind.
4. After the change: sync, unmount, close the mappings, then rebuild the
   read-only stack and mounts that existed before.  Device names of mappings
   can change, so the new names are returned.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .. import log, paths
from ..drives import superblock, system
from . import blockdev, crypt, lvm, mounting
from .state import Layer

if TYPE_CHECKING:
    from .volumes import VolumeManager

logger = log.get("helper.writable")


class WritableError(Exception):
    def __init__(self, message: str, code: str = "not_permitted", details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details


@dataclass
class Step:
    kind: str                       # unlock | lvm | mount
    kname: str                      # volume the step is applied to
    stable: str                     # name that survives re-creation (raw kname, crypt:<root>, lv:<vg>/<lv>)
    role: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plan:
    volume: str
    root: str
    fstype: str
    chain: list[Step]                       # from the raw device down to the filesystem
    needs_secret: list[dict[str, str]]      # [{volume, kind}] that must be unlocked again
    replay_journal: bool
    notes: list[str]
    restore: dict[str, Any]                 # what to rebuild afterwards


@dataclass
class Session:
    mountpoint: str
    plan: Plan
    driver: str
    options: list[str]
    renamed: dict[str, str] = field(default_factory=dict)
    restore_errors: list[str] = field(default_factory=list)


def _stable(mgr: VolumeManager, kname: str) -> str:
    for layer in mgr.state.layers:
        if layer.kind == "crypt" and system.kname_for_path(f"/dev/mapper/{layer.target}") == kname:
            return f"crypt:{layer.owner}"
        if layer.kind == "lvm" and system.kname_for_path(f"/dev/mapper/{layer.target}") == kname:
            return f"lv:{layer.extra.get('vg')}/{layer.extra.get('lv')}"
    return kname


def plan(mgr: VolumeManager, kname: str) -> Plan:
    """Work out (without changing anything) how ``kname`` would be made writable."""
    dev, snap = mgr.resolve(kname)
    if mgr.role(dev) != "filesystem":
        raise WritableError("only files on a filesystem volume can be changed")
    if dev.fstype not in mounting.WRITABLE_FSTYPES:
        raise WritableError(f"changing files on {dev.fstype or 'this'} filesystem is not supported")
    lineage = [kname]
    while lineage[-1] in mgr.state.parents:
        lineage.append(mgr.state.parents[lineage[-1]])
    root = lineage[-1]
    for node in lineage:
        if snap.system.is_system(node):
            raise WritableError("this volume belongs to the running system; change it from the system itself")
        if [m for m in snap.host_mounts.get(node, []) if not paths.is_our_mount(m)]:
            raise WritableError("this volume is mounted by the computer itself; unmount it there first")
    ours = mgr.our_devices()
    if mgr._host_holders(root, ours):
        raise WritableError("the computer is using this device (LVM, RAID or encryption); "
                            "deactivate it first")
    if any(layer.kind == "dislocker" and layer.owner in lineage for layer in mgr.state.layers):
        raise WritableError("BitLocker volumes opened through dislocker can only be read")
    root_dev = snap.devices[root]
    if _write_protected(mgr, root_dev.path, _disk_path(root_dev, snap)):
        raise WritableError("the device is write-protected (its read-only switch or flag is set)")
    cached = mgr.probe_cache.get(mgr._cache_key(dev))
    if cached is None and dev.fstype in mounting.NTFS_TYPES:
        cached = mgr.probe(kname)            # hibernation must be known before writing to NTFS
    cached = cached or {}
    if (cached.get("hibernation") or {}).get("hibernated"):
        raise WritableError("Windows on this volume is hibernated or uses Fast Startup; writing now would "
                            "lose data when it resumes. Start Windows and shut it down fully first.")
    chain: list[Step] = []
    needs: list[dict[str, str]] = []
    for node in reversed(lineage[1:]):                 # devices that were opened, root first
        node_dev = snap.devices[node]
        role = mgr.role(node_dev)
        if role in ("luks", "bitlocker"):
            chain.append(Step("unlock", node, _stable(mgr, node), role))
            needs.append({"volume": node, "kind": role})
        elif role == "lvm_pv":
            child = lineage[lineage.index(node) - 1]
            lv_layer = next((layer for layer in mgr.state.layers if layer.kind == "lvm"
                             and system.kname_for_path(f"/dev/mapper/{layer.target}") == child), None)
            if lv_layer is None:
                raise WritableError("cannot tell which logical volume this is")
            chain.append(Step("lvm", node, _stable(mgr, node), role,
                              {"vg": lv_layer.extra.get("vg"), "lv": lv_layer.extra.get("lv")}))
        else:
            raise WritableError(f"cannot make a {role} volume writable")
    chain.append(Step("mount", kname, _stable(mgr, kname), "filesystem", {"fstype": dev.fstype}))
    replay = False
    notes: list[str] = []
    if not lineage[1:]:
        state = superblock.probe(dev.path, dev.fstype)
        if state is not None and (state.needs_recovery or state.orphans):
            replay = True
    elif cached.get("fs_state") and not cached["fs_state"].get("clean", True):
        replay = True
    if replay:
        notes.append("The filesystem was not shut down cleanly: mounting it writable replays its journal, "
                     "as a normal start of that system would.")
    if dev.fstype in mounting.NTFS_TYPES:
        notes.append("NTFS: Windows may run a disk check at its next start.")
    return Plan(kname, root, dev.fstype or "", chain, needs, replay, notes, _restore_state(mgr, root))


def _write_protected(mgr: VolumeManager, part: str, disk: str) -> bool:
    """Was the device read-only before we touched it?

    Our own flags say nothing, and while the disk-wide flag is set (by us) the
    partition always reports read-only, so recorded original states win.
    """
    def recorded(path: str) -> list[Layer]:
        return [layer for layer in mgr.state.layers if layer.kind == "setro" and layer.target == path]

    disk_layers = recorded(disk) if disk else []
    if disk_layers:
        if disk_layers[0].extra.get("was_ro", True):
            return True
    elif disk and blockdev.get_ro(disk):
        return True
    part_layers = recorded(part) if part != disk else []
    if part_layers:
        return bool(part_layers[0].extra.get("was_ro", True))
    if part != disk and not disk_layers:
        return blockdev.get_ro(part)
    return False


def _lift_disk_protection(mgr: VolumeManager, root: str, owner: str) -> None:
    """Other volumes of ours on the same disk may rely on the disk-wide read-only flag.

    Protect each of them at partition level instead, then lift the disk flag for
    the session; both are recorded as layers of ``owner`` and undone at its end.
    """
    dev, snap = mgr.resolve(root)
    disk = snap.devices.get(dev.pkname) if dev.type == "part" and dev.pkname else None
    if disk is None:
        return
    held = [layer for layer in mgr.state.layers if layer.kind == "setro" and layer.target == disk.path]
    if not held:
        return
    owners = {mgr._root_owner(layer.owner) for layer in held}
    for part in disk.children:
        if part.kname != root and part.kname in owners:
            # The partition's own flag cannot be read while the disk flag is set; we never set it.
            mgr._add(Layer("setro", part.path, owner, {"was_ro": False}))
            blockdev.set_ro(part.path, True)
    mgr._add(Layer("unsetro", disk.path, owner, {}))
    blockdev.set_ro(disk.path, False)


def _disk_path(dev: Any, snap: Any) -> str:
    if dev.type == "part" and dev.pkname and dev.pkname in snap.devices:
        return snap.devices[dev.pkname].path
    return ""


def _restore_state(mgr: VolumeManager, root: str) -> dict[str, Any]:
    """What exists now below ``root``: unlocked/activated volumes and mounts (by stable name)."""
    subtree = {root} | mgr._descendants(root)
    opened: list[dict[str, Any]] = []
    for node in sorted(subtree, key=lambda n: _depth(mgr, n)):
        if node == root or node not in mgr.state.parents:
            continue
        parent = mgr.state.parents[node]
        stable = _stable(mgr, node)
        if stable.startswith("crypt:"):
            opened.append({"kind": "unlock", "parent": _stable(mgr, parent), "stable": stable})
        elif stable.startswith("lv:"):
            if not any(o["kind"] == "lvm" and o["parent"] == _stable(mgr, parent) for o in opened):
                opened.append({"kind": "lvm", "parent": _stable(mgr, parent), "stable": stable})
    mounts = [{"stable": _stable(mgr, layer.owner), "keep": mgr._root_owner(layer.owner) in mgr.state.keep}
              for layer in mgr.state.layers if layer.kind == "mount" and layer.owner in subtree]
    return {"opened": opened, "mounts": mounts}


def _depth(mgr: VolumeManager, node: str) -> int:
    depth = 0
    while node in mgr.state.parents and depth < 16:
        node = mgr.state.parents[node]
        depth += 1
    return depth


@contextlib.contextmanager
def session(mgr: VolumeManager, kname: str,
            secrets: dict[str, tuple[str, str]] | None = None) -> Iterator[Session]:
    """Mount ``kname`` writable for the duration of the ``with`` block (manager lock held)."""
    secrets = secrets or {}
    with mgr._lock:
        p = plan(mgr, kname)
        missing = [n for n in p.needs_secret if n["volume"] not in secrets]
        if missing:
            raise WritableError("the passphrase or recovery key is needed again to open the volume writable",
                                "needs_secret", {"volumes": missing})
        renamed: dict[str, str] = {}
        stable_to_kname: dict[str, str] = {p.root: p.root}
        mgr.teardown(p.root)
        owner = f"rw:{p.root}"
        session_obj: Session | None = None
        try:
            _lift_disk_protection(mgr, p.root, owner)
            source = mgr.resolve(p.root)[0].path
            if blockdev.get_ro(source):
                raise WritableError("the device stayed read-only; it may be write-protected")
            for step in p.chain:
                if step.kind == "unlock":
                    secret, secret_kind = secrets[step.kname]
                    if step.role == "bitlocker" and secret_kind == "recovery_key":
                        secret = crypt.normalize_recovery_key(secret)
                    name = crypt.mapper_name(p.root) + "-rw"
                    mgr._add(Layer("crypt", name, owner, {"source": source, "kind": step.role,
                                                          "writable": True}))
                    try:
                        source = crypt.cryptsetup_open(source, name, step.role, secret.encode("utf-8"),
                                                       readonly=False)
                    except crypt.UnlockError as exc:
                        code = "not_permitted" if "wrong" in str(exc) else "failed"
                        raise WritableError(str(exc), code) from exc
                elif step.kind == "lvm":
                    volumes = {(lv.vg, lv.name): lv for lv in lvm.logical_volumes([source])}
                    lv = volumes.get((step.extra["vg"], step.extra["lv"]))
                    if lv is None:
                        raise WritableError("the logical volume was not found again")
                    mgr._add(Layer("lvm", lv.dm_name + "-rw", owner, {"vg": lv.vg, "lv": lv.name,
                                                                     "writable": True}))
                    source = lvm.activate(lv, readonly=False, suffix="-rw")
                else:
                    target = str(paths.private_root() / f"rw-{kname}")
                    mgr._add(Layer("mount", target, owner, {"fstype": p.fstype, "writable": True}))
                    result = mounting.mount_writable(source, target, p.fstype)
                    session_obj = Session(target, p, result.driver, result.options)
            assert session_obj is not None
            yield session_obj
        except mounting.MountError as exc:
            raise WritableError(f"could not mount the volume writable: {exc}", "failed",
                                {"attempts": exc.attempts}) from exc
        finally:
            os.sync()
            closed = True
            try:
                mgr.teardown(owner)
            except Exception as exc:
                closed = False
                logger.error("could not close the writable session: %s", exc)
                if session_obj is not None:
                    mounting.detach(session_obj.mountpoint)
            if closed:
                errors = _rebuild(mgr, p, secrets, stable_to_kname)
            else:
                # Never put a read-only view next to a writable mount that is still there.
                errors = ["the writable mount could not be closed normally; it was detached and the "
                          "read-only view was not rebuilt. Unplug the drive or restart before using it."]
            renamed.update({old: new for old, new in _renames(p, stable_to_kname).items() if old != new})
            if session_obj is not None:
                session_obj.renamed = renamed
                session_obj.restore_errors = errors


def _renames(p: Plan, stable_to_kname: dict[str, str]) -> dict[str, str]:
    out = {}
    for step in p.chain:
        new = stable_to_kname.get(step.stable)
        if new:
            out[step.kname] = new
    return out


def _rebuild(mgr: VolumeManager, p: Plan, secrets: dict[str, tuple[str, str]],
             stable_to_kname: dict[str, str]) -> list[str]:
    """Bring back the read-only stack and mounts that existed before the session."""
    errors: list[str] = []
    for item in p.restore["opened"]:
        parent = stable_to_kname.get(item["parent"])
        if parent is None:
            errors.append(f"could not reopen {item['stable']}: its parent is gone")
            continue
        try:
            if item["kind"] == "unlock":
                secret, kind = secrets.get(parent) or secrets.get(item["parent"]) or ("", "")
                result = mgr.unlock(parent, secret, kind or "passphrase")
                stable_to_kname[item["stable"]] = result["unlocked"]
            else:
                result = mgr.activate_lvm(parent)
                for lv in result.get("activated", []):
                    stable_to_kname[f"lv:{lv['name']}"] = lv["volume"]
        except Exception as exc:
            errors.append(f"could not reopen {item['stable']} read-only: {exc}")
    for item in p.restore["mounts"]:
        kname = stable_to_kname.get(item["stable"])
        if kname is None:
            errors.append(f"could not remount {item['stable']}: the volume is gone")
            continue
        try:
            mgr.mount(kname, keep=item["keep"])
        except Exception as exc:
            errors.append(f"could not remount {kname} read-only: {exc}")
    return errors
