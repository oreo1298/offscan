"""Volume manager: enumerate, classify, unlock, mount and tear down.

Every operation builds a stack of layers, recorded in :mod:`state` before
use and removed in reverse order on teardown:

    setro(partition) [+ setro(disk) when nothing else on it is in use]
      -> loop (read-only)
        -> crypt / lvm mapping (read-only)        optional
          -> mount (ro,nosuid,nodev,noexec,nosymfollow + no replay)

Volumes that belong to the running system, or that are already mounted by
the host, are never re-mounted: we give a read-only bind view instead and
never touch their block devices' flags.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .. import log, paths, sandbox
from ..drives import hibernation, lsblk, osdetect, superblock, system
from ..drives.lsblk import BlockDevice
from ..safefs import RootFS
from . import blockdev, crypt, lvm, mounting
from .state import Layer, State, StateStore

logger = log.get("helper.volumes")

ROLE_BY_FSTYPE = {
    "crypto_LUKS": "luks",
    "BitLocker": "bitlocker",
    "LVM2_member": "lvm_pv",
    "linux_raid_member": "raid_member",
    "isw_raid_member": "raid_member",
    "ddf_raid_member": "raid_member",
    "swap": "swap",
    "swsuspend": "swap",
    "zfs_member": "unsupported",
    "ceph": "unsupported",
}
FILESYSTEM_TYPES = set(mounting.SUPPORTED_FSTYPES)


class VolumeError(Exception):
    def __init__(self, message: str, code: str = "failed", details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details


@dataclass
class Snapshot:
    devices: dict[str, BlockDevice]
    roots: list[BlockDevice]
    system: system.SystemDevices
    host_mounts: dict[str, list[str]]       # kname -> mount points (host namespace)
    host_rw: set[str]                       # knames with a read-write host mount


class VolumeManager:
    def __init__(self, store: StateStore | None = None):
        self.store = store or StateStore()
        self.state = State()
        self._lock = threading.RLock()
        self.probe_cache: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ state

    def start(self) -> None:
        if not self.store.acquire():
            raise VolumeError("another session of this program is already running", "busy")
        self.state = self.store.load()
        self._drop_vanished_layers()
        stale = [layer.owner for layer in self.state.layers
                 if self._root_owner(layer.owner) not in self.state.keep]
        for owner in dict.fromkeys(reversed(stale)):
            try:
                self.teardown(owner)
            except Exception as exc:
                logger.warning("could not clean up leftover %s: %s", owner, exc)

    def stop(self) -> None:
        """Tear down everything not marked 'keep'."""
        with self._lock:
            owners = [layer.owner for layer in self.state.layers
                      if self._root_owner(layer.owner) not in self.state.keep]
            for owner in dict.fromkeys(reversed(owners)):
                try:
                    self.teardown(owner)
                except Exception as exc:
                    logger.error("teardown of %s failed: %s", owner, exc)
            self.store.release()

    def _save(self) -> None:
        self.store.save(self.state)

    def _add(self, layer: Layer) -> None:
        self.state.layers.append(layer)
        self._save()

    def _root_owner(self, owner: str) -> str:
        owner = owner.removeprefix("probe:")
        seen = set()
        while owner in self.state.parents and owner not in seen:
            seen.add(owner)
            owner = self.state.parents[owner]
        return owner

    def _drop_vanished_layers(self) -> None:
        kept = []
        for layer in self.state.layers:
            if layer.kind == "mount" and not mounting.is_mounted(layer.target):
                continue
            if layer.kind == "loop" and blockdev.loop_backing(layer.target) is None:
                continue
            if layer.kind in ("crypt", "lvm") and not os.path.exists(f"/dev/mapper/{layer.target}"):
                continue
            kept.append(layer)
        self.state.layers = kept
        self._save()

    # -------------------------------------------------------------- discovery

    def snapshot(self) -> Snapshot:
        roots = lsblk.list_devices()
        lsblk.fill_missing_fstypes(roots)
        devices = lsblk.flatten(roots)
        host: dict[str, list[str]] = {}
        host_rw: set[str] = set()
        from ..drives import mountinfo
        ours = str(paths.mount_root())
        for entry in mountinfo.read(1):
            kname = system.kname_for_majmin(entry.majmin)
            if kname is None and entry.source.startswith("/dev/"):
                kname = system.kname_for_path(entry.source)      # FUSE (ntfs-3g) mounts
            if not kname or entry.mountpoint.startswith(ours):
                continue
            host.setdefault(kname, []).append(entry.mountpoint)
            if not entry.readonly:
                host_rw.add(kname)
            dev = devices.get(kname)
            if dev is not None and not dev.fstype and entry.fstype not in ("fuseblk", "fuse"):
                dev.fstype = entry.fstype
        return Snapshot(devices, roots, system.detect(), host, host_rw)

    def our_devices(self) -> dict[str, Layer]:
        """kernel name -> layer for loop/dm devices we created."""
        out: dict[str, Layer] = {}
        for layer in self.state.layers:
            if layer.kind == "loop":
                kname = os.path.basename(layer.target)
            elif layer.kind in ("crypt", "lvm"):
                kname = system.kname_for_path(f"/dev/mapper/{layer.target}") or ""
            else:
                continue
            if kname:
                out[kname] = layer
        return out

    def _mount_layer(self, kname: str) -> Layer | None:
        return next((layer for layer in self.state.layers
                     if layer.kind == "mount" and layer.owner == kname), None)

    def describe(self, snap: Snapshot | None = None) -> list[dict[str, Any]]:
        snap = snap or self.snapshot()
        ours = self.our_devices()
        disks = []
        for root in snap.roots:
            if root.kname in ours or (root.type == "rom" and not root.fstype):
                continue
            if root.kname.startswith("zram") or (root.type == "loop" and not root.fstype
                                                  and not root.children):
                continue
            if root.type not in ("disk", "loop", "rom"):
                continue
            disks.append(self._describe_disk(root, snap, ours))
        return disks

    def _describe_disk(self, disk: BlockDevice, snap: Snapshot, ours: dict[str, Layer]) -> dict[str, Any]:
        parts = [c for c in disk.children if c.type == "part"]
        volumes_src = parts if parts else [disk]
        volumes = [self._describe_volume(v, snap, ours) for v in volumes_src]
        return {
            "id": disk.kname, "device": disk.path, "type": disk.type, "size": disk.size,
            "model": disk.model, "vendor": disk.vendor, "serial": disk.serial,
            "transport": disk.tran, "removable": disk.removable or disk.hotplug,
            "readonly": disk.readonly,
            "system": any(snap.system.is_system(d.kname) for d in disk.walk()),
            "live_medium": disk.kname in snap.system.live_medium,
            "volumes": volumes,
        }

    def role(self, dev: BlockDevice) -> str:
        if dev.fstype in ROLE_BY_FSTYPE:
            return ROLE_BY_FSTYPE[dev.fstype]
        if dev.fstype in FILESYSTEM_TYPES:
            return "filesystem"
        if dev.fstype is None:
            return "unknown"
        return "unsupported"

    def _describe_volume(self, dev: BlockDevice, snap: Snapshot, ours: dict[str, Layer]) -> dict[str, Any]:
        role = self.role(dev)
        warnings: list[dict[str, str]] = []
        reason = snap.system.reasons.get(dev.kname)
        host_mounts = [m for m in snap.host_mounts.get(dev.kname, [])
                       if not m.startswith(str(paths.mount_root()))]
        if reason:
            warnings.append({"code": "system", "message": f"This volume {reason}. Scanning a "
                             "running system is less reliable, and files may change during the scan."})
        elif host_mounts and dev.kname in snap.host_rw:
            warnings.append({"code": "mounted_elsewhere", "message": "Already mounted read-write "
                             f"by this computer at {', '.join(host_mounts)}. The scan will use a "
                             "read-only view, but other programs can still write to it. Unmount "
                             "it first for full protection."})
        elif self._host_holders(dev.kname, ours):
            warnings.append({"code": "in_use_by_host", "message": "This computer is already using "
                             "this volume (an active LVM, RAID or encryption mapping: "
                             f"{', '.join(self._host_holders(dev.kname, ours))}). Deactivate it "
                             "first, or the scan may see changing data."})
        elif host_mounts:
            warnings.append({"code": "mounted_elsewhere_ro", "message": "Already mounted "
                             f"(read-only) by this computer at {', '.join(host_mounts)}; the scan "
                             "will use that mount."})
        info: dict[str, Any] = {
            "id": dev.kname, "device": dev.path, "type": dev.type, "size": dev.size,
            "fstype": dev.fstype, "fsver": dev.fsver, "label": dev.label or dev.partlabel,
            "uuid": dev.uuid, "role": role, "system": bool(reason), "system_reason": reason,
            "host_mounts": host_mounts, "warnings": warnings, "children": [],
            "mountpoint": None, "encryption": None,
        }
        layer = self._mount_layer(dev.kname)
        if layer:
            info["mountpoint"] = layer.target
            info["driver"] = layer.extra.get("driver")
        if role in ("luks", "bitlocker"):
            info["encryption"] = {"kind": role, "version": dev.fsver,
                                  "unlocked": dev.kname in self.state.parents.values()}
        cached = self.probe_cache.get(self._cache_key(dev))
        if cached:
            info.update({k: v for k, v in cached.items() if k != "warnings"})
            warnings.extend(cached.get("warnings", []))
        # Volumes we created on top of this one (unlocked / LVM).
        for child_kname, parent in self.state.parents.items():
            if parent == dev.kname and child_kname in snap.devices:
                info["children"].append(self._describe_volume(snap.devices[child_kname], snap, ours))
        return info

    @staticmethod
    def _host_holders(kname: str, ours: dict[str, Layer]) -> list[str]:
        """Device-mapper/md devices the host stacked on ``kname`` (not ours)."""
        try:
            holders = os.listdir(f"/sys/class/block/{kname}/holders")
        except OSError:
            return []
        out = []
        for holder in holders:
            if holder in ours:
                continue
            try:
                with open(f"/sys/class/block/{holder}/dm/name", encoding="utf-8") as fh:
                    out.append(fh.read().strip())
            except OSError:
                out.append(holder)
        return out

    @staticmethod
    def _cache_key(dev: BlockDevice) -> str:
        return f"{dev.kname}:{dev.uuid}:{dev.size}"

    def resolve(self, kname: str, snap: Snapshot | None = None) -> tuple[BlockDevice, Snapshot]:
        snap = snap or self.snapshot()
        if "/" in kname or kname not in snap.devices:
            raise VolumeError(f"unknown volume {kname!r}", "not_found")
        ours = self.our_devices()
        if kname in ours and ours[kname].kind == "loop" and kname not in self.state.parents:
            raise VolumeError("that is an internal device", "not_permitted")
        return snap.devices[kname], snap

    # ------------------------------------------------------------- protection

    def _parent_disk(self, dev: BlockDevice, snap: Snapshot) -> BlockDevice | None:
        if dev.type == "part" and dev.pkname and dev.pkname in snap.devices:
            return snap.devices[dev.pkname]
        return None

    def _disk_in_use(self, disk: BlockDevice, snap: Snapshot, exclude: str) -> bool:
        for node in disk.walk():
            if node.kname == exclude:
                continue
            if snap.system.is_system(node.kname) or snap.host_mounts.get(node.kname):
                return True
        return False

    def _setro(self, path: str, owner: str) -> None:
        # Shared by several volumes: the first layer knows the true original state.
        earlier = [layer for layer in self.state.layers
                   if layer.kind == "setro" and layer.target == path]
        was_ro = earlier[0].extra.get("was_ro", True) if earlier else blockdev.get_ro(path)
        layer = Layer("setro", path, owner, {"was_ro": was_ro})
        self._add(layer)
        if not was_ro:
            blockdev.set_ro(path, True)

    def _protected_loop(self, dev: BlockDevice, snap: Snapshot, owner: str) -> str:
        """Set the block-level read-only flag, then attach a read-only loop.

        The kernel reports a partition as read-only if either its own flag or
        its disk's flag is set, so we protect exactly one level: the whole
        disk when nothing else on it is in use (this covers every partition),
        otherwise only the partition.  That keeps the recorded original state
        accurate so teardown restores exactly what was there.
        """
        if snap.system.is_system(dev.kname):
            raise VolumeError("refusing to change block devices of the running system", "not_permitted")
        disk = self._parent_disk(dev, snap)
        if disk is not None and not self._disk_in_use(disk, snap, dev.kname):
            self._setro(disk.path, owner)
        else:
            self._setro(dev.path, owner)
        if not blockdev.get_ro(dev.path):
            raise VolumeError(f"could not make {dev.path} read-only", "failed")
        layer = Layer("loop", "", owner, {"source": dev.path})
        loop = blockdev.attach_loop_readonly(dev.path)
        layer.target = loop
        self._add(layer)
        return loop

    # ------------------------------------------------------------------ mount

    def mount(self, kname: str, keep: bool = False, owner: str | None = None) -> dict[str, Any]:
        with self._lock:
            dev, snap = self.resolve(kname)
            owner = owner or kname
            existing = self._mount_layer(owner)
            if existing:
                return self._mount_info(existing)
            role = self.role(dev)
            if role != "filesystem":
                raise VolumeError(f"this volume holds {dev.fstype or 'no recognised filesystem'}, "
                                  "not a mountable filesystem", "not_permitted")
            target = str(paths.mount_root() / owner.replace(":", "_"))
            host = [m for m in snap.host_mounts.get(kname, [])
                    if not m.startswith(str(paths.mount_root()))]
            ours = self.our_devices()
            try:
                if host:
                    result = mounting.bind_readonly(host[0], target)
                    layer = Layer("mount", target, owner, {"driver": "bind", "view_of": host[0],
                                                           "fstype": dev.fstype})
                    self._add(layer)
                elif kname in ours:                       # our read-only dm mapping
                    layer = Layer("mount", target, owner, {"fstype": dev.fstype})
                    self._add(layer)
                    result = mounting.mount(dev.path, target, dev.fstype or "")
                else:
                    loop = self._protected_loop(dev, snap, owner)
                    layer = Layer("mount", target, owner, {"fstype": dev.fstype})
                    self._add(layer)
                    result = mounting.mount(loop, target, dev.fstype or "")
            except Exception as exc:
                self.teardown(owner)
                attempts = getattr(exc, "attempts", None) or []
                detail = (" (" + "; ".join(a[:200] for a in attempts) + ")") if attempts else ""
                raise VolumeError(f"could not mount {dev.path} read-only: {exc}{detail}", "failed",
                                  {"attempts": attempts}) from exc
            layer.extra.update({"driver": result.driver, "options": result.options,
                                "messages": result.messages})
            self._save()
            if keep:
                self.state.keep.add(self._root_owner(owner))
                self._save()
            return self._mount_info(layer)

    def _mount_info(self, layer: Layer) -> dict[str, Any]:
        return {"volume": layer.owner, "mountpoint": layer.target,
                "driver": layer.extra.get("driver"), "fstype": layer.extra.get("fstype"),
                "options": layer.extra.get("options", []), "view_of": layer.extra.get("view_of"),
                "messages": layer.extra.get("messages", [])}

    def mountpoint(self, kname: str) -> str | None:
        layer = self._mount_layer(kname)
        return layer.target if layer else None

    def unmount(self, kname: str) -> None:
        with self._lock:
            if not self._mount_layer(kname):
                raise VolumeError(f"{kname} is not mounted by this program", "not_found")
            self._teardown_layers(lambda layer: layer.owner == kname)
            self.state.keep.discard(kname)
            self._save()

    def keep(self, kname: str) -> None:
        """Keep ``kname`` (and what it needs) after this helper exits."""
        with self._lock:
            self.state.keep.add(self._root_owner(kname))
            self._save()

    def cleanup(self, include_kept: bool = False) -> None:
        with self._lock:
            owners = [layer.owner for layer in self.state.layers
                      if include_kept or self._root_owner(layer.owner) not in self.state.keep]
            for owner in dict.fromkeys(reversed(owners)):
                self.teardown(owner)
            if include_kept:
                self.state.keep.clear()
                self._save()

    # ------------------------------------------------------------ teardown

    def teardown(self, owner: str) -> None:
        with self._lock:
            owners = {owner} | {c for c in self._descendants(owner)}
            owners |= {f"probe:{o}" for o in owners}
            self._teardown_layers(lambda layer: layer.owner in owners)
            for o in owners:
                self.state.parents.pop(o, None)
                self.state.keep.discard(o)
            self._save()

    def _descendants(self, owner: str) -> set[str]:
        out: set[str] = set()
        todo = [owner]
        while todo:
            cur = todo.pop()
            for child, parent in self.state.parents.items():
                if parent == cur and child not in out:
                    out.add(child)
                    todo.append(child)
        return out

    def _teardown_layers(self, select: Callable[[Layer], bool]) -> None:
        errors = []
        for layer in reversed(list(self.state.layers)):
            if not select(layer):
                continue
            try:
                self._remove_layer(layer)
            except Exception as exc:
                errors.append(f"{layer.kind} {layer.target}: {exc}")
                logger.error("could not remove %s %s: %s", layer.kind, layer.target, exc)
                continue
            self.state.layers.remove(layer)
            self._save()
        if errors:
            raise VolumeError("cleanup incomplete: " + "; ".join(errors), "failed")

    def _remove_layer(self, layer: Layer) -> None:
        if layer.kind == "mount":
            if mounting.is_mounted(layer.target):
                mounting.umount(layer.target)
            else:
                try:
                    os.rmdir(layer.target)
                except OSError:
                    pass
        elif layer.kind == "crypt":
            if os.path.exists(f"/dev/mapper/{layer.target}"):
                crypt.cryptsetup_close(layer.target)
        elif layer.kind == "dislocker":
            crypt.dislocker_close(layer.target)
        elif layer.kind == "lvm":
            if os.path.exists(f"/dev/mapper/{layer.target}"):
                lvm.deactivate(layer.target)
        elif layer.kind == "loop":
            if layer.target and blockdev.loop_backing(layer.target) is not None:
                blockdev.detach_loop(layer.target)
        elif layer.kind == "unsetro":                 # a writable session lifted a shared flag
            if os.path.exists(layer.target):
                blockdev.set_ro(layer.target, True)
        elif layer.kind == "setro":
            still_needed = any(o is not layer and o.kind == "setro" and o.target == layer.target
                               for o in self.state.layers)
            if not layer.extra.get("was_ro", True) and not still_needed and os.path.exists(layer.target):
                blockdev.set_ro(layer.target, False)

    # ---------------------------------------------------------------- unlock

    def unlock(self, kname: str, secret: str, secret_kind: str = "passphrase") -> dict[str, Any]:
        with self._lock:
            dev, snap = self.resolve(kname)
            role = self.role(dev)
            if role not in ("luks", "bitlocker"):
                raise VolumeError("this volume is not encrypted with LUKS or BitLocker", "not_permitted")
            if any(parent == kname for parent in self.state.parents.values()):
                raise VolumeError("already unlocked", "busy")
            if role == "bitlocker" and secret_kind == "recovery_key":
                try:
                    secret = crypt.normalize_recovery_key(secret)
                except crypt.UnlockError as exc:
                    raise VolumeError(str(exc), "invalid_params") from exc
            loop = self._protected_loop(dev, snap, kname)
            name = crypt.mapper_name(kname)
            layer = Layer("crypt", name, kname, {"source": loop, "kind": role})
            self._add(layer)
            try:
                crypt.cryptsetup_open(loop, name, role, secret.encode("utf-8"))
            except crypt.UnlockError as exc:
                if role == "bitlocker" and "wrong" not in str(exc):
                    self.state.layers.remove(layer)
                    self._save()
                    return self._unlock_dislocker(kname, loop, secret, secret_kind)
                self.teardown(kname)
                code = "not_permitted" if "wrong" in str(exc) else "failed"
                raise VolumeError(str(exc), code) from exc
            child = system.kname_for_path(f"/dev/mapper/{name}")
            if child is None:
                self.teardown(kname)
                raise VolumeError("the unlocked device did not appear")
            self.state.parents[child] = kname
            self._save()
            return {"volume": kname, "unlocked": child, "device": f"/dev/mapper/{name}"}

    def _unlock_dislocker(self, kname: str, loop: str, secret: str, secret_kind: str) -> dict[str, Any]:
        workdir = str(paths.runtime_dir() / "dislocker" / kname)
        layer = Layer("dislocker", workdir, kname, {"source": loop})
        self._add(layer)
        try:
            image = crypt.dislocker_open(loop, workdir, secret, secret_kind)
            inner = blockdev.attach_loop_readonly(image)
        except Exception as exc:
            self.teardown(kname)
            raise VolumeError(f"could not unlock the BitLocker volume: {exc}") from exc
        self._add(Layer("loop", inner, kname, {"source": image}))
        child = os.path.basename(inner)
        self.state.parents[child] = kname
        self._save()
        return {"volume": kname, "unlocked": child, "device": inner, "via": "dislocker"}

    def lock(self, kname: str) -> None:
        with self._lock:
            if not any(parent == kname for parent in self.state.parents.values()):
                raise VolumeError(f"{kname} is not unlocked", "not_found")
            self.teardown(kname)

    # ------------------------------------------------------------------ LVM

    def activate_lvm(self, kname: str) -> dict[str, Any]:
        with self._lock:
            dev, snap = self.resolve(kname)
            if self.role(dev) != "lvm_pv":
                raise VolumeError("this volume is not an LVM physical volume", "not_permitted")
            if any(parent == kname for parent in self.state.parents.values()):
                raise VolumeError("already activated", "busy")
            ours = self.our_devices()
            source = dev.path if kname in ours else self._protected_loop(dev, snap, kname)
            try:
                volumes = lvm.logical_volumes([source])
            except lvm.LvmError as exc:
                self.teardown(kname)
                raise VolumeError(f"cannot read LVM metadata: {exc}") from exc
            activated, skipped = [], []
            for lv in volumes:
                if not lv.supported:
                    skipped.append({"name": f"{lv.vg}/{lv.name}", "reason": lv.reason})
                    continue
                layer = Layer("lvm", lv.dm_name, kname, {"vg": lv.vg, "lv": lv.name})
                self._add(layer)
                try:
                    path = lvm.activate_readonly(lv)
                except Exception as exc:
                    self.state.layers.remove(layer)
                    self._save()
                    skipped.append({"name": f"{lv.vg}/{lv.name}", "reason": str(exc)})
                    continue
                child = system.kname_for_path(path)
                if child:
                    self.state.parents[child] = kname
                    activated.append({"name": f"{lv.vg}/{lv.name}", "volume": child, "device": path})
            self._save()
            if not activated and not skipped:
                self.teardown(kname)
                raise VolumeError("no logical volumes found", "not_found")
            return {"volume": kname, "activated": activated, "skipped": skipped}

    # ---------------------------------------------------------------- probe

    def probe(self, kname: str) -> dict[str, Any]:
        """Detect OS, hibernation and filesystem state using a temporary read-only mount."""
        with self._lock:
            dev, snap = self.resolve(kname)
            result: dict[str, Any] = {"os": None, "hibernation": None, "fs_state": None,
                                      "warnings": []}
            if self.role(dev) != "filesystem":
                return result
            state = None
            if not snap.system.is_system(kname) and not snap.host_mounts.get(kname):
                state = superblock.probe(dev.path, dev.fstype)
            if state is not None:
                result["fs_state"] = {"clean": state.clean, "detail": state.detail}
                if state.needs_recovery or state.orphans:
                    result["warnings"].append({
                        "code": "needs_recovery",
                        "message": f"The filesystem was not cleanly unmounted ({state.detail}). "
                                   "It is mounted without replaying its journal, so the most "
                                   "recent changes may be missing from the scan."})
            mounted_here = self.mountpoint(kname)
            owner = f"probe:{kname}"
            try:
                target = mounted_here or self.mount(kname, owner=owner)["mountpoint"]
            except VolumeError as exc:
                result["warnings"].append({"code": "probe_failed", "message": str(exc)})
                return result
            try:
                detected = self._detect(target)
                result["warnings"].extend(detected.pop("warnings", []))
                result.update(detected)
            finally:
                if not mounted_here:
                    self.teardown(owner)
            self.probe_cache[self._cache_key(dev)] = result
            return result

    def _detect(self, mountpoint: str) -> dict[str, Any]:
        out: dict[str, Any] = {"os": None, "hibernation": None, "warnings": []}
        with RootFS(mountpoint) as root:
            hive = osdetect.windows_hive(root)
            if hive is not None:
                info = osdetect.OSInfo("windows", "Windows")
                try:
                    fd = root.open_regular(hive)
                    try:
                        values = sandbox.run("windows.version", fds=[fd], timeout=120)
                    finally:
                        os.close(fd)
                    info = osdetect.windows_version_from_values(values)
                except Exception as exc:
                    logger.warning("windows version detection failed: %s", exc)
                out["os"] = info.to_dict()
                hib = hibernation.detect(root)
                if hib is not None:
                    out["hibernation"] = {"hibernated": hib.hibernated, "reason": hib.reason,
                                          "explanation": hib.explain()}
                    if hib.hibernated:
                        out["warnings"].append({"code": "hibernated", "message": hib.explain()})
                return out
            linux = osdetect.detect_linux(root)
            if linux is not None:
                out["os"] = linux.to_dict()
                return out
            efi = osdetect.detect_efi(root)
            if efi is not None:
                out["os"] = efi.to_dict()
        return out
