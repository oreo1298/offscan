"""Read-only access to LVM logical volumes without touching LVM metadata.

LVM's own ``--readonly`` mode reads metadata but refuses to activate, and
normal activation can write metadata, conflict with identically named host
volume groups (two Ubuntu installs both have ``ubuntu-vg``) or be undone by
host auto-activation.  So we read the metadata with ``lvm lvs --readonly``,
restricted by a device filter to our read-only loop devices, and build the
device-mapper tables ourselves with ``dmsetup create --readonly`` under our
own names.  Linear and striped segments are supported (what installers
create); thin, RAID, cache and snapshot segments are reported unsupported.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass

from .. import appinfo, tools
from . import blockdev

SUPPORTED_SEGMENTS = ("linear", "striped")


class LvmError(Exception):
    pass


@dataclass
class LogicalVolume:
    vg: str
    name: str
    uuid: str
    size_sectors: int
    table: list[str]
    supported: bool
    reason: str = ""

    @property
    def dm_name(self) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.+-]", "_", f"{self.vg}-{self.name}")
        return f"{appinfo.DEVICE_PREFIX}lvm-{safe}"[:120]


def _config(devices: list[str]) -> str:
    accept = ", ".join(f'"a|^{re.escape(d)}$|"' for d in devices)
    filt = f'[ {accept}, "r|.*|" ]'
    return (f"devices {{ filter = {filt} global_filter = {filt} use_devicesfile = 0 "
            "obtain_device_list_from_udev = 0 } "
            "global { metadata_read_only = 1 use_lvmetad = 0 } "
            "backup { backup = 0 archive = 0 }")


def _lvm(args: list[str], devices: list[str]) -> dict:
    lvm = tools.require("lvm")
    proc = tools.run([lvm, *args, "--readonly", "--reportformat", "json", "--units", "s",
                      "--nosuffix", "--config", _config(devices)], timeout=120, check=False)
    if proc.returncode != 0:
        raise LvmError((proc.stderr or proc.stdout).strip()[:500] or "lvm failed")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise LvmError("unexpected lvm output") from exc


def _report(data: dict, kind: str) -> list[dict]:
    rows: list[dict] = []
    for report in data.get("report", []):
        rows.extend(report.get(kind, []))
    return rows


def physical_volumes(devices: list[str]) -> list[dict]:
    data = _lvm(["pvs", "-o", "pv_name,pv_uuid,vg_name,vg_uuid,pe_start,vg_extent_size"], devices)
    return _report(data, "pv")


_DEV_RE = re.compile(r"([^,()]+)\((\d+)\)")


def logical_volumes(devices: list[str]) -> list[LogicalVolume]:
    pvs = {row["pv_name"]: row for row in physical_volumes(devices)}
    data = _lvm(["lvs", "-a", "-o", "vg_name,lv_name,lv_uuid,lv_size,segtype,seg_start_pe,"
                 "seg_size_pe,stripes,stripe_size,devices,vg_extent_size"], devices)
    by_lv: dict[tuple[str, str], LogicalVolume] = {}
    for row in _report(data, "lv"):
        key = (row["vg_name"], row["lv_name"])
        lv = by_lv.get(key)
        if lv is None:
            lv = LogicalVolume(row["vg_name"], row["lv_name"], row.get("lv_uuid", ""),
                               int(float(row.get("lv_size") or 0)), [], True)
            by_lv[key] = lv
        segtype = row.get("segtype", "")
        if segtype not in SUPPORTED_SEGMENTS:
            lv.supported = False
            lv.reason = f"segment type {segtype!r} is not supported"
            continue
        extent = int(float(row.get("vg_extent_size") or 0))
        start = int(row["seg_start_pe"]) * extent
        length = int(row["seg_size_pe"]) * extent
        targets = []
        for dev, pe in _DEV_RE.findall(row.get("devices", "")):
            pv = pvs.get(dev)
            if pv is None:
                lv.supported = False
                lv.reason = f"physical volume {dev} is missing"
                break
            offset = int(float(pv["pe_start"])) + int(pe) * extent
            targets.append(f"{dev} {offset}")
        if not lv.supported:
            continue
        if segtype == "linear" and len(targets) == 1:
            lv.table.append(f"{start} {length} linear {targets[0]}")
        else:
            stripes = int(row.get("stripes") or len(targets))
            chunk = int(float(row.get("stripe_size") or 0))
            if stripes != len(targets) or chunk <= 0:
                lv.supported = False
                lv.reason = "could not interpret striped segment"
                continue
            lv.table.append(f"{start} {length} striped {stripes} {chunk} {' '.join(targets)}")
    # Hidden internal volumes ([lv_tmeta] etc.) are never mountable.
    return [lv for lv in by_lv.values() if not lv.name.startswith("[")]


def activate_readonly(lv: LogicalVolume) -> str:
    if not lv.supported:
        raise LvmError(f"{lv.vg}/{lv.name}: {lv.reason}")
    dmsetup = tools.require("dmsetup")
    table = "\n".join(lv.table) + "\n"
    tools.run([dmsetup, "create", lv.dm_name, "--readonly", "--uuid",
               f"{appinfo.NAME.upper()}-LVM-{lv.uuid}"[:128]],
              input=table.encode(), timeout=60)
    path = f"/dev/mapper/{lv.dm_name}"
    deadline = time.monotonic() + 15
    while not os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.1)
    if not os.path.exists(path):
        raise LvmError(f"{path} did not appear")
    if not blockdev.get_ro(path):
        deactivate(lv.dm_name)
        raise LvmError("mapping is not read-only; removed it again")
    return path


def deactivate(dm_name: str) -> None:
    dmsetup = tools.require("dmsetup")
    for attempt in range(5):
        proc = tools.run([dmsetup, "remove", dm_name], timeout=60, check=False)
        if proc.returncode == 0 or not os.path.exists(f"/dev/mapper/{dm_name}"):
            return
        time.sleep(0.5 * (attempt + 1))
    raise LvmError(f"could not remove {dm_name}")
