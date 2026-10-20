"""Parse ``lsblk --json`` output into a device tree."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .. import tools

COLUMNS = (
    "NAME,KNAME,PATH,MAJ:MIN,TYPE,SIZE,MODEL,VENDOR,SERIAL,TRAN,RM,HOTPLUG,RO,"
    "FSTYPE,FSVER,LABEL,UUID,PARTUUID,PARTTYPE,PARTLABEL,PKNAME,MOUNTPOINTS"
)


@dataclass
class BlockDevice:
    name: str
    kname: str
    path: str
    majmin: str
    type: str
    size: int
    model: str | None = None
    vendor: str | None = None
    serial: str | None = None
    tran: str | None = None
    removable: bool = False
    hotplug: bool = False
    readonly: bool = False
    fstype: str | None = None
    fsver: str | None = None
    label: str | None = None
    uuid: str | None = None
    partuuid: str | None = None
    parttype: str | None = None
    partlabel: str | None = None
    pkname: str | None = None
    mountpoints: list[str] = field(default_factory=list)
    children: list[BlockDevice] = field(default_factory=list)

    def walk(self) -> list[BlockDevice]:
        out = [self]
        for child in self.children:
            out.extend(child.walk())
        return out


def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip() in ("1", "true")
    if isinstance(value, int):
        return value != 0
    return False


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_node(node: dict[str, Any]) -> BlockDevice:
    mountpoints = node.get("mountpoints")
    if mountpoints is None and "mountpoint" in node:     # util-linux < 2.37
        mountpoints = [node.get("mountpoint")]
    dev = BlockDevice(
        name=_str(node.get("name")) or "",
        kname=_str(node.get("kname")) or _str(node.get("name")) or "",
        path=_str(node.get("path")) or "/dev/" + (_str(node.get("kname")) or ""),
        majmin=_str(node.get("maj:min")) or _str(node.get("maj_min")) or "",
        type=_str(node.get("type")) or "unknown",
        size=_int(node.get("size")),
        model=_str(node.get("model")),
        vendor=_str(node.get("vendor")),
        serial=_str(node.get("serial")),
        tran=_str(node.get("tran")),
        removable=_bool(node.get("rm")),
        hotplug=_bool(node.get("hotplug")),
        readonly=_bool(node.get("ro")),
        fstype=_str(node.get("fstype")),
        fsver=_str(node.get("fsver")),
        label=_str(node.get("label")),
        uuid=_str(node.get("uuid")),
        partuuid=_str(node.get("partuuid")),
        parttype=_str(node.get("parttype")),
        partlabel=_str(node.get("partlabel")),
        pkname=_str(node.get("pkname")),
        mountpoints=[m for m in (mountpoints or []) if m],
    )
    dev.children = [_parse_node(c) for c in node.get("children") or [] if isinstance(c, dict)]
    return dev


def parse(text: str) -> list[BlockDevice]:
    data = json.loads(text)
    nodes = data.get("blockdevices") or []
    return [_parse_node(n) for n in nodes if isinstance(n, dict)]


def list_devices(devices: list[str] | None = None) -> list[BlockDevice]:
    lsblk = tools.require("lsblk")
    args = [lsblk, "--json", "--bytes", "--output", COLUMNS]
    if devices:
        args += ["--nodeps", *devices]
    proc = tools.run(args, timeout=60)
    return parse(proc.stdout)


def flatten(devices: list[BlockDevice]) -> dict[str, BlockDevice]:
    """Map kernel name -> device (a device can appear under several parents)."""
    out: dict[str, BlockDevice] = {}
    for dev in devices:
        for node in dev.walk():
            out.setdefault(node.kname, node)
    return out


def blkid_probe(path: str) -> dict[str, str]:
    """Low-level probe (``blkid -p``) used when lsblk lacks udev data."""
    blkid = tools.find("blkid")
    if blkid is None:
        return {}
    proc = tools.run([blkid, "-p", "-o", "export", path], timeout=30, check=False)
    if proc.returncode not in (0, 2):
        return {}
    result: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            result[key.strip()] = value.strip()
    return result


def fill_missing_fstypes(devices: list[BlockDevice]) -> None:
    """In containers without udev, lsblk leaves FSTYPE empty; probe directly."""
    for dev in flatten(devices).values():
        if dev.fstype or dev.type not in ("disk", "part", "loop", "crypt", "lvm"):
            continue
        if dev.children and dev.type == "disk":
            continue
        info = blkid_probe(dev.path)
        dev.fstype = info.get("TYPE")
        dev.fsver = dev.fsver or info.get("VERSION")
        dev.label = dev.label or info.get("LABEL")
        dev.uuid = dev.uuid or info.get("UUID")
