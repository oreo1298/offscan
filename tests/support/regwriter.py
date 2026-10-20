"""Minimal Windows registry hive (REGF) writer for test fixtures.

Produces small but structurally valid hives (base block with checksum, one
or more hbins, nk/vk/lf/value-list/data cells) so that persistence checks
can be tested against fake Run keys, services, IFEO entries and so on
without any real Windows data.
"""

from __future__ import annotations

import struct
from pathlib import Path

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ = 1, 2, 3, 4, 7
FILETIME_2026 = 134_000_000_000_000_000


class Key:
    def __init__(self, name: str):
        self.name = name
        self.subkeys: dict[str, Key] = {}
        self.values: list[tuple[str, int, bytes]] = []

    def key(self, path: str) -> Key:
        node = self
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            lower = part.lower()
            match = next((k for n, k in node.subkeys.items() if n.lower() == lower), None)
            if match is None:
                match = Key(part)
                node.subkeys[part] = match
            node = match
        return node

    def set(self, name: str, value: str | int | bytes | list[str], kind: int | None = None) -> Key:
        if isinstance(value, int) and not isinstance(value, bool):
            data, kind = struct.pack("<I", value), kind or REG_DWORD
        elif isinstance(value, list):
            data, kind = ("\0".join(value) + "\0\0").encode("utf-16-le"), kind or REG_MULTI_SZ
        elif isinstance(value, bytes):
            data, kind = value, kind or REG_BINARY
        else:
            data, kind = (value + "\0").encode("utf-16-le"), kind or REG_SZ
        self.values.append((name, kind, data))
        return self


class _Writer:
    def __init__(self) -> None:
        self.data = bytearray()

    def alloc(self, payload: bytes) -> int:
        size = len(payload) + 4
        size += -size % 8
        offset = len(self.data)
        self.data += struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload))
        return offset

    def patch(self, offset: int, payload: bytes) -> None:
        self.data[offset + 4:offset + 4 + len(payload)] = payload


def _nk(key: Key, flags: int, parent: int, subkeys: int, subkey_list: int, values: int,
        value_list: int, sk: int) -> bytes:
    name = key.name.encode("ascii")
    max_sub = max((len(k.name) * 2 for k in key.subkeys.values()), default=0)
    max_vname = max((len(v[0]) * 2 for v in key.values), default=0)
    max_vdata = max((len(v[2]) for v in key.values), default=0)
    return (b"nk" + struct.pack("<HQ4sIIIIIIIIIIIII4sHH", flags, FILETIME_2026, b"\0" * 4, parent,
                                subkeys, 0, subkey_list, 0xFFFFFFFF, values, value_list, sk,
                                0xFFFFFFFF, max_sub, 0, max_vname, max_vdata, b"\0" * 4,
                                len(name), 0) + name)


def _alloc_sk(w: _Writer) -> int:
    descriptor = b"\x01\x00\x04\x80" + b"\0" * 16
    sk = w.alloc(b"sk" + struct.pack("<HIIII", 0, 0, 0, 1, len(descriptor)) + descriptor)
    w.patch(sk, b"sk" + struct.pack("<HIIII", 0, sk, sk, 1, len(descriptor)) + descriptor)
    return sk


def _write_key(w: _Writer, key: Key, parent: int, sk: int, root: bool = False) -> int:
    flags = 0x0020 | (0x0004 | 0x0008 if root else 0)
    # Readers such as regipy take the first cell of the first bin as the root key.
    me = w.alloc(_nk(key, flags, parent, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF, sk))
    if root:
        sk = _alloc_sk(w)
    value_offsets = []
    for name, kind, data in key.values:
        if len(data) <= 4:
            size_field = len(data) | 0x80000000
            data_off = struct.unpack("<I", data.ljust(4, b"\0"))[0]
        else:
            size_field = len(data)
            data_off = w.alloc(data)
        raw = name.encode("ascii")
        value_offsets.append(w.alloc(b"vk" + struct.pack("<HIIIHH", len(raw), size_field, data_off, kind,
                                                         1 if raw else 0, 0) + raw))
    value_list = (w.alloc(b"".join(struct.pack("<I", o) for o in value_offsets)) if value_offsets
                  else 0xFFFFFFFF)
    children = sorted(key.subkeys.values(), key=lambda k: k.name.upper())
    child_offsets = [_write_key(w, child, me, sk) for child in children]
    if child_offsets:
        elements = b"".join(struct.pack("<I4s", off, child.name.encode("ascii")[:4].ljust(4, b"\0"))
                            for off, child in zip(child_offsets, children, strict=True))
        subkey_list = w.alloc(b"lf" + struct.pack("<H", len(child_offsets)) + elements)
    else:
        subkey_list = 0xFFFFFFFF
    w.patch(me, _nk(key, flags, parent, len(child_offsets), subkey_list, len(value_offsets),
                    value_list, sk))
    return me


def write_hive(root: Key, path: Path, file_name: str = "fixture") -> None:
    w = _Writer()
    w.data += b"\0" * 32            # room for the hbin header: offsets are relative to the bin area
    root_off = _write_key(w, root, 0xFFFFFFFF, 0xFFFFFFFF, root=True)
    bin_size = len(w.data) + (-len(w.data) % 4096)
    if bin_size - len(w.data) < 8:
        bin_size += 4096
    free = bin_size - len(w.data)
    w.data += struct.pack("<i", free) + b"\0" * (free - 4)        # one free cell fills the bin
    w.data[0:32] = b"hbin" + struct.pack("<IIIIQI", 0, bin_size, 0, 0, FILETIME_2026, 0)
    header = bytearray(4096)
    struct.pack_into("<4sIIQIIIIIII", header, 0, b"regf", 1, 1, FILETIME_2026, 1, 5, 0, 1,
                     root_off, bin_size, 1)
    name = file_name.encode("utf-16-le")[:64]
    header[0x30:0x30 + len(name)] = name
    checksum = 0
    for (word,) in struct.iter_unpack("<I", bytes(header[:508])):
        checksum ^= word
    struct.pack_into("<I", header, 508, checksum)
    path.write_bytes(bytes(header) + bytes(w.data))
