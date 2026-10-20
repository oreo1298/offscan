"""Generate tiny, valid (non-functional) PE images for tests: one section, no imports."""

from __future__ import annotations

import struct


def make_pe(subsystem: int = 1, pe32_plus: bool = True, payload: bytes = b"\xc3" + b"\0" * 15) -> bytes:
    """A 1 KiB PE image (subsystem 1 = native/driver, 2 = GUI, 3 = console)."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt_size = 240 if pe32_plus else 224
    coff = struct.pack("<HHIIIHH", 0x8664 if pe32_plus else 0x14C, 1, 0, 0, 0, opt_size,
                       0x22 if pe32_plus else 0x102)
    if pe32_plus:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
        opt += struct.pack("<QII", 0x140000000, 0x1000, 0x200)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000)
        opt += struct.pack("<III", 0x400000, 0x1000, 0x200)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    opt += struct.pack("<IIIHH", 0x2000, 0x200, 0, subsystem, 0x160)
    opt += struct.pack("<QQQQ" if pe32_plus else "<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    opt += b"\0" * (16 * 8)
    assert len(opt) == opt_size
    section = struct.pack("<8sIIIIIIHHI", b".text", len(payload), 0x1000, 0x200, 0x200, 0, 0, 0, 0,
                          0x60000020)
    headers = bytes(dos) + b"PE\0\0" + coff + opt + section
    image = headers.ljust(0x200, b"\0") + payload.ljust(0x200, b"\0")
    return image
