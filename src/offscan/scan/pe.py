"""Minimal PE header reading and the Authenticode image hash ("Authentihash").

LOLDrivers publishes the Authenticode SHA-256 of vulnerable and malicious
drivers as well as file hashes.  The Authentihash stays the same when a
driver is re-signed or its certificate table is changed, so it also
catches copies whose file hash differs.

The hash covers the whole file except the optional header's CheckSum field,
the Certificate Table data-directory entry and the certificate data itself
(Microsoft "Windows Authenticode Portable Executable Signature Format";
the same ranges as osslsigncode and signify for well-formed images).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

SUBSYSTEM_NATIVE = 1          # kernel drivers


@dataclass
class PEInfo:
    pe32_plus: bool
    subsystem: int
    checksum_offset: int
    security_entry_offset: int
    cert_offset: int
    cert_size: int


def parse(data: bytes) -> PEInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew > len(data) - 24 or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    (size_optional,) = struct.unpack_from("<H", data, e_lfanew + 20)
    opt = e_lfanew + 24
    if size_optional < 96 or opt + size_optional > len(data):
        return None
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic not in (0x10B, 0x20B):
        return None
    plus = magic == 0x20B
    (subsystem,) = struct.unpack_from("<H", data, opt + 68)
    count_offset = opt + (108 if plus else 92)
    directories = opt + (112 if plus else 96)
    (count,) = struct.unpack_from("<I", data, count_offset)
    security = directories + 4 * 8
    if count < 5 or security + 8 > opt + size_optional:
        return None
    cert_offset, cert_size = struct.unpack_from("<II", data, security)
    return PEInfo(plus, subsystem, opt + 64, security, cert_offset, cert_size)


def authentihash(data: bytes, info: PEInfo | None = None) -> bytes | None:
    """Authenticode SHA-256 digest of a PE image, or None if ``data`` is not one."""
    info = info or parse(data)
    if info is None:
        return None
    end = len(data)
    if info.cert_size and info.security_entry_offset + 8 <= info.cert_offset < len(data):
        end = info.cert_offset
    h = hashlib.sha256()
    h.update(data[:info.checksum_offset])
    h.update(data[info.checksum_offset + 4:info.security_entry_offset])
    h.update(data[info.security_entry_offset + 8:end])
    return h.digest()
