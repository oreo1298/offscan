"""Authenticode image hash and its use for LOLDrivers-style driver lists."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from offscan.defs import build
from offscan.scan import pe, runtime, worker
from offscan.scan.options import Limits, ScanOptions
from support.pefile_gen import make_pe

# Reference digests computed by osslsigncode 2.8 ("Calculated message digest") for these exact images,
# both unsigned and after signing them with a throwaway self-signed certificate.
OSSLSIGNCODE_PE32_PLUS = "F4D2D4A83A68E1066BA1ABF7CB2865F00E826DFC1ED6E53D8D7FFFB581D9201C"
OSSLSIGNCODE_PE32 = "E2D0FF99C04647A0D79A52F7301681997B3575CFEDC17FFD820B1939EEBE8607"


def fake_sign(image: bytes, blob: bytes = b"\x30\x82" + b"\x11" * 300) -> bytes:
    """Append a (fake) WIN_CERTIFICATE and point the security directory at it; bump the checksum."""
    info = pe.parse(image)
    assert info is not None
    out = bytearray(image)
    cert = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    cert += b"\0" * (-len(cert) % 8)
    struct.pack_into("<II", out, info.security_entry_offset, len(out), len(cert))
    struct.pack_into("<I", out, info.checksum_offset, 0xDEADBEEF)
    return bytes(out) + cert


def test_reference_vectors() -> None:
    assert pe.authentihash(make_pe(pe32_plus=True)).hex().upper() == OSSLSIGNCODE_PE32_PLUS
    assert pe.authentihash(make_pe(pe32_plus=False)).hex().upper() == OSSLSIGNCODE_PE32


def test_signature_and_checksum_do_not_change_the_hash() -> None:
    image = make_pe()
    signed = fake_sign(image)
    assert hashlib.sha256(signed).digest() != hashlib.sha256(image).digest()
    assert pe.authentihash(signed) == pe.authentihash(image)
    other = make_pe(payload=b"\x90\xc3")
    assert pe.authentihash(other) != pe.authentihash(image)


def test_not_pe() -> None:
    assert pe.parse(b"MZ" + b"\0" * 10) is None
    assert pe.parse(b"\x7fELF" + b"\0" * 200) is None
    truncated = make_pe()[:0x90]
    assert pe.parse(truncated) is None
    assert pe.parse(make_pe(subsystem=3)).subsystem == 3


def test_worker_matches_resigned_driver(tmp_path: Path) -> None:
    driver = make_pe()
    listed = pe.authentihash(driver)
    set_dir = tmp_path / "set"
    build.build_set(set_dir, set_id="t", sources={"lol": {"name": "x", "version": "1"}},
                    authentihash_lists={"lol-ah": ({"name": "LOLDrivers: vulnerable driver",
                                                    "category": "vulnerable_driver", "severity": "medium",
                                                    "signature": "LOLDrivers.VulnerableDriver.Authentihash"},
                                                   [listed])},
                    hash_lists={"other": ({"name": "unrelated"}, [b"\1" * 32])})
    rt = runtime.prepare(set_dir, ScanOptions(volumes=["x"]), os.geteuid(), os.getegid(), base=str(tmp_path))
    engines = worker.Engines(rt, {"runtime": str(rt), "engines": ["hashes"], "mode": "full",
                                  "limits": vars(Limits()), "clamd": False})
    resigned = tmp_path / "Windows/System32/drivers/vuln.sys"
    resigned.parent.mkdir(parents=True)
    resigned.write_bytes(fake_sign(driver))
    console = tmp_path / "tool.exe"
    console.write_bytes(fake_sign(make_pe(subsystem=3)))
    results = {}
    for path in (resigned, console):
        fd = os.open(path, os.O_RDONLY)
        try:
            job = {"id": 1, "path": "/" + path.name, "mode": "full"}
            results[path.name] = worker.process(engines, job, fd)
        finally:
            os.close(fd)
    (det,) = results["vuln.sys"]["detections"]
    assert det["signature"] == "LOLDrivers.VulnerableDriver.Authentihash"
    assert det["severity"] == "medium" and det["details"]["authentihash"] == listed.hex()
    assert results["tool.exe"]["detections"] == []          # not a driver: not looked up
    runtime.cleanup(rt)
