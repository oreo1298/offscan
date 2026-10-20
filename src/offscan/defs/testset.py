"""A tiny definition set that detects only the EICAR test file.

Used by the self-test (``offscan selftest --engines``) and the test suite to
prove that each engine works end to end without downloading anything.  The
EICAR string is assembled at run time, so no file in this project contains
it and nothing here is real malware.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .. import appinfo
from . import build

SOURCE_ID = "selftest"
PREFIX = appinfo.SIGNATURE_PREFIX
YARA_RULE = f"{PREFIX.lower()}_selftest_eicar"
HASH_SIGNATURE = f"{PREFIX}.SelfTest.EICAR.sha256"
CLAMAV_SIGNATURES = (f"{PREFIX}.SelfTest.EICAR.Hash", f"{PREFIX}.SelfTest.EICAR.Body")


def eicar() -> bytes:
    return ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")


def yara_rule() -> str:
    return (
        f"rule {YARA_RULE} {{\n"
        "  meta:\n"
        f'    author = "{appinfo.NAME} self-test"\n'
        '    description = "EICAR anti-virus test file"\n'
        '    category = "test"\n'
        '    severity = "info"\n'
        "  strings:\n"
        '    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii\n'
        "  condition:\n"
        "    $a\n"
        "}\n")


def clamav_signatures() -> dict[str, bytes]:
    data = eicar()
    sha = hashlib.sha256(data).hexdigest()
    hsb = f"{sha}:{len(data)}:{CLAMAV_SIGNATURES[0]}:73\n"
    ndb = f"{CLAMAV_SIGNATURES[1]}:0:*:{data[:40].hex()}\n"
    return {f"{appinfo.NAME}-selftest.hsb": hsb.encode(), f"{appinfo.NAME}-selftest.ndb": ndb.encode()}


def build_test_set(out: Path, with_clamav: bool = True, with_yara: bool = True,
                   with_hashes: bool = True, yara_engine_name: str | None = None) -> dict[str, Any]:
    info = {"name": "Self-test (EICAR only)", "version": "1", "license": "GPL-3.0-or-later",
            "updated": 0}
    return build.build_set(
        out, set_id="selftest",
        sources={SOURCE_ID: info},
        clamav_files=clamav_signatures() if with_clamav else None,
        yara_sources=[("selftest", "selftest.yar", yara_rule())] if with_yara else None,
        yara_namespaces={"selftest": SOURCE_ID},
        hash_lists={SOURCE_ID: ({"name": "Self-test list", "category": "test", "severity": "info",
                                 "signature": HASH_SIGNATURE},
                                [hashlib.sha256(eicar()).digest()])} if with_hashes else None,
        yara_engine_name=yara_engine_name)
