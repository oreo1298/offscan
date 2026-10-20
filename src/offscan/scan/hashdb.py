"""Compact SHA-256 hash database: a sorted array of digests, memory-mapped.

File layout (little endian)::

    magic  b"OFSHASH1"
    u32    record count N
    u32    source table length L (bytes, UTF-8 JSON list of source ids)
    L      source table
    pad    to 8 bytes
    N*32   sorted SHA-256 digests
    N*2    u16 source index per digest (parallel array)

Lookups binary-search the mmap, so tens of millions of hashes cost no RAM
beyond the page cache, and many worker processes share the same pages.
A digest listed by several sources appears once per source (adjacent).
"""

from __future__ import annotations

import json
import mmap
import os
import struct
from collections.abc import Iterable
from pathlib import Path

MAGIC = b"OFSHASH1"
DIGEST = 32


class HashDBError(Exception):
    pass


def build(path: Path, entries: Iterable[tuple[bytes, str]]) -> int:
    """Write a database from (digest, source_id) pairs; returns the record count."""
    sources: list[str] = []
    index: dict[str, int] = {}
    records: set[tuple[bytes, int]] = set()
    for digest, source in entries:
        if len(digest) != DIGEST:
            raise HashDBError("digest must be 32 bytes")
        sid = index.get(source)
        if sid is None:
            if len(sources) >= 65535:
                raise HashDBError("too many sources")
            sid = index[source] = len(sources)
            sources.append(source)
        records.add((digest, sid))
    ordered = sorted(records)
    table = json.dumps(sources).encode()
    header = MAGIC + struct.pack("<II", len(ordered), len(table)) + table
    header += b"\0" * (-len(header) % 8)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(header)
        fh.write(b"".join(d for d, _ in ordered))
        fh.write(b"".join(struct.pack("<H", s) for _, s in ordered))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return len(ordered)


class HashDB:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = str(path)
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size < 16:
                raise HashDBError("hash database is truncated")
            self._mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        if self._mm[:8] != MAGIC:
            raise HashDBError("not a hash database")
        count, table_len = struct.unpack_from("<II", self._mm, 8)
        table_end = 16 + table_len
        try:
            self.sources: list[str] = json.loads(self._mm[16:table_end].decode())
        except ValueError as exc:
            raise HashDBError("corrupt source table") from exc
        self._digests = table_end + (-table_end % 8)
        self._ids = self._digests + count * DIGEST
        if self._ids + count * 2 != size:
            raise HashDBError("hash database size mismatch")
        self.count = count

    def close(self) -> None:
        self._mm.close()

    def _digest_at(self, i: int) -> bytes:
        off = self._digests + i * DIGEST
        return self._mm[off:off + DIGEST]

    def lookup(self, digest: bytes) -> list[str]:
        """Source ids listing ``digest`` (empty when unknown)."""
        lo, hi = 0, self.count
        while lo < hi:
            mid = (lo + hi) // 2
            if self._digest_at(mid) < digest:
                lo = mid + 1
            else:
                hi = mid
        out = []
        i = lo
        while i < self.count and self._digest_at(i) == digest:
            (sid,) = struct.unpack_from("<H", self._mm, self._ids + i * 2)
            out.append(self.sources[sid])
            i += 1
        return out

    def __contains__(self, digest: bytes) -> bool:
        return bool(self.lookup(digest))

    def __len__(self) -> int:
        return self.count


def parse_hex_lines(lines: Iterable[str], strict: bool = True) -> Iterable[bytes]:
    """Yield digests from text lines holding a SHA-256 in hex (comments ignored)."""
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = line.split()[0].split(",")[0].strip('"').lower()
        if len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            if strict:
                raise HashDBError(f"line {lineno}: not a SHA-256: {line[:80]!r}")
            continue
        yield bytes.fromhex(token)
