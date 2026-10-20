"""Hand many small target files to the sandbox through one sealed memfd.

The helper (root) only *reads* target files here, bounded in size, through
:class:`~offscan.safefs.RootFS`; nothing is parsed.  The bytes are copied
into an anonymous memory file which is sealed against writes and passed to
the sandbox as a single descriptor together with a JSON index, so that a
target with thousands of cron, unit or task files does not need thousands
of open descriptors, and the sandbox can read files that only root may
open on the target (``/etc/shadow``, ``/var/spool/cron/crontabs/root``).
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from typing import Any

from .. import names
from ..safefs import RootFS, open_regular_at, read_limited

MAX_EACH = 1 << 20
MAX_TOTAL = 256 << 20
MAX_ENTRIES = 50_000


class Packer:
    def __init__(self, max_total: int = MAX_TOTAL, max_entries: int = MAX_ENTRIES):
        self.fd = os.memfd_create("pack", os.MFD_CLOEXEC | getattr(os, "MFD_ALLOW_SEALING", 2))
        self.offset = 0
        self.index: list[dict[str, Any]] = []
        self.max_total = max_total
        self.max_entries = max_entries
        self.seen: set[tuple[int, int]] = set()
        self.full = False

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _room(self) -> bool:
        if len(self.index) >= self.max_entries or self.offset >= self.max_total:
            self.full = True
            return False
        return True

    def add_fd(self, fd: int, path: bytes, kind: str, max_size: int = MAX_EACH,
               st: os.stat_result | None = None, **meta: Any) -> bool:
        if not self._room():
            return False
        st = st or os.fstat(fd)
        key = (st.st_dev, st.st_ino)
        entry: dict[str, Any] = {"file": names.to_wire(path), "kind": kind, "mode": st.st_mode,
                                 "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
                                 "mtime": int(st.st_mtime), **meta}
        if key in self.seen and st.st_nlink > 1:
            entry["hardlink"] = True
        self.seen.add(key)
        data = read_limited(fd, min(max_size, max(0, self.max_total - self.offset)))
        entry["offset"], entry["length"] = self.offset, len(data)
        entry["truncated"] = len(data) < st.st_size
        written = 0
        while written < len(data):
            written += os.pwrite(self.fd, data[written:], self.offset + written)
        self.offset += len(data)
        self.index.append(entry)
        return True

    def add(self, root: RootFS, path: bytes | str, kind: str, max_size: int = MAX_EACH,
            follow: bool = True, **meta: Any) -> bool:
        """Add one regular file (links followed inside the root unless ``follow`` is False)."""
        path = os.fsencode(path)
        try:
            fd = root.open_regular(path, follow_last=follow)
        except OSError:
            return False
        try:
            return self.add_fd(fd, path, kind, max_size, **meta)
        finally:
            os.close(fd)

    def add_link(self, path: bytes, target: bytes, kind: str, **meta: Any) -> None:
        if self._room():
            self.index.append({"file": names.to_wire(path), "kind": kind, "link": names.to_wire(target),
                               "offset": 0, "length": 0, **meta})

    def add_tree(self, root: RootFS, directory: bytes | str, kind: str, recursive: bool = False,
                 max_size: int = MAX_EACH, max_depth: int = 6, links: bool = False, **meta: Any) -> int:
        """Add the regular files in ``directory``; with ``links`` also record symlinks."""
        count = 0
        stack = [(os.fsencode(directory), 0)]
        visited: set[tuple[int, int]] = set()
        while stack and not self.full:
            current, depth = stack.pop()
            try:
                dfd = root.open_dir(current)
            except OSError:
                continue
            try:
                st = os.fstat(dfd)
                if (st.st_dev, st.st_ino) in visited:
                    continue
                visited.add((st.st_dev, st.st_ino))
                with os.scandir(dfd) as it:
                    listing = sorted(os.fsencode(e.name) for e in it)
                for name in listing:
                    path = current.rstrip(b"/") + b"/" + name
                    try:
                        est = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISLNK(est.st_mode):
                        if links:
                            try:
                                self.add_link(path, os.readlink(name, dir_fd=dfd), kind, **meta)
                            except OSError:
                                pass
                        continue
                    if stat.S_ISDIR(est.st_mode):
                        if recursive and depth < max_depth:
                            stack.append((path, depth + 1))
                        continue
                    if not stat.S_ISREG(est.st_mode):
                        continue
                    try:
                        fd = open_regular_at(dfd, name)
                    except OSError:
                        continue
                    try:
                        if self.add_fd(fd, path, kind, max_size, st=est, **meta):
                            count += 1
                    finally:
                        os.close(fd)
            finally:
                os.close(dfd)
        return count

    def finish(self) -> tuple[int, list[dict[str, Any]]]:
        """Seal the memfd; returns (fd, index).  The caller passes the fd on and closes it."""
        try:
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        except (OSError, AttributeError):
            pass
        return self.fd, self.index


def entries(fd: int, index: list[dict[str, Any]],
            kind: str | None = None) -> Iterator[tuple[dict[str, Any], bytes]]:
    """Sandbox side: iterate (entry, data) from a pack."""
    for entry in index:
        if kind is not None and entry.get("kind") != kind:
            continue
        length = int(entry.get("length", 0))
        data = os.pread(fd, length, int(entry.get("offset", 0))) if length else b""
        yield entry, data


def fd_path(fd: int, max_size: int = 2 << 30) -> tuple[str, int]:
    """Sandbox side: a path that libraries needing a file name can open.

    Re-opening ``/proc/self/fd/N`` repeats the permission check against the
    target file's owner and mode, which the unprivileged sandbox may fail.
    So the data is copied into a private memfd first.  Returns (path, memfd);
    close the memfd when done.
    """
    copy = os.memfd_create("copy", os.MFD_CLOEXEC)
    offset = 0
    while offset < max_size:
        chunk = os.pread(fd, min(8 << 20, max_size - offset), offset)
        if not chunk:
            break
        os.pwrite(copy, chunk, offset)
        offset += len(chunk)
    return f"/proc/self/fd/{copy}", copy
