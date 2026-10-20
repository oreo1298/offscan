"""Walk a mounted target safely and hand out open file descriptors.

* Directory traversal uses directory fds (``openat``-style), never path
  strings, so renames and symlinks cannot redirect it.
* Symlinks are never followed; only regular files are opened (``O_NOFOLLOW |
  O_NONBLOCK``, then ``fstat``), so FIFOs, sockets and device nodes are never
  read.
* A (device, inode) set stops bind/hardlink loops; depth is limited.
* Filenames stay raw bytes; the protocol carries them losslessly.
"""

from __future__ import annotations

import errno
import os
import stat
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ..safefs import O_PATH, RootFS, open_regular_at
from . import selection

MAX_DEPTH = 128
MAX_SETID = 20_000
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass
class FileItem:
    relpath: bytes            # "/"-prefixed, relative to the volume root
    fd: int
    size: int
    mtime: float
    uid: int


@dataclass
class WalkStats:
    dirs: int = 0
    files: int = 0
    bytes: int = 0
    skipped_special: int = 0
    symlinks: int = 0
    errors: list[tuple[bytes, str]] = field(default_factory=list)
    error_count: int = 0
    setid: list[dict] = field(default_factory=list)      # SUID/SGID files seen (for integrity checks)

    def error(self, path: bytes, message: str) -> None:
        self.error_count += 1
        if len(self.errors) < 200:
            self.errors.append((path, message))


def _join(parent: bytes, name: bytes) -> bytes:
    return (parent.rstrip(b"/") + b"/" + name) if parent != b"/" else b"/" + name


def walk(root: RootFS, start: bytes = b"/", mode: str = "full",
         stop: threading.Event | None = None,
         stats: WalkStats | None = None,
         open_files: bool = True) -> Iterator[FileItem]:
    """Yield regular files below ``start`` (a path inside the target)."""
    stats = stats if stats is not None else WalkStats()
    stop = stop or threading.Event()
    try:
        parent, name = root.resolve(start)
    except OSError as exc:
        stats.error(start, exc.strerror or str(exc))
        return
    try:
        st = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        os.close(parent)
        stats.error(start, exc.strerror or str(exc))
        return
    canonical = root.realpath(start)
    if stat.S_ISREG(st.st_mode):
        try:
            if open_files:
                fd = open_regular_at(parent, name)
                yield FileItem(canonical, fd, st.st_size, st.st_mtime, st.st_uid)
            else:
                yield FileItem(canonical, -1, st.st_size, st.st_mtime, st.st_uid)
        except OSError as exc:
            stats.error(canonical, exc.strerror or str(exc))
        finally:
            os.close(parent)
        return
    if not stat.S_ISDIR(st.st_mode):
        os.close(parent)
        return
    try:
        top = os.open(name, _DIR_FLAGS, dir_fd=parent)
    except OSError as exc:
        stats.error(canonical, exc.strerror or str(exc))
        return
    finally:
        os.close(parent)
    yield from _walk_dir(top, canonical, 0, mode, stop, stats, set(), open_files)


def _walk_dir(dir_fd: int, relpath: bytes, depth: int, mode: str, stop: threading.Event,
              stats: WalkStats, seen: set[tuple[int, int]], open_files: bool) -> Iterator[FileItem]:
    try:
        st = os.fstat(dir_fd)
        key = (st.st_dev, st.st_ino)
        if key in seen:
            return
        seen.add(key)
        stats.dirs += 1
        try:
            with os.scandir(dir_fd) as it:
                entries = list(it)
        except OSError as exc:
            stats.error(relpath, exc.strerror or str(exc))
            return
        subdirs: list[bytes] = []
        for entry in entries:
            if stop.is_set():
                return
            name = os.fsencode(entry.name)
            child = _join(relpath, name)
            try:
                est = entry.stat(follow_symlinks=False)
            except OSError as exc:
                stats.error(child, exc.strerror or str(exc))
                continue
            mode_bits = est.st_mode
            if stat.S_ISLNK(mode_bits):
                stats.symlinks += 1
                continue
            if stat.S_ISDIR(mode_bits):
                subdirs.append(name)
                continue
            if not stat.S_ISREG(mode_bits):
                stats.skipped_special += 1
                continue
            stats.files += 1
            stats.bytes += est.st_size
            if mode_bits & (stat.S_ISUID | stat.S_ISGID) and len(stats.setid) < MAX_SETID:
                stats.setid.append({"path": child, "mode": mode_bits, "uid": est.st_uid})
            if not open_files:
                yield FileItem(child, -1, est.st_size, est.st_mtime, est.st_uid)
                continue
            try:
                fd = open_regular_at(dir_fd, name)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    stats.error(child, exc.strerror or str(exc))
                continue
            yield FileItem(child, fd, est.st_size, est.st_mtime, est.st_uid)
        if depth >= MAX_DEPTH:
            if subdirs:
                stats.error(relpath, "directory nesting too deep; not descending further")
            return
        for name in subdirs:
            if stop.is_set():
                return
            child = _join(relpath, name)
            if selection.prune(os.fsdecode(child), mode):
                continue
            try:
                sub = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            except OSError as exc:
                stats.error(child, exc.strerror or str(exc))
                continue
            yield from _walk_dir(sub, child, depth + 1, mode, stop, stats, seen, open_files)
    finally:
        os.close(dir_fd)


def estimate(root: RootFS, starts: list[bytes], mode: str, stop: threading.Event,
             progress: Callable[[int, int], None] | None = None) -> tuple[int, int]:
    """Count files and bytes the scan will look at (metadata only)."""
    files = size = 0
    stats = WalkStats()
    for start in starts:
        for item in walk(root, start, mode, stop, stats, open_files=False):
            if mode == "quick" and not selection.interesting_by_name(os.fsdecode(item.relpath)):
                continue
            files += 1
            size += item.size
            if progress and files % 2000 == 0:
                progress(files, size)
    return files, size


__all__ = ["O_PATH", "FileItem", "WalkStats", "estimate", "walk"]
