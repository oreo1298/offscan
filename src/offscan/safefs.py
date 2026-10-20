"""Safe access to a hostile directory tree.

Target filesystems are mounted ``nosymfollow``, so the kernel refuses to
follow *any* symlink there.  When we need to resolve a path inside the
target (``/etc/os-release -> ../usr/lib/os-release``, registry paths, cron
references), :class:`RootFS` does it component by component, treating the
mount point as ``/``.  Absolute links restart at the target root and ``..``
never climbs above it, the same semantics as ``openat2(RESOLVE_IN_ROOT)``,
so a path can never escape onto the host.

Only regular files are ever opened for reading; FIFOs, sockets and device
nodes are refused before any read.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator

O_PATH = getattr(os, "O_PATH", 0o10000000)
_DIR_FLAGS = O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
MAX_SYMLINKS = 40


class UnsafePath(OSError):
    """Raised when a path cannot be resolved safely inside the root."""


def _split(path: bytes) -> list[bytes]:
    return [part for part in path.split(b"/") if part and part != b"."]


class RootFS:
    """A directory treated as the root of an untrusted filesystem."""

    def __init__(self, root: str | bytes | os.PathLike[str], max_symlinks: int = MAX_SYMLINKS):
        self.root_path = os.fsencode(root)
        self.root_fd = os.open(self.root_path, _DIR_FLAGS)
        self.root_stat = os.fstat(self.root_fd)
        self.max_symlinks = max_symlinks

    def close(self) -> None:
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def __enter__(self) -> RootFS:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- resolution -------------------------------------------------------

    def resolve(self, path: str | bytes, follow_last: bool = True) -> tuple[int, bytes]:
        """Resolve ``path`` inside the root.

        Returns ``(parent_dir_fd, final_name)``; the caller owns
        ``parent_dir_fd`` and must close it.  ``final_name`` is ``b"."`` when
        the path names the root itself.  The final component need not exist.
        """
        fd, name, _ = self._walk(path, follow_last)
        return fd, name

    def realpath(self, path: str | bytes) -> bytes:
        """Canonical path as seen from inside the target (links resolved)."""
        fd, name, parts = self._walk(path, True)
        os.close(fd)
        if name != b".":
            parts.append(name)
        return b"/" + b"/".join(parts)

    def _walk(self, path: str | bytes, follow_last: bool) -> tuple[int, bytes, list[bytes]]:
        pending = _split(os.fsencode(path))
        stack: list[int] = []                    # fds of directories below root
        names: list[bytes] = []                  # their names, parallel to stack
        links = 0
        try:
            while pending:
                name = pending.pop(0)
                cur = stack[-1] if stack else self.root_fd
                if name == b"..":
                    if stack:
                        os.close(stack.pop())
                        names.pop()
                    continue
                is_last = not pending
                try:
                    st = os.stat(name, dir_fd=cur, follow_symlinks=False)
                except FileNotFoundError:
                    if is_last:
                        return os.dup(cur), name, names
                    raise
                if stat.S_ISLNK(st.st_mode) and (follow_last or not is_last):
                    links += 1
                    if links > self.max_symlinks:
                        raise UnsafePath(errno.ELOOP, "too many symbolic links", os.fsdecode(path))
                    target = os.readlink(name, dir_fd=cur)
                    if target.startswith(b"/"):
                        for fd in stack:
                            os.close(fd)
                        stack, names = [], []
                    pending = _split(target) + pending
                    continue
                if is_last:
                    return os.dup(cur), name, names
                if not stat.S_ISDIR(st.st_mode):
                    raise NotADirectoryError(errno.ENOTDIR, "not a directory", os.fsdecode(path))
                stack.append(os.open(name, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=cur))
                names.append(name)
            return os.dup(stack[-1] if stack else self.root_fd), b".", names
        finally:
            for fd in stack:
                os.close(fd)

    # -- queries ----------------------------------------------------------

    def lstat(self, path: str | bytes) -> os.stat_result:
        parent, name = self.resolve(path, follow_last=False)
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)

    def stat(self, path: str | bytes) -> os.stat_result:
        parent, name = self.resolve(path, follow_last=True)
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)

    def exists(self, path: str | bytes) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_dir(self, path: str | bytes) -> int:
        """Open a directory (following links inside the root); returns an O_RDONLY fd."""
        parent, name = self.resolve(path)
        try:
            return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent)
        finally:
            os.close(parent)

    def listdir(self, path: str | bytes = b"/") -> list[bytes]:
        fd = self.open_dir(path)
        try:
            # listdir(fd) returns str (surrogateescape); we work in bytes.
            return sorted(os.fsencode(name) for name in os.listdir(fd))
        finally:
            os.close(fd)

    def open_regular(self, path: str | bytes, follow_last: bool = True) -> int:
        """Open a regular file read-only; refuses anything else."""
        parent, name = self.resolve(path, follow_last=follow_last)
        try:
            return open_regular_at(parent, name)
        finally:
            os.close(parent)

    def read_file(self, path: str | bytes, max_size: int = 1 << 20) -> bytes:
        fd = self.open_regular(path)
        try:
            return read_limited(fd, max_size)
        finally:
            os.close(fd)

    def find_ci(self, path: str | bytes) -> bytes | None:
        """Case-insensitive lookup (for NTFS/FAT targets); returns the real path."""
        current = b""
        for part in _split(os.fsencode(path)):
            try:
                entries = self.listdir(current or b"/")
            except OSError:
                return None
            wanted = os.fsdecode(part).casefold()
            match = next((e for e in entries if os.fsdecode(e).casefold() == wanted), None)
            if match is None:
                return None
            current = current + b"/" + match
        return current or b"/"


def open_regular_at(dir_fd: int, name: bytes | str) -> int:
    """Open ``name`` in ``dir_fd`` only if it is a regular file (never follows links)."""
    fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePath(errno.EINVAL, "not a regular file", os.fsdecode(name))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_limited(fd: int, max_size: int) -> bytes:
    """Read at most ``max_size`` bytes from the start of ``fd``."""
    chunks: list[bytes] = []
    remaining = max_size
    offset = 0
    while remaining > 0:
        chunk = os.pread(fd, min(remaining, 1 << 20), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_regular_files(root: RootFS, path: bytes) -> Iterator[bytes]:
    """Non-recursive helper: names of regular files directly in ``path``."""
    fd = root.open_dir(path)
    try:
        with os.scandir(fd) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        yield os.fsencode(entry.name)
                except OSError:
                    continue
    finally:
        os.close(fd)
