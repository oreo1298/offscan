"""Prepare the private runtime directory a scan's engines run from.

The root helper builds it for every scan from the definition set the client
names, so the client chooses neither the engines' configuration nor their
socket. It lives under ``/tmp`` (one of the locations the distribution
AppArmor profile allows clamd to use), is mode 0700 and belongs to the *scan
identity* (the dedicated scan account). It holds links to, or copies of, the
active definition set plus clamd's configuration.

The definition set belongs to the user. When ``owner_uid`` is given (the
helper, running as root), every file is opened relative to the set's
directory without following links, must be a regular file owned by that
user, and must have a plain name: a client cannot make root copy a file the
user could not read.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from pathlib import Path

from .. import appinfo
from ..defs import layout
from . import clamd
from .options import ScanOptions


class RuntimeSetupError(Exception):
    """The definition set cannot be used (unsafe name, wrong owner, not a regular file)."""


def _plain_name(name: object) -> str:
    if not isinstance(name, str) or not name or "/" in name or "\0" in name or name in (".", "..") \
            or len(name) > 255:
        raise RuntimeSetupError(f"unsafe file name in the definition set: {str(name)[:80]!r}")
    return name


def _open_in(dirfd: int, name: str, owner_uid: int | None, directory: bool = False) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    try:
        fd = os.open(_plain_name(name), flags, dir_fd=dirfd)
    except OSError as exc:
        raise RuntimeSetupError(f"cannot open {name} in the definition set: {exc.strerror}") from exc
    st = os.fstat(fd)
    ok = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not ok or (owner_uid is not None and st.st_uid != owner_uid):
        os.close(fd)
        raise RuntimeSetupError(f"{name} in the definition set is not a "
                            f"{'directory' if directory else 'regular file'} of its owner")
    return fd


def _place(src_fd: int, dst: Path) -> None:
    """Hard-link the opened file (cheap) when others may read it, else copy it."""
    st = os.fstat(src_fd)
    if st.st_mode & 0o004:
        try:
            os.link(f"/proc/self/fd/{src_fd}", dst, follow_symlinks=True)
            return
        except OSError:
            pass
    out = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        offset = 0
        while True:
            sent = os.sendfile(out, src_fd, offset, 8 << 20)
            if sent == 0:
                break
            offset += sent
    finally:
        os.close(out)


def _symlink_or_copy(src: Path, dst: Path) -> None:
    """For world-readable system files (e.g. /var/lib/clamav) a symlink suffices."""
    try:
        if os.access(src, os.R_OK) and (src.stat().st_mode & 0o004):
            os.symlink(src, dst)
            return
    except OSError:
        pass
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o644)


def prepare(set_dir: Path, options: ScanOptions, scan_uid: int, scan_gid: int,
            base: str = "/tmp", owner_uid: int | None = None) -> Path:
    set_fd = os.open(set_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    runtime = Path(tempfile.mkdtemp(prefix=f"{appinfo.NAME}-scan-", dir=base))
    try:
        st = os.fstat(set_fd)
        if owner_uid is not None and st.st_uid != owner_uid:
            raise RuntimeSetupError("the definition set does not belong to the user who started the scan")
        manifest_fd = _open_in(set_fd, layout.MANIFEST, owner_uid)
        with os.fdopen(manifest_fd, "rb") as fh:
            manifest = json.loads(fh.read(64 << 20))
        os.chmod(runtime, 0o700)

        def copy_group(subdir: str, wanted: list[str], target: Path) -> None:
            target.mkdir(mode=0o755)
            if not wanted:
                return
            dir_fd = _open_in(set_fd, subdir, owner_uid, directory=True)
            try:
                for name in wanted:
                    fd = _open_in(dir_fd, name, owner_uid)
                    try:
                        _place(fd, target / name)
                    finally:
                        os.close(fd)
            finally:
                os.close(dir_fd)

        cdir = runtime / "clamav"
        copy_group("clamav", list(manifest["clamav"].get("files", [])), cdir)
        if manifest["clamav"].get("official") == "system":
            # Only the distribution's own database directory, whatever the manifest says.
            for path in layout.system_clamav_files(layout.SYSTEM_CLAMAV_DIR):
                if not (cdir / path.name).exists():
                    _symlink_or_copy(path, cdir / path.name)
        yfile = (manifest.get("yara") or {}).get("file")
        copy_group("yara", [yfile] if yfile else [], runtime / "yara")
        hashes = manifest.get("hashes") or {}
        names = [n for n in [*hashes.get("malware", []), hashes.get("known_good"), hashes.get("authentihash")]
                 if n]
        copy_group("hashes", names, runtime / "hashes")
        (runtime / layout.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        has_clamav = any(cdir.iterdir())
        if not has_clamav:
            cdir.rmdir()
        else:
            clamd.write_config(runtime, options.limits, options.worker_count(), options.detect_pua)
        if scan_uid != os.geteuid():
            for root, dirs, files in os.walk(runtime):
                os.lchown(root, scan_uid, scan_gid)
                for name in dirs + files:
                    path = os.path.join(root, name)
                    st = os.lstat(path)
                    if st.st_nlink == 1:          # our own copies, not hard links to definitions
                        os.lchown(path, scan_uid, scan_gid)
        return runtime
    except BaseException:
        shutil.rmtree(runtime, ignore_errors=True)
        raise
    finally:
        os.close(set_fd)


def cleanup(runtime: Path) -> None:
    if runtime.name.startswith(f"{appinfo.NAME}-scan-"):
        shutil.rmtree(runtime, ignore_errors=True)
