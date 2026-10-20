"""Prepare the private runtime directory a scan's engines run from (client side).

Runs as the user who owns the definitions.  The directory is created under
``/tmp`` (one of the locations the distribution AppArmor profile allows
clamd to use), is mode 0700 and is owned by the *scan identity* (the user,
or ``nobody`` when the client itself is root).  It holds links or copies of
the active definition set plus clamd's configuration.  The root helper only
validates ownership and passes the path on; it never reads inside.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from .. import appinfo
from ..defs import layout
from . import clamd
from .options import ScanOptions


def _link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
        return
    except OSError:
        pass
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o644)


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
            base: str = "/tmp") -> Path:
    manifest = layout.load_manifest(set_dir)
    runtime = Path(tempfile.mkdtemp(prefix=f"{appinfo.NAME}-scan-", dir=base))
    try:
        os.chmod(runtime, 0o700)
        cdir = runtime / "clamav"
        cdir.mkdir(mode=0o755)
        for name in manifest["clamav"].get("files", []):
            _link_or_copy(set_dir / "clamav" / name, cdir / name)
        if manifest["clamav"].get("official") == "system":
            for path in layout.system_clamav_files(manifest["clamav"].get("system_dir")
                                                   or layout.SYSTEM_CLAMAV_DIR):
                if not (cdir / path.name).exists():
                    _symlink_or_copy(path, cdir / path.name)
        ydir = runtime / "yara"
        ydir.mkdir(mode=0o755)
        yfile = (manifest.get("yara") or {}).get("file")
        if yfile:
            _link_or_copy(set_dir / "yara" / yfile, ydir / yfile)
        hdir = runtime / "hashes"
        hdir.mkdir(mode=0o755)
        hashes = manifest.get("hashes") or {}
        for name in [*hashes.get("malware", []), hashes.get("known_good"), hashes.get("authentihash")]:
            if name:
                _link_or_copy(set_dir / "hashes" / name, hdir / name)
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


def cleanup(runtime: Path) -> None:
    if runtime.name.startswith(f"{appinfo.NAME}-scan-"):
        shutil.rmtree(runtime, ignore_errors=True)
