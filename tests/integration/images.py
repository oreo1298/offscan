"""Build loopback disk images for integration tests (needs root).

No real malware is used.  ``eicar()`` assembles the standard EICAR antivirus
test string at run time so the repository itself never contains it.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def eicar() -> bytes:
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]
    return "".join(parts).encode("ascii")


def run(*args: str, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), input=input, capture_output=True, env=ENV, check=check)


def have(*tools: str) -> bool:
    return all(shutil.which(t, path=ENV["PATH"]) for t in tools)


def kernel_fs(name: str) -> bool:
    with open("/proc/filesystems") as fh:
        return any(line.split()[-1] == name for line in fh)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@contextlib.contextmanager
def attached(image: Path, partscan: bool = False, readonly: bool = False) -> Iterator[str]:
    args = ["losetup", "--find", "--show"]
    if partscan:
        args.append("--partscan")
    if readonly:
        args.append("--read-only")
    dev = run(*args, str(image)).stdout.decode().strip()
    if not readonly:
        # The kernel's read-only flag is sticky across detach; a crashed
        # earlier run must not leave the next fixture read-only.
        run("blockdev", "--setrw", dev, check=False)
    try:
        if partscan:
            for _ in range(50):
                if os.path.exists(dev + "p1"):
                    break
                # Some containers do not scan at attach time; ask explicitly.
                run("partx", "--add", dev, check=False)
                time.sleep(0.1)
        yield dev
    finally:
        for _ in range(10):
            if run("losetup", "--detach", dev, check=False).returncode == 0:
                break
            time.sleep(0.3)


@contextlib.contextmanager
def mounted(dev: str, fstype: str | None = None, options: str = "") -> Iterator[Path]:
    mnt = Path(tempfile.mkdtemp(prefix="fixture-mnt-"))
    if fstype == "ntfs-3g":
        run("ntfs-3g", dev, str(mnt))
    else:
        args = ["mount"]
        if fstype:
            args += ["-t", fstype]
        if options:
            args += ["-o", options]
        run(*args, dev, str(mnt))
    try:
        yield mnt
    finally:
        run("sync")
        for _ in range(10):
            if run("umount", str(mnt), check=False).returncode == 0:
                break
            time.sleep(0.3)
        mnt.rmdir()


def populate_linux(root: Path, distro: str = "Fixture Linux 1.0") -> None:
    (root / "etc").mkdir(exist_ok=True)
    (root / "usr/lib").mkdir(parents=True, exist_ok=True)
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (root / "usr/lib/os-release").write_text(
        f'NAME="Fixture Linux"\nPRETTY_NAME="{distro}"\nVERSION_ID="1.0"\nID=fixture\n')
    os.symlink("../usr/lib/os-release", root / "etc/os-release")
    (root / "etc/fstab").write_text("# fixture\n")
    (root / "home/user").mkdir(parents=True)
    (root / "home/user/eicar.com").write_bytes(eicar())
    os.symlink("/etc/shadow", root / "home/user/escape-link")


def populate_windows(root: Path, hibernated: bool) -> None:
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"not a real hive")
    (root / "Users" / "Alice" / "Downloads").mkdir(parents=True)
    (root / "Users" / "Alice" / "Downloads" / "eicar.com").write_bytes(eicar())
    header = b"HIBR" if hibernated else b"\0\0\0\0"
    (root / "hiberfil.sys").write_bytes(header + b"\0" * (64 * 1024 - 4))


def make_disk(path: Path, size_mb: int, layout: list[tuple[str, int]]) -> None:
    """Create a GPT disk image; ``layout`` is [(gpt type code, size MiB or 0=rest)]."""
    with open(path, "wb") as fh:
        fh.truncate(size_mb << 20)
    script = "label: gpt\n" + "".join(
        f",{f'{size}MiB' if size else ''},{ptype}\n" for ptype, size in layout)
    run("sfdisk", "--quiet", str(path), input=script.encode())


def dirty_copy(dev: str, image: Path, out: Path, fstype: str, populate) -> None:
    """Mount ``dev`` read-write, write files, then copy ``image`` while still mounted.

    The copy has an unreplayed journal/log (and an orphan inode for ext4),
    exactly like a disk pulled from a machine that lost power.
    """
    with mounted(dev, fstype) as mnt:
        populate(mnt)
        held = open(mnt / "orphan.tmp", "wb")
        held.write(b"x" * 4096)
        held.flush()
        os.unlink(mnt / "orphan.tmp")
        run("sync")
        time.sleep(0.5)
        run("cp", "--sparse=always", str(image), str(out))
        held.close()
