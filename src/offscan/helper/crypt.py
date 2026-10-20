"""Unlock LUKS and BitLocker volumes read-only.

Every mapping is created on top of a read-only loop device and is itself
read-only (device-mapper does not inherit the read-only flag of the device
underneath).  ``--disable-locks`` keeps cryptsetup from running LUKS2
header auto-recovery, which would otherwise write a repaired header back.
Secrets are passed on stdin, never on the command line.
"""

from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import tempfile
import time

from .. import appinfo, tools
from . import blockdev

RECOVERY_KEY_RE = re.compile(r"^\d{6}(-\d{6}){7}$")


class UnlockError(Exception):
    pass


def mapper_name(kname: str) -> str:
    return f"{appinfo.DEVICE_PREFIX}crypt-{re.sub(r'[^A-Za-z0-9_.-]', '_', kname)}"


def normalize_recovery_key(text: str) -> str:
    digits = re.sub(r"[^0-9]", "", text)
    if len(digits) != 48:
        raise UnlockError("a BitLocker recovery key has 48 digits (8 groups of 6)")
    return "-".join(digits[i:i + 6] for i in range(0, 48, 6))


def _cryptsetup() -> str:
    return tools.require("cryptsetup")


def cryptsetup_open(source: str, name: str, kind: str, secret: bytes, readonly: bool = True) -> str:
    """Open ``source`` (normally a read-only loop) as /dev/mapper/<name>.

    ``readonly=False`` is used only for a confirmed quarantine/delete/restore.
    """
    ctype = {"luks": "luks", "bitlocker": "bitlk"}[kind]
    args = [_cryptsetup(), "open", "--type", ctype, *(["--readonly"] if readonly else []),
            "--disable-locks", "--key-file", "-", source, name]
    proc = tools.run(args, input=secret, timeout=180, check=False)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip()
        if proc.returncode == 2 or "No key available" in msg:
            raise UnlockError("wrong passphrase or key")
        raise UnlockError(msg or f"cryptsetup failed ({proc.returncode})")
    path = f"/dev/mapper/{name}"
    _wait_for(path)
    if readonly and not blockdev.get_ro(path):
        cryptsetup_close(name)
        raise UnlockError("the unlocked mapping is not read-only; closed it again")
    return path


def cryptsetup_close(name: str) -> None:
    for attempt in range(5):
        proc = tools.run([_cryptsetup(), "close", name], timeout=60, check=False)
        if proc.returncode == 0 or not os.path.exists(f"/dev/mapper/{name}"):
            return
        time.sleep(0.5 * (attempt + 1))
    raise UnlockError(f"could not close {name}: {proc.stderr.strip()}")


def luks_info(source: str) -> dict[str, str]:
    """Header summary (``isLuks``/``luksDump`` read the header only)."""
    proc = tools.run([_cryptsetup(), "luksDump", "--disable-locks", source], timeout=60,
                     check=False)
    info: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in ("Version", "UUID", "Label", "Cipher", "Cipher name"):
            info[key.strip().lower()] = value.strip()
    return info


def _wait_for(path: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise UnlockError(f"{path} did not appear")
        time.sleep(0.1)


# --- dislocker fallback (Vista-era or otherwise unsupported BitLocker) -----

def dislocker_open(source: str, workdir: str, secret: str, kind: str) -> str:
    """Expose a BitLocker volume through dislocker's FUSE file (read-only).

    The secret is typed into dislocker's own prompt through a pseudo
    terminal, so it never appears in the process list.
    """
    dislocker = tools.find("dislocker") or tools.find("dislocker-fuse")
    setsid = tools.find("setsid")
    if dislocker is None or setsid is None:
        raise UnlockError("dislocker is not installed")
    option = {"recovery_key": "-p", "password": "-u"}.get(kind)
    if option is None:
        raise UnlockError(f"dislocker cannot use a {kind}")
    os.makedirs(workdir, mode=0o700, exist_ok=True)
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            [setsid, "--ctty", "--wait", dislocker, "-r", "-V", source, option, "--", workdir],
            stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=tools.safe_env())
    finally:
        os.close(slave)
    target = os.path.join(workdir, "dislocker-file")
    output = b""
    sent = False
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline and not (sent and os.path.exists(target)):
            ready, _, _ = select.select([master], [], [], 0.5)
            if ready:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
                tail = output[-200:].lower()
                if not sent and (b"password" in tail or tail.rstrip().endswith(b":")):
                    os.write(master, secret.encode() + b"\n")
                    sent = True
            if proc.poll() is not None:
                break
    finally:
        os.close(master)
    if not os.path.exists(target):
        # The terminal may echo what was typed: never put the secret into the message.
        text = output.replace(secret.encode(), b"***").decode("utf-8", "replace").strip()[-300:]
        raise UnlockError("dislocker could not unlock the volume: " + text)
    return target


def dislocker_close(workdir: str) -> None:
    umount = tools.find("umount")
    if umount:
        tools.run([umount, workdir], timeout=60, check=False)
    try:
        os.rmdir(workdir)
    except OSError:
        pass


def secret_tempdir() -> str:
    return tempfile.mkdtemp(prefix=f"{appinfo.NAME}-dislocker-")
