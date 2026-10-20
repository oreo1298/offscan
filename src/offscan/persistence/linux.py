"""Linux persistence: collection (helper, root) and analysis (sandbox, unprivileged).

The helper copies the relevant configuration files (cron, systemd, shell
start-up files, SSH, PAM, sudo, udev, package-manager hooks, ...) into one
sealed memfd with :class:`~offscan.persistence.filepack.Packer` and lists a
few directories by name.  The sandbox task :func:`task_persistence` does all
the parsing.  Paths are relative to the installation's root directory.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import stat
from typing import Any

from .. import names
from ..safefs import RootFS
from . import Finding, filepack, heuristics

# ----------------------------------------------------------------- collection

SYSTEM_FILES: list[tuple[str, str]] = [
    ("cron", "/etc/crontab"), ("anacron", "/etc/anacrontab"),
    ("rc_local", "/etc/rc.local"), ("rc_local", "/etc/rc.d/rc.local"),
    ("preload", "/etc/ld.so.preload"), ("ldconf", "/etc/ld.so.conf"),
    ("passwd", "/etc/passwd"), ("shadow", "/etc/shadow"), ("group", "/etc/group"),
    ("sudoers", "/etc/sudoers"), ("sshd", "/etc/ssh/sshd_config"),
    ("grub", "/etc/default/grub"), ("grub_cfg", "/boot/grub/grub.cfg"), ("grub_cfg", "/boot/grub2/grub.cfg"),
    *(("shellrc", p) for p in ("/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
                               "/etc/zsh/zprofile", "/etc/zsh/zshenv", "/etc/zsh/zlogin", "/etc/zshrc",
                               "/etc/zprofile", "/etc/zshenv", "/etc/environment", "/etc/fish/config.fish",
                               "/etc/csh.cshrc", "/etc/csh.login", "/etc/X11/Xsession")),
]

# (kind, directory, recursive, record symlinks, max bytes per file)
SYSTEM_DIRS: list[tuple[str, str, bool, bool, int]] = [
    ("cron", "/etc/cron.d", False, False, filepack.MAX_EACH),
    *(("cron_script", f"/etc/cron.{p}", False, False, filepack.MAX_EACH)
      for p in ("hourly", "daily", "weekly", "monthly")),
    ("crontab", "/var/spool/cron/crontabs", False, False, filepack.MAX_EACH),
    ("crontab", "/var/spool/cron", False, False, filepack.MAX_EACH),
    ("crontab", "/var/spool/cron/tabs", False, False, filepack.MAX_EACH),          # openSUSE
    ("at", "/var/spool/cron/atjobs", False, False, filepack.MAX_EACH),
    ("at", "/var/spool/at", False, False, filepack.MAX_EACH),
    ("shellrc", "/etc/profile.d", False, False, filepack.MAX_EACH),
    ("sudoers", "/etc/sudoers.d", False, False, filepack.MAX_EACH),
    ("sshd", "/etc/ssh/sshd_config.d", False, False, filepack.MAX_EACH),
    ("pam", "/etc/pam.d", False, False, filepack.MAX_EACH),
    ("pam", "/usr/lib/pam.d", False, False, filepack.MAX_EACH),
    ("udev", "/etc/udev/rules.d", False, False, filepack.MAX_EACH),
    ("udev_vendor", "/usr/lib/udev/rules.d", False, False, filepack.MAX_EACH),
    ("udev_vendor", "/lib/udev/rules.d", False, False, filepack.MAX_EACH),
    ("script", "/etc/update-motd.d", False, False, filepack.MAX_EACH),
    ("script", "/etc/NetworkManager/dispatcher.d", True, False, filepack.MAX_EACH),
    ("script", "/etc/init.d", False, False, filepack.MAX_EACH),
    ("script", "/etc/X11/Xsession.d", False, False, filepack.MAX_EACH),
    ("apt_hook", "/etc/apt/apt.conf.d", False, False, filepack.MAX_EACH),
    ("pacman_hook", "/etc/pacman.d/hooks", False, False, filepack.MAX_EACH),
    ("pacman_hook_vendor", "/usr/share/libalpm/hooks", False, False, filepack.MAX_EACH),
    ("modprobe", "/etc/modprobe.d", False, False, filepack.MAX_EACH),
    ("modprobe", "/usr/lib/modprobe.d", False, False, filepack.MAX_EACH),
    ("polkit", "/etc/polkit-1/rules.d", False, False, filepack.MAX_EACH),
    ("polkit_vendor", "/usr/share/polkit-1/rules.d", False, False, filepack.MAX_EACH),
    ("xdg_autostart", "/etc/xdg/autostart", False, False, filepack.MAX_EACH),
    ("ldconf", "/etc/ld.so.conf.d", False, False, filepack.MAX_EACH),
    ("systemd", "/etc/systemd/system", True, True, filepack.MAX_EACH),
    ("systemd", "/usr/local/lib/systemd/system", True, True, filepack.MAX_EACH),
    ("systemd_vendor", "/usr/lib/systemd/system", True, True, filepack.MAX_EACH),
    ("systemd_vendor", "/lib/systemd/system", True, True, filepack.MAX_EACH),
    ("systemd_user", "/etc/systemd/user", True, True, filepack.MAX_EACH),
    ("systemd_user_vendor", "/usr/lib/systemd/user", True, True, filepack.MAX_EACH),
    ("dbus_vendor", "/usr/share/dbus-1/system-services", False, False, filepack.MAX_EACH),
    ("dbus_vendor", "/usr/share/dbus-1/services", False, False, filepack.MAX_EACH),
    ("dbus", "/usr/local/share/dbus-1/system-services", False, False, filepack.MAX_EACH),
    ("initramfs", "/etc/initramfs-tools/hooks", False, False, filepack.MAX_EACH),
    ("initramfs", "/etc/initramfs-tools/scripts", True, False, filepack.MAX_EACH),
    ("generator", "/etc/systemd/system-generators", False, True, 0),
    ("generator", "/usr/local/lib/systemd/system-generators", False, True, 0),
    ("generator", "/etc/systemd/user-generators", False, True, 0),
]

USER_FILES: list[tuple[str, str]] = [
    *(("user_shellrc", p) for p in (".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
                                    ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
                                    ".config/fish/config.fish", ".xprofile", ".xinitrc", ".xsessionrc",
                                    ".xsession", ".pam_environment", ".cshrc", ".tcshrc", ".login")),
    ("authorized_keys", ".ssh/authorized_keys"), ("authorized_keys", ".ssh/authorized_keys2"),
    ("ssh_rc", ".ssh/rc"), ("ssh_environment", ".ssh/environment"),
]
USER_DIRS: list[tuple[str, str, bool, bool]] = [
    ("user_autostart", ".config/autostart", False, False),
    ("user_shellrc", ".bashrc.d", False, False),
    ("user_shellrc", ".config/plasma-workspace/env", False, False),
    ("user_shellrc", ".config/autostart-scripts", False, False),
    ("user_shellrc", ".config/environment.d", False, False),
    ("systemd_user", ".config/systemd/user", True, True),
    ("systemd_user", ".local/share/systemd/user", True, True),
    ("dbus", ".local/share/dbus-1/services", False, False),
]

TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
ODD_NAME_DIRS = ("/", "/dev", "/tmp", "/var/tmp", "/dev/shm", "/usr", "/usr/lib", "/usr/bin", "/usr/sbin",
                 "/usr/share", "/lib", "/etc", "/var", "/var/lib", "/var/log", "/root", "/bin", "/sbin",
                 "/opt", "/srv", "/boot", "/home")
LOGIN_SHELL_RE = re.compile(rb"^(?!.*(nologin|false|sync|shutdown|halt)$)/\S+$")


def _users_from_passwd(root: RootFS) -> list[dict[str, Any]]:
    """Home directories from /etc/passwd.

    Only a ``split(b":")`` happens here (in the helper); everything else
    about the file is analysed in the sandbox.
    """
    out: list[dict[str, Any]] = []
    try:
        data = root.read_file("/etc/passwd", 4 << 20)
    except OSError:
        return out
    for line in data.split(b"\n")[:20000]:
        fields = line.split(b":")
        if len(fields) != 7 or not fields[0] or not fields[5].startswith(b"/") or b"\0" in fields[5]:
            continue
        try:
            uid = int(fields[2])
        except ValueError:
            continue
        out.append({"name": fields[0][:64], "uid": uid, "home": fields[5][:1024],
                    "login": bool(LOGIN_SHELL_RE.match(fields[6]))})
    return out


def find_homes(root: RootFS, home_volume: bool = False) -> list[dict[str, Any]]:
    """Users and their homes; on a separate /home volume, each top-level directory."""
    users: list[dict[str, Any]] = [] if home_volume else _users_from_passwd(root)
    known = {u["home"] for u in users}
    base = b"/" if home_volume else b"/home"
    try:
        for name in root.listdir(base):
            home = base.rstrip(b"/") + b"/" + name
            if home not in known and stat.S_ISDIR(root.lstat(home).st_mode):
                users.append({"name": name[:64], "uid": None, "home": home, "login": True})
    except OSError:
        pass
    if not home_volume and b"/root" not in known:
        users.append({"name": b"root", "uid": 0, "home": b"/root", "login": True})
    return users


def looks_like_home_volume(root: RootFS) -> bool:
    try:
        entries = root.listdir(b"/")[:200]
    except OSError:
        return False
    for name in entries:
        for marker in (b"/.bashrc", b"/.profile", b"/.config", b"/.local", b"/.cache"):
            if root.exists(b"/" + name + marker):
                return True
    return False


def collect(root: RootFS, home_volume: bool = False) -> tuple[dict[str, Any], list[int]]:
    """Gather the files the analysis needs; returns (args, fds) for the sandbox."""
    pack = filepack.Packer()
    seen_dirs: set[bytes] = set()

    def tree(kind: str, directory: bytes, recursive: bool, links: bool, max_size: int, **meta: Any) -> None:
        try:
            real = root.realpath(directory)
            if real in seen_dirs or not stat.S_ISDIR(root.stat(directory).st_mode):
                return
        except OSError:
            return
        seen_dirs.add(real)
        pack.add_tree(root, real, kind, recursive=recursive, max_size=max_size, links=links, **meta)

    users = find_homes(root, home_volume)
    try:
        if not home_volume:
            for kind, path in SYSTEM_FILES:
                pack.add(root, path, kind)
            for kind, directory, recursive, links, max_size in SYSTEM_DIRS:
                tree(kind, os.fsencode(directory), recursive, links, max_size)
        homes_done: set[bytes] = set()
        for user in users:
            home = user["home"]
            if home in (b"/", b"/nonexistent") or home in homes_done:
                continue
            homes_done.add(home)
            meta = {"user": names.to_wire(user["name"]), "home": names.to_wire(home)}
            for kind, rel in USER_FILES:
                pack.add(root, home + b"/" + os.fsencode(rel), kind, **meta)
            for kind, rel, recursive, links in USER_DIRS:
                tree(kind, home + b"/" + os.fsencode(rel), recursive, links, filepack.MAX_EACH, **meta)
        fd, index = pack.finish()
        args: dict[str, Any] = {
            "pack": 0, "index": index, "truncated": pack.full, "home_volume": home_volume,
            "users": [{"name": names.to_wire(u["name"]), "uid": u["uid"], "home": names.to_wire(u["home"]),
                       "login": u["login"]} for u in users],
            "odd": [] if home_volume else _odd_names(root),
            "temp_exec": [] if home_volume else _temp_executables(root),
        }
        return args, [os.dup(fd)]
    finally:
        pack.close()


def _odd_names(root: RootFS) -> list[dict[str, Any]]:
    """Names that hide well in a listing ('...', '.. ', ' ') and regular files in /dev."""
    out: list[dict[str, Any]] = []
    for directory in ODD_NAME_DIRS:
        try:
            entries = root.listdir(directory)
        except OSError:
            continue
        for name in entries:
            path = directory.rstrip("/").encode() + b"/" + name
            odd = (re.fullmatch(rb"[. ]+", name) is not None and name not in (b".", b"..")) \
                or re.search(rb"[\x00-\x1f\x7f]", name) is not None or name.endswith(b" ")
            regular_in_dev = False
            if directory == "/dev":
                try:
                    regular_in_dev = stat.S_ISREG(root.lstat(path).st_mode)
                except OSError:
                    pass
            if odd or regular_in_dev:
                try:
                    mode = root.lstat(path).st_mode
                except OSError:
                    continue
                out.append({"file": names.to_wire(path), "mode": mode, "odd": odd, "dev": regular_in_dev})
            if len(out) >= 500:
                return out
    return out


def _temp_executables(root: RootFS) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for directory in TEMP_DIRS:
        stack = [(directory.encode(), 0)]
        while stack and len(out) < 500:
            current, depth = stack.pop()
            try:
                entries = root.listdir(current)
            except OSError:
                continue
            for name in entries[:5000]:
                path = current + b"/" + name
                try:
                    st = root.lstat(path)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and depth < 2:
                    stack.append((path, depth + 1))
                elif stat.S_ISREG(st.st_mode):
                    try:
                        head = root.read_file(path, 4)
                    except OSError:
                        head = b""
                    if st.st_mode & 0o111 or head == b"\x7fELF":
                        out.append({"file": names.to_wire(path), "mode": st.st_mode, "size": st.st_size,
                                    "elf": head == b"\x7fELF", "uid": st.st_uid})
    return out


# ------------------------------------------------------------------- analysis

SHELL_RULES: list[tuple[re.Pattern[str], str, str]] = [(re.compile(p), why, sev) for p, why, sev in (
    (r"^\s*alias\s+(sudo|su|ssh|passwd|doas)=", "redefines a security-sensitive command", "medium"),
    (r"\btrap\b[^\n]*\bDEBUG\b", "runs a command before every shell command", "low"),
    (r"^\s*(export\s+)?PROMPT_COMMAND=", "runs a command at every prompt", "info"),
)]
NOLOGIN = ("nologin", "false", "sync", "shutdown", "halt")
SERVICE_USERS = {"nobody", "www-data", "apache", "nginx", "daemon", "http", "mysql", "postgres", "ftp",
                 "games", "mail", "news", "lp", "bin", "sys", "uucp", "proxy", "backup", "list", "irc"}
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
             "ExecCondition")
APT_HOOK_RE = re.compile(
    r"(?P<name>APT::Update::(?:Pre|Post)-Invoke(?:-Success)?|DPkg::(?:Pre|Post)-Invoke|DPkg::Pre-Install-Pkgs|"
    r"APT::Install::(?:Pre|Post)-Invoke)\s*(?:::\s*)?"
    r'(?:\{(?P<block>(?:"(?:[^"\\]|\\.)*"|[^}"])*)\}|(?P<single>"(?:[^"\\]|\\.)*"))', re.IGNORECASE)
SYSTEM_DIRS_EXEC = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/etc/", "/snap/", "/nix/")


class _Ctx:
    def __init__(self, users: list[dict[str, Any]]):
        self.findings: list[Finding] = []
        self.targets: set[str] = set()
        self.errors: list[str] = []
        self.info: dict[str, Any] = {}
        self.users = {u["name"]: u for u in users}

    def add(self, finding: Finding, report_info: bool = True) -> None:
        if finding.target:
            self.targets.add(finding.target)
        if report_info or finding.severity != "info":
            self.findings.append(finding)

    def command(self, check: str, title: str, location: str, command: str, file: str, mitre: str | None,
                user: str | None = None, base: str = "info", reason: str | None = None,
                report_info: bool = True, system: bool = True) -> None:
        severity, reasons = heuristics.assess_linux(command)
        severity = heuristics.higher(severity, base)
        target = command_target(command)
        if system and target and target.startswith(("/home/", "/root/")):
            severity = heuristics.higher(severity, "medium")
            reasons.append("a system-wide entry runs a program from a home directory")
        if reason:
            reasons.insert(0, reason)
        self.add(Finding(check, title, location, command[:2000], severity, reasons, file, target, user,
                         mitre), report_info)


WRAPPERS = {"sudo", "nohup", "setsid", "exec", "env", "nice", "ionice", "timeout", "flock", "chronic",
            "run-parts", "test", "[", "doas", "su", "runuser", "systemd-run", "stdbuf", "chrt", "taskset"}
INTERPRETER_RE = re.compile(r"(^|/)(python[\d.]*|perl|ruby|node|php[\d.]*|bash|sh|dash|zsh|ksh|lua[\d.]*)$")


def command_target(command: str) -> str | None:
    """Program (or interpreted script) that a shell command line starts, if it is an absolute path."""
    try:
        words = shlex.split(command, comments=False, posix=True)
    except ValueError:
        words = command.split()
    program = None
    wrapped = False
    for word in words[:20]:
        if "=" in word and not word.startswith("/") and word.split("=", 1)[0].isidentifier():
            continue
        if word.startswith("-") and not word.startswith("-/"):
            continue                                        # an option (of a wrapper)
        word = word.lstrip("@-:+!|")
        if not word or os.path.basename(word) in WRAPPERS:
            wrapped = wrapped or bool(word)
            continue
        if wrapped and program is None and re.fullmatch(r"[\d.]+[smhd]?", word):
            continue                                        # e.g. nice -n 5, timeout 30s
        if program is None:
            if INTERPRETER_RE.search(word):
                program = word                      # look for the script it runs
                continue
            return os.path.normpath(word)[:1024] if word.startswith("/") and len(word) > 1 else None
        if word.startswith("/") and len(word) > 1:
            return os.path.normpath(word)[:1024]
        if not word.startswith("-"):
            break
    return os.path.normpath(program)[:1024] if program and program.startswith("/") else None


def _lines(data: bytes) -> list[tuple[int, str]]:
    out = []
    for number, raw in enumerate(data.decode("utf-8", "replace").splitlines()[:20000], 1):
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append((number, line))
    return out


def _unsafe_owner(entry: dict[str, Any]) -> bool:
    """World-writable, or (for system-wide files) not owned by root."""
    mode = int(entry.get("mode", 0))
    if entry.get("kind") == "crontab":           # per-user crontabs belong to their user
        return bool(mode & 0o002)
    return bool(mode & 0o002) or entry.get("uid") not in (0, None)


ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


def analyze_cron(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    file, kind = entry["file"], entry["kind"]
    if _unsafe_owner(entry):
        mode = oct(int(entry.get("mode", 0)))
        ctx.add(Finding("linux.cron", "Cron file writable by other users", file, mode, "high",
                        ["a non-root user could add commands that run as root"], file, None, None,
                        "T1053.003"))
    owner = file.rsplit("/", 1)[-1] if kind == "crontab" else None
    for number, line in _lines(data):
        if ENV_ASSIGN.match(line):
            continue
        if kind == "anacron":
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            user, command, when = "root", parts[3], f"every {parts[0]} days"
        elif line.startswith("@"):
            parts = line.split(None, 1 if owner else 2)
            if len(parts) < (2 if owner else 3):
                continue
            when = parts[0]
            user, command = (owner, parts[1]) if owner else (parts[1], parts[2])
        else:
            parts = line.split(None, 5 if owner else 6)
            if len(parts) < (6 if owner else 7):
                continue
            when = " ".join(parts[:5])
            user, command = (owner, parts[5]) if owner else (parts[5], parts[6])
        reason = "runs at every boot" if when == "@reboot" else None
        ctx.command("linux.cron", f"Scheduled command ({user})", f"{file}:{number}", command, file,
                    "T1053.003", user=user, reason=reason, system=owner is None)


def analyze_script(entry: dict[str, Any], data: bytes, ctx: _Ctx, check: str, label: str,
                   mitre: str | None, rules: list | None = None) -> None:
    """Report only the suspicious lines of a script (start-up files, cron scripts, hooks)."""
    file = entry["file"]
    user = entry.get("user")
    if data[:4] == b"\x7fELF":
        return
    for number, line in _lines(data):
        severity, reasons = heuristics.assess_linux(line)
        if rules:
            extra_sev, extra = heuristics.assess(line, rules)
            severity, reasons = heuristics.higher(severity, extra_sev), reasons + extra
        if severity == "info":
            continue
        ctx.add(Finding(check, f"{label}: suspicious line" + (f" ({user})" if user else ""),
                        f"{file}:{number}", line[:2000], severity, reasons, file, command_target(line),
                        user, mitre))


def parse_unit(data: bytes) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] = {}
    pending = ""
    for raw in data.decode("utf-8", "replace").splitlines()[:5000]:
        line = pending + raw.strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        key, sep, value = line.partition("=")
        if sep:
            current.setdefault(key.strip(), []).append(value.strip())
    return sections


def analyze_systemd(entries: list[tuple[dict[str, Any], bytes]], ctx: _Ctx) -> None:
    enabled: dict[str, list[str]] = {}
    for entry, _data in entries:
        link = entry.get("link")
        if link is None:
            continue
        name = entry["file"].rsplit("/", 1)[-1]
        parent = entry["file"].rsplit("/", 2)[-2] if entry["file"].count("/") >= 2 else ""
        if parent.endswith((".wants", ".requires", ".upholds")):
            enabled.setdefault(name, []).append(parent)
            if "@" in name:                                   # instance of a template unit
                prefix, _, rest = name.partition("@")
                enabled.setdefault(f"{prefix}@{rest[rest.rfind('.'):]}", []).append(parent)
            if link.startswith("/") and not link.startswith(("/usr/lib/systemd/", "/lib/systemd/",
                                                             "/etc/systemd/", "/usr/local/lib/systemd/",
                                                             "/run/systemd/")) \
                    and not link.startswith(entry.get("home", "\0") + "/."):
                ctx.add(Finding("linux.systemd", f"Enabled unit {name} points outside the unit folders",
                                entry["file"], link, "high", ["unit file stored in an unusual place"],
                                entry["file"], link, entry.get("user"), "T1543.002"))
    for entry, data in entries:
        if entry.get("link") is not None:
            continue
        file, kind = entry["file"], entry["kind"]
        name = file.rsplit("/", 1)[-1]
        vendor = kind.endswith("_vendor")
        user_unit = kind.startswith("systemd_user")
        dropin = "/" in file and file.rsplit("/", 2)[-2].endswith(".d") and name.endswith(".conf")
        if not (name.endswith((".service", ".timer", ".socket", ".path")) or dropin):
            continue
        unit = parse_unit(data)
        section = unit.get("Service", {})
        commands = [(k, c) for k in EXEC_KEYS for c in section.get(k, []) if c]
        if name.endswith(".timer"):
            what = (unit.get("Timer", {}).get("Unit") or [name.removesuffix(".timer") + ".service"])[0]
            if not vendor:
                ctx.add(Finding("linux.systemd_timer", f"Timer {name}", file, f"activates {what}", "info",
                                [], file, None, entry.get("user"), "T1053.006"))
            continue
        state = "enabled" if name in enabled else "not enabled"
        if dropin:
            unit_name = file.rsplit("/", 2)[-2].removesuffix(".d")
            title, base = f"Override for {unit_name}", "low" if commands and not vendor else "info"
            reason = "a drop-in replaces or adds commands of an existing unit" if commands else None
        else:
            title, base, reason = f"{'User' if user_unit else 'System'} unit {name} ({state})", "info", None
        location = file
        for key, command in commands:
            ctx.command("linux.systemd_user" if user_unit else "linux.systemd", title, f"{location} : {key}",
                        command, file, "T1543.002", user=entry.get("user"), base=base, reason=reason,
                        report_info=not vendor, system=not user_unit)


def analyze_desktop(entry: dict[str, Any], data: bytes, ctx: _Ctx, vendor: bool) -> None:
    unit = parse_unit(data)
    section = unit.get("Desktop Entry", {})
    if (section.get("Hidden") or ["false"])[0].lower() == "true":
        return
    for command in section.get("Exec", [])[:1]:
        command = re.sub(r"%[fFuUdDnNickvm]", "", command).strip()
        ctx.command("linux.autostart", f"Autostart program {entry['file'].rsplit('/', 1)[-1]}"
                    + (f" ({entry['user']})" if entry.get("user") else ""), entry["file"], command,
                    entry["file"], "T1547.013", user=entry.get("user"), report_info=not vendor,
                    system=not entry.get("user"))


def analyze_dbus(entry: dict[str, Any], data: bytes, ctx: _Ctx, vendor: bool) -> None:
    section = parse_unit(data).get("D-BUS Service", {})
    for command in section.get("Exec", [])[:1]:
        user = entry.get("user")
        ctx.command("linux.dbus", f"D-Bus activated program {entry['file'].rsplit('/', 1)[-1]}"
                    + (f" ({user})" if user else ""), entry["file"], command, entry["file"], "T1543",
                    user=user, report_info=not vendor, system=not user)


def analyze_initramfs(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    analyze_script(entry, data, ctx, "linux.initramfs", "initramfs hook", "T1542")
    if data[:2] == b"#!" or entry["file"].split("/")[-2] == "hooks":
        ctx.add(Finding("linux.initramfs", "Local initramfs hook", entry["file"], "", "info",
                        ["runs whenever the early-boot image is rebuilt and can add code to it"],
                        entry["file"], entry["file"], None, "T1542"))


def analyze_rc_local(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    for number, line in _lines(data):
        if line in ("exit 0", "exit") or line.startswith("#!"):
            continue
        ctx.command("linux.rc_local", "Boot script command", f"{entry['file']}:{number}", line, entry["file"],
                    "T1037.004", base="low", reason="rc.local runs as root at every boot")


def ssh_fingerprint(blob_b64: str) -> str | None:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (ValueError, TypeError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


KEY_TYPES = re.compile(r"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)"
                       r"@openssh\.com|ssh-(rsa|ed25519)-cert-v01@openssh\.com)$")


def split_key_line(line: str) -> tuple[str, str, str, str] | None:
    """(options, type, base64, comment) of an authorized_keys line."""
    words = line.split()
    for i, word in enumerate(words[:-1]):
        if KEY_TYPES.match(word):
            prefix = line[:line.find(word)] if i else ""
            rest = line[line.find(word) + len(word):].split(None, 1)
            return prefix.strip(), word, rest[0], rest[1] if len(rest) > 1 else ""
    return None


def analyze_authorized_keys(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    file, user = entry["file"], entry.get("user")
    account = ctx.users.get(user or "", {})
    uid = account.get("uid")
    for number, line in _lines(data):
        parsed = split_key_line(line)
        if parsed is None:
            continue
        options, ktype, blob, comment = parsed
        reasons: list[str] = []
        severity = "info"
        if file.endswith("authorized_keys2"):
            severity, reasons = "low", ["key in the legacy authorized_keys2 file (rarely checked by admins)"]
        if (uid is not None and 0 < uid < 1000) or user in SERVICE_USERS:
            severity = heuristics.higher(severity, "medium")
            reasons.append("a service account accepts SSH logins")
        command = re.search(r'command="((?:[^"\\]|\\.)*)"', options)
        if command:
            sev, why = heuristics.assess_linux(command.group(1))
            severity = heuristics.higher(severity, sev)
            reasons.extend(why)
        if "environment=" in options:
            reasons.append("sets environment variables at login")
        ctx.add(Finding("linux.ssh_key", f"SSH login key for {user}", f"{file}:{number}",
                        f"{ktype} {ssh_fingerprint(blob) or '?'} {comment}".strip()[:500], severity, reasons,
                        file, None, user, "T1098.004", {"options": options[:500]}))


def analyze_sshd(entries: list[tuple[dict[str, Any], bytes]], ctx: _Ctx) -> None:
    for entry, data in entries:
        for number, line in _lines(data):
            parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
            key, value = parts[0].lower(), (parts[1] if len(parts) > 1 else "").strip().strip('"')
            location = f"{entry['file']}:{number}"
            if key == "permitemptypasswords" and value.lower() == "yes":
                ctx.add(Finding("linux.sshd", "SSH allows empty passwords", location, line, "high",
                                [], entry["file"], None, None, "T1098"))
            elif key == "permitrootlogin" and value.lower() == "yes":
                ctx.add(Finding("linux.sshd", "SSH allows root to log in with a password", location, line,
                                "low", [], entry["file"], None, None, "T1021.004"))
            elif key == "permituserenvironment" and value.lower() not in ("no", ""):
                ctx.add(Finding("linux.sshd", "SSH lets users set environment variables", location, line,
                                "medium", ["allows LD_PRELOAD tricks through ~/.ssh/environment"],
                                entry["file"], None, None, "T1098"))
            elif key == "authorizedkeysfile" and value not in (
                    ".ssh/authorized_keys", ".ssh/authorized_keys .ssh/authorized_keys2",
                    "%h/.ssh/authorized_keys", ".ssh/authorized_keys2 .ssh/authorized_keys"):
                ctx.add(Finding("linux.sshd", "SSH reads login keys from an unusual place", location, line,
                                "medium", [], entry["file"], None, None, "T1098.004"))
            elif key == "authorizedkeyscommand" and value.lower() != "none":
                ctx.command("linux.sshd", "SSH asks a program for login keys", location, value,
                            entry["file"], "T1098.004", base="medium")


def analyze_accounts(passwd: bytes | None, shadow: bytes | None, group: bytes | None,
                     files: dict[str, str], ctx: _Ctx) -> None:
    accounts: dict[str, dict[str, Any]] = {}
    for number, line in _lines(passwd or b""):
        fields = line.split(":")
        if len(fields) != 7:
            continue
        name, pw, uid_text, _gid, _gecos, home, shell = fields
        try:
            uid = int(uid_text)
        except ValueError:
            continue
        login = not shell.rstrip().endswith(NOLOGIN) and shell.startswith("/")
        accounts[name] = {"uid": uid, "login": login, "home": home}
        location = f"{files.get('passwd')}:{number}"
        if uid == 0 and name != "root":
            ctx.add(Finding("linux.account", f"Second superuser account {name}", location, f"{name} uid=0",
                            "high", ["any account with UID 0 has full root rights"], files.get("passwd"),
                            None, name, "T1136.001"))
        if pw == "" and login:
            ctx.add(Finding("linux.account", f"Account {name} has no password", location, name, "high",
                            ["anyone can log in as this user"], files.get("passwd"), None, name, "T1098"))
    for number, line in _lines(shadow or b""):
        fields = line.split(":")
        if len(fields) < 2 or fields[0] not in accounts:
            continue
        name, hashed = fields[0], fields[1]
        acct = accounts[name]
        location = f"{files.get('shadow')}:{number}"
        if hashed == "" and acct["login"]:
            ctx.add(Finding("linux.account", f"Account {name} has an empty password", location, name, "high",
                            ["anyone can log in as this user"], files.get("shadow"), None, name, "T1098"))
        elif hashed[:1] == "$" and acct["login"] and 0 < acct["uid"] < 1000:
            ctx.add(Finding("linux.account", f"Service account {name} can log in with a password", location,
                            name, "medium", ["system accounts normally have locked passwords"],
                            files.get("shadow"), None, name, "T1078.003"))
    admins = []
    for _number, line in _lines(group or b""):
        fields = line.split(":")
        if len(fields) == 4 and fields[0] in ("sudo", "wheel", "admin") and fields[3].strip():
            admins.extend(m for m in fields[3].split(",") if m)
    if admins:
        ctx.add(Finding("linux.account", "Administrator accounts", files.get("group") or "/etc/group",
                        ", ".join(sorted(set(admins)))[:500], "info", [], files.get("group")))
    ctx.info["accounts"] = len(accounts)


def analyze_sudoers(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    file = entry["file"]
    if int(entry.get("mode", 0)) & 0o022 or entry.get("uid") not in (0, None):
        ctx.add(Finding("linux.sudo", "sudo rules file has unsafe permissions", file,
                        oct(int(entry.get("mode", 0))), "medium", ["writable by others or not owned by root"],
                        file, None, None, "T1548.003"))
    text = data.decode("utf-8", "replace").replace("\\\n", " ")
    for number, raw in enumerate(text.splitlines()[:5000], 1):
        line = raw.strip()
        if not line or (line.startswith("#") and not line.startswith(("#include", "#includedir"))):
            continue
        location = f"{file}:{number}"
        if line.startswith("Defaults"):
            if re.search(r"!\s*authenticate\b", line):
                ctx.add(Finding("linux.sudo", "sudo never asks for a password", location, line, "high", [],
                                file, None, None, "T1548.003"))
            if re.search(r"env_keep\s*\+?=.*\bLD_(PRELOAD|LIBRARY_PATH)\b", line):
                ctx.add(Finding("linux.sudo", "sudo keeps LD_PRELOAD", location, line, "high",
                                ["lets any sudo user load code into root programs"], file, None, None,
                                "T1574.006"))
            continue
        if "NOPASSWD" not in line:
            continue
        who = line.split(None, 1)[0]
        everything = re.search(r"NOPASSWD\s*:\s*ALL\b", line) is not None
        severity = "medium" if everything else "low"
        reasons = ["passwordless root access" if everything
                   else "some commands run as root without a password"]
        if who.lstrip("%") in SERVICE_USERS:
            severity, reasons = "high", [f"service account {who} can become root", *reasons]
        ctx.add(Finding("linux.sudo", f"Passwordless sudo for {who}", location, line, severity, reasons, file,
                        None, who.lstrip("%"), "T1548.003"))


SECURITY_DIRS = re.compile(r"^/(usr/)?lib(64|32|x32)?/([\w.-]+/)?security/")


def analyze_pam(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    file = entry["file"]
    for number, line in _lines(data):
        words = line.split()
        if len(words) < 3 or words[0].lstrip("-") not in ("auth", "account", "password", "session"):
            continue
        ptype = words[0].lstrip("-")
        control_end = 2
        if words[1].startswith("["):
            for i, word in enumerate(words[1:], 1):
                if word.endswith("]"):
                    control_end = i + 1
                    break
        control = " ".join(words[1:control_end])
        if control_end >= len(words):
            continue
        module, module_args = words[control_end], " ".join(words[control_end + 1:])
        location = f"{file}:{number}"
        base = module.rsplit("/", 1)[-1]
        if module.startswith("/") and not SECURITY_DIRS.match(module):
            ctx.add(Finding("linux.pam", f"PAM module loaded from an unusual place ({ptype})", location, line,
                            "high", ["login modules normally live in a security/ library folder"], file,
                            module, None, "T1556.003"))
        if base == "pam_permit.so" and ptype == "auth" and ("sufficient" in control or "done" in control):
            ctx.add(Finding("linux.pam", "PAM accepts any password", location, line, "high",
                            ["pam_permit as a sufficient auth module lets anyone log in"], file, None, None,
                            "T1556.003"))
        if base == "pam_exec.so":
            reason = ("pam_exec can capture passwords (expose_authtok)" if "expose_authtok" in module_args
                      else "runs a program at every login")
            ctx.command("linux.pam", f"PAM runs a program ({ptype})", location, module_args, file,
                        "T1556.003", base="medium", reason=reason)


def analyze_udev(entry: dict[str, Any], data: bytes, ctx: _Ctx, vendor: bool) -> None:
    for number, line in _lines(data):
        for match in re.finditer(r'\b(RUN|PROGRAM|IMPORT\{program\})\s*\+?=\s*"([^"]*)"', line):
            command = match.group(2)
            if command.startswith("builtin") or not command:
                continue
            ctx.command("linux.udev", f"Device rule runs {command.split()[0][:80]}",
                        f"{entry['file']}:{number}", command, entry["file"], "T1546", base="info",
                        report_info=not vendor)


def analyze_hooks(entry: dict[str, Any], data: bytes, ctx: _Ctx, vendor: bool) -> None:
    file, kind = entry["file"], entry["kind"]
    if kind == "apt_hook":
        text = data.decode("utf-8", "replace")
        for match in APT_HOOK_RE.finditer(text):
            number = text.count("\n", 0, match.start()) + 1
            body = match.group("block") or match.group("single") or ""
            for command in re.findall(r'"((?:[^"\\]|\\.)*)"', body)[:20]:
                ctx.command("linux.package_hook", f"APT hook ({match.group('name')})", f"{file}:{number}",
                            command, file, "T1546.016", report_info=not vendor)
        return
    for number, line in _lines(data):                    # pacman .hook files
        key, sep, value = line.partition("=")
        if sep and key.strip() == "Exec":
            ctx.command("linux.package_hook", "pacman hook", f"{file}:{number}", value.strip(), file,
                        "T1546.016", report_info=not vendor)


BLACKLIST_IDIOM = re.compile(r"(/usr)?/s?bin/(true|false)|true|false|"
                             r"/bin/sh -c ['\"]?(exit \d|true|false)['\"]?")


def analyze_modprobe(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    for number, line in _lines(data):
        words = line.split(None, 2)
        if len(words) == 3 and words[0] == "install":
            command = words[2].strip()
            if BLACKLIST_IDIOM.fullmatch(command) or "--ignore-install" in command:
                continue
            ctx.command("linux.modprobe", f"Module load for {words[1]} runs a command",
                        f"{entry['file']}:{number}", command, entry["file"], "T1547.006", base="medium")


def analyze_preload(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    for number, line in _lines(data):
        for path in line.replace(":", " ").split():
            ctx.add(Finding("linux.ld_preload", "Library preloaded into every program",
                            f"{entry['file']}:{number}", path, "high",
                            ["/etc/ld.so.preload is a common rootkit technique"], entry["file"],
                            path if path.startswith("/") else None, None, "T1574.006"))


def analyze_ldconf(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    for number, line in _lines(data):
        if line.startswith("include"):
            continue
        if re.match(r"^/(tmp|var/tmp|dev/shm|home|root)(/|$)", line) or "/." in line:
            ctx.add(Finding("linux.ld_preload", "Library search path in an unusual place",
                            f"{entry['file']}:{number}", line, "high",
                            ["programs would load libraries from this folder"], entry["file"], None, None,
                            "T1574.006"))


def analyze_grub(entry: dict[str, Any], data: bytes, ctx: _Ctx) -> None:
    for number, line in _lines(data):
        if entry["kind"] == "grub":
            relevant = line.startswith("GRUB_CMDLINE_LINUX")
        else:
            relevant = line.split(None, 1)[0] in ("linux", "linux16", "linuxefi")
        if relevant and re.search(r"(^|[\s\"'])(rd)?init=\S+", line):
            ctx.add(Finding("linux.boot", "Kernel command line replaces the init program",
                            f"{entry['file']}:{number}", line[:500], "high",
                            ["init= makes the kernel start a different first program"], entry["file"], None,
                            None, "T1542"))


def analyze_polkit(entry: dict[str, Any], data: bytes, ctx: _Ctx, vendor: bool) -> None:
    text = data.decode("utf-8", "replace")
    if "Result.YES" not in text:
        return
    body = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    unconditional = re.search(r"function\s*\([^)]*\)\s*\{\s*return\s+polkit\.Result\.YES", body) is not None
    if unconditional:
        ctx.add(Finding("linux.polkit", "polkit rule allows every action", entry["file"], text[:500], "high",
                        ["any local user gets administrator rights"], entry["file"], None, None, "T1548"))
    elif not vendor:
        ctx.add(Finding("linux.polkit", "polkit rule grants rights without a password", entry["file"],
                        text[:500], "info", [], entry["file"], None, None, "T1548"))


def analyze_odd(args: dict[str, Any], ctx: _Ctx) -> None:
    for item in args.get("odd", []):
        if item.get("odd"):
            ctx.add(Finding("linux.hidden_name", "Entry with a name that hides in listings", item["file"],
                            repr(item["file"].rsplit("/", 1)[-1]), "high",
                            ["names such as '...' or '.. ' are used to hide rootkit files"], item["file"],
                            item["file"] if stat.S_ISREG(item["mode"]) else None, None, "T1564.001"))
        elif item.get("dev"):
            ctx.add(Finding("linux.hidden_name", "Regular file in /dev", item["file"], "", "medium",
                            ["/dev normally holds only device nodes; rootkits hide files here"], item["file"],
                            item["file"], None, "T1564.001"))
    for item in args.get("temp_exec", []):
        ctx.add(Finding("linux.temp_executable", "Program in a temporary folder", item["file"],
                        "ELF executable" if item.get("elf") else "executable file", "medium",
                        ["malware is often dropped and run from temporary folders"], item["file"],
                        item["file"], None, "T1036"))


def task_persistence(args: dict[str, Any], fds: list[int]) -> dict[str, Any]:
    """Sandbox entry point (see offscan.sandbox.TASKS)."""
    ctx = _Ctx(args.get("users", []))
    by_kind: dict[str, list[tuple[dict[str, Any], bytes]]] = {}
    for entry, data in filepack.entries(fds[args["pack"]], args["index"]):
        by_kind.setdefault(entry["kind"], []).append((entry, data))
    if args.get("truncated"):
        ctx.errors.append("too many files: only part of the configuration was checked")

    def each(*kinds: str) -> list[tuple[dict[str, Any], bytes]]:
        return [item for kind in kinds for item in by_kind.get(kind, [])]

    def guard(name: str, func: Any, *a: Any) -> None:
        try:
            func(*a)
        except Exception as exc:
            ctx.errors.append(f"{name}: {type(exc).__name__}: {exc}"[:300])

    for entry, data in each("cron", "crontab", "anacron"):
        guard(entry["file"], analyze_cron, entry, data, ctx)
    for entry, data in each("at"):
        if entry["file"].rsplit("/", 1)[-1].startswith("."):       # .SEQ counter, not a job
            continue
        guard(entry["file"], analyze_script, entry, data, ctx, "linux.at", "at job", "T1053.002")
        ctx.add(Finding("linux.at", "Pending at job", entry["file"], "", "low",
                        ["one-off commands queued with at"], entry["file"], None, None, "T1053.002"))
    for entry, data in each("cron_script"):
        guard(entry["file"], analyze_script, entry, data, ctx, "linux.cron", "Cron script", "T1053.003")
    for entry, data in each("script", "generator"):
        guard(entry["file"], analyze_script, entry, data, ctx, "linux.script", "Start-up script", "T1037")
    for entry, _data in each("generator"):
        name = entry["file"].rsplit("/", 1)[-1]
        ctx.add(Finding("linux.systemd", f"systemd generator {name}", entry["file"], entry.get("link") or "",
                        "medium",
                        ["generators run very early at every boot; local ones are rare"], entry["file"],
                        entry["file"], None, "T1543.002"))
    for entry, data in each("shellrc", "user_shellrc", "ssh_rc", "ssh_environment"):
        label = "SSH start-up file" if entry["kind"].startswith("ssh") else "Shell start-up file"
        guard(entry["file"], analyze_script, entry, data, ctx, "linux.shell_rc", label, "T1546.004",
              SHELL_RULES)
    for entry, data in each("rc_local"):
        guard(entry["file"], analyze_rc_local, entry, data, ctx)
    guard("systemd", analyze_systemd,
          each("systemd", "systemd_vendor", "systemd_user", "systemd_user_vendor"), ctx)
    for entry, data in each("xdg_autostart", "user_autostart"):
        guard(entry["file"], analyze_desktop, entry, data, ctx, entry["kind"] == "xdg_autostart")
    for entry, data in each("dbus", "dbus_vendor"):
        guard(entry["file"], analyze_dbus, entry, data, ctx, entry["kind"] == "dbus_vendor")
    for entry, data in each("initramfs"):
        guard(entry["file"], analyze_initramfs, entry, data, ctx)
    for entry, data in each("authorized_keys"):
        guard(entry["file"], analyze_authorized_keys, entry, data, ctx)
    guard("sshd", analyze_sshd, each("sshd"), ctx)
    single = {kind: (items[0][1], items[0][0]["file"]) for kind in ("passwd", "shadow", "group")
              if (items := by_kind.get(kind))}
    account_data = [single.get(k, (None, None))[0] for k in ("passwd", "shadow", "group")]
    guard("accounts", analyze_accounts, *account_data, {k: v[1] for k, v in single.items()}, ctx)
    for entry, data in each("sudoers"):
        guard(entry["file"], analyze_sudoers, entry, data, ctx)
    for entry, data in each("pam"):
        guard(entry["file"], analyze_pam, entry, data, ctx)
    for entry, data in each("udev", "udev_vendor"):
        guard(entry["file"], analyze_udev, entry, data, ctx, entry["kind"] == "udev_vendor")
    for entry, data in each("apt_hook", "pacman_hook", "pacman_hook_vendor"):
        guard(entry["file"], analyze_hooks, entry, data, ctx, entry["kind"].endswith("_vendor"))
    for entry, data in each("modprobe"):
        guard(entry["file"], analyze_modprobe, entry, data, ctx)
    for entry, data in each("preload"):
        guard(entry["file"], analyze_preload, entry, data, ctx)
    for entry, data in each("ldconf"):
        guard(entry["file"], analyze_ldconf, entry, data, ctx)
    for entry, data in each("grub", "grub_cfg"):
        guard(entry["file"], analyze_grub, entry, data, ctx)
    for entry, data in each("polkit", "polkit_vendor"):
        guard(entry["file"], analyze_polkit, entry, data, ctx, entry["kind"] == "polkit_vendor")
    guard("names", analyze_odd, args, ctx)
    ctx.info["files_checked"] = len(args["index"])
    return {"findings": [f.to_dict() for f in ctx.findings], "targets": sorted(ctx.targets),
            "errors": ctx.errors[:100], "info": ctx.info}
