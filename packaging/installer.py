#!/usr/bin/env python3
"""Install, update or remove the application without a package manager.

install.sh starts this as root once python3 exists. The files are the same
ones the packages install (``build.py stage``). Each one is recorded with
its SHA-256 in a manifest, so ``--uninstall`` removes exactly those files,
and never one that was changed after installation. Definitions, the
quarantine, the change log, history and reports are only deleted after an
explicit yes (or ``--purge``).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402

MANIFEST_FORMAT = 1
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


class InstallError(Exception):
    pass


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False)


# ------------------------------------------------------------ distributions

def parse_os_release(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.startswith("#"):
            fields[key.strip()] = value.strip().strip("\"'")
    return fields


def detect_family(fields: dict[str, str]) -> str | None:
    """deb, fedora, opensuse or arch, from ID and ID_LIKE."""
    for ident in [fields.get("ID", ""), *fields.get("ID_LIKE", "").split()]:
        if ident in ("debian", "ubuntu"):
            return "deb"
        if ident == "fedora":
            return "fedora"
        if ident.startswith("opensuse") or ident in ("suse", "sles"):
            return "opensuse"
        if ident in ("arch", "archlinux"):
            return "arch"
    return None


def strip_version(name: str) -> str:
    return name.split("(")[0].split(">=")[0].split()[0]


class PackageManager:
    """The few package-manager queries the installer needs."""

    tool = ""

    def __init__(self, run: Runner = _run):
        self.run = run
        self.refreshed = False

    def installed(self, name: str) -> bool:
        return self.run(["rpm", "-q", "--whatprovides", name]).returncode == 0

    def available(self, name: str) -> bool:
        raise NotImplementedError

    def refresh(self) -> None:
        """Bring the package lists up to date once, before looking for candidates."""

    def install_command(self, names: list[str], yes: bool) -> list[str]:
        raise NotImplementedError

    def owns_app(self, name: str) -> bool:
        return self.run(["rpm", "-q", name]).returncode == 0


class Apt(PackageManager):
    tool = "apt-get"

    def installed(self, name: str) -> bool:
        out = self.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", name])
        return out.returncode == 0 and out.stdout.startswith("ii")

    def refresh(self) -> None:
        if not self.refreshed:
            self.refreshed = True
            self.run(["apt-get", "update", "-q"])

    def available(self, name: str) -> bool:
        out = self.run(["apt-cache", "show", "--no-all-versions", name])
        return out.returncode == 0 and "Package:" in out.stdout

    def install_command(self, names: list[str], yes: bool) -> list[str]:
        return ["apt-get", "install", *(["-y"] if yes else []), *names]

    def owns_app(self, name: str) -> bool:
        return self.installed(name)


class Dnf(PackageManager):
    tool = "dnf"

    def available(self, name: str) -> bool:
        out = self.run(["dnf", "-q", "repoquery", "--qf", "%{name}\n", name])
        return out.returncode == 0 and name in out.stdout.split()

    def install_command(self, names: list[str], yes: bool) -> list[str]:
        return ["dnf", "install", *(["-y"] if yes else []), *names]


class Zypper(PackageManager):
    tool = "zypper"

    def available(self, name: str) -> bool:
        out = self.run(["zypper", "--non-interactive", "--quiet", "search", "--match-exact",
                        "--type", "package", name])
        return out.returncode == 0

    def install_command(self, names: list[str], yes: bool) -> list[str]:
        return ["zypper", *(["--non-interactive"] if yes else []), "install", *names]


class Pacman(PackageManager):
    tool = "pacman"

    def installed(self, name: str) -> bool:
        return self.run(["pacman", "-T", name]).returncode == 0

    def available(self, name: str) -> bool:
        return self.run(["pacman", "-Si", name]).returncode == 0

    def install_command(self, names: list[str], yes: bool) -> list[str]:
        return ["pacman", "-S", "--needed", *(["--noconfirm"] if yes else []), *names]

    def owns_app(self, name: str) -> bool:
        return self.run(["pacman", "-Q", name]).returncode == 0


MANAGERS = {"deb": Apt, "fedora": Dnf, "opensuse": Zypper, "arch": Pacman}


@dataclass
class DependencyPlan:
    install: list[str]
    missing: list[list[str]]      # required, and no candidate in the repositories
    optional: list[str]           # not installed, worth mentioning


def plan_dependencies(pm: PackageManager, deps: dict) -> DependencyPlan:
    plan = DependencyPlan([], [], [])
    for kind in ("depends", "recommends"):
        for group in deps.get(kind, []):
            names = [strip_version(n) for n in group]
            if any(pm.installed(n) for n in names):
                continue
            pm.refresh()
            candidate = next((n for n in names if pm.available(n)), None)
            if candidate:
                plan.install.append(candidate)
            elif kind == "depends":
                plan.missing.append(group)
            else:
                plan.optional.append(" or ".join(names))
    for name, why in deps.get("optdepends", []):
        if not pm.installed(name):
            plan.optional.append(f"{name} ({why})")
    return plan


# ----------------------------------------------------------------- manifest

def sha256_file(path: Path) -> str:
    return build.sha256_file(path)


@dataclass
class Layout:
    """Where things go; ``root`` is "/" except in tests and image builds."""

    root: Path
    info: dict[str, str]

    def path(self, installed: str) -> Path:
        pure = PurePosixPath(installed)
        if not pure.is_absolute() or ".." in pure.parts:
            raise InstallError(f"bad path {installed!r}")
        return self.root / pure.relative_to("/")

    @property
    def state_dir(self) -> Path:
        return self.path(self.info["SYSTEM_STATE_DIR"])

    @property
    def manifest(self) -> Path:
        return self.state_dir / "install-manifest.json"


def load_manifest(layout: Layout) -> dict | None:
    try:
        data = json.loads(layout.manifest.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise InstallError(f"cannot read {layout.manifest}: {exc}") from exc
    if data.get("format") != MANIFEST_FORMAT or not isinstance(data.get("files"), dict):
        raise InstallError(f"{layout.manifest} has an unknown format")
    return data


def write_manifest(layout: Layout, data: dict) -> None:
    layout.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = layout.manifest.with_name(layout.manifest.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, layout.manifest)


def _make_parents(layout: Layout, target: Path, created: list[str]) -> None:
    missing = []
    parent = target.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)  # noqa: S103 - installed directories are world-readable
        created.append("/" + directory.relative_to(layout.root).as_posix())


def _install_file(src: Path, dst: Path, mode: int) -> None:
    if dst.is_symlink() or (dst.exists() and not dst.is_file()):
        raise InstallError(f"{dst} exists and is not a regular file")
    tmp = dst.with_name(f".{dst.name}.install-new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
        shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, mode)
    if os.geteuid() == 0:
        os.chown(tmp, 0, 0)
    os.replace(tmp, dst)


def _remove_if_unchanged(path: Path, sha256: str, force: bool) -> bool:
    """Remove ``path`` if it still has the installed content; True if gone."""
    if not path.exists() and not path.is_symlink():
        return True
    if path.is_symlink() or not path.is_file():
        return False
    if not force and sha256_file(path) != sha256:
        return False
    path.unlink()
    return True


def _remove_bytecode(layout: Layout) -> None:
    for directory in (layout.info["PYTHON_DIR"], layout.info["VENDOR_DIR"]):
        base = layout.path(directory)
        if not base.is_dir() or base.is_symlink():
            continue
        for cache in sorted(base.rglob("__pycache__"), key=lambda p: -len(p.parts)):
            if cache.is_dir() and not cache.is_symlink():
                shutil.rmtree(cache)


def _remove_dirs(layout: Layout, dirs: list[str]) -> None:
    for directory in sorted(set(dirs), key=lambda d: -len(PurePosixPath(d).parts)):
        try:
            layout.path(directory).rmdir()
        except OSError:
            pass                       # not empty: something else lives there now


# --------------------------------------------------------------- user data

@dataclass
class DataItem:
    question: str
    paths: list[Path]
    base: Path                  # every path must lie inside this directory
    home: bool = False          # inside a user's home: deleted with that user's rights

    def present(self) -> list[Path]:
        return [p for p in self.paths if p.exists() or p.is_symlink()]


def _size(paths: list[Path]) -> int:
    total = 0
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_file():
            total += path.stat().st_size
        elif path.is_dir():
            total += sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())
    return total


def data_items(layout: Layout, home: Path | None) -> list[DataItem]:
    name = layout.info["NAME"]
    state = layout.state_dir
    quarantine = state / "quarantine"
    count = sum(1 for p in quarantine.iterdir() if p.is_dir()) if quarantine.is_dir() else 0
    items = [
        DataItem(f"Delete the quarantine ({count} file(s); they cannot be restored to their drives "
                 "afterwards)?", [quarantine], state),
        DataItem("Delete the log of changes made to drives?", [state / "changes.jsonl"], state),
    ]
    if home is not None:
        data = home / ".local" / "share" / name
        items += [
            DataItem("Delete the downloaded definitions?", [data / "definitions"], home, True),
            DataItem("Delete the scan history and reports?",
                     [data / "history.sqlite3", data / "history.sqlite3-wal",
                      data / "history.sqlite3-shm", data / "reports"], home, True),
            DataItem("Delete the settings, saved keys, logs and cache?",
                     [home / ".config" / name, home / ".local" / "state" / name, home / ".cache" / name],
                     home, True),
        ]
    return items


def _check_inside(path: Path, base: Path) -> None:
    """``path`` must be below ``base`` with no symbolic link on the way (the last part may be one)."""
    try:
        rel = path.relative_to(base)
    except ValueError:
        raise InstallError(f"refusing to delete {path}: it is not inside {base}") from None
    current = base
    for part in rel.parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            raise InstallError(f"refusing to delete {path}: {current} is not a plain directory")


def _delete(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink()              # a link itself, never what it points to
    else:
        shutil.rmtree(path)        # does not follow symbolic links inside


def _remove_data(path: Path, base: Path, as_owner: bool = False) -> None:
    """Delete one data file or directory, never anything outside ``base``.

    Data in a user's home is deleted by a child process with that user's
    rights (``as_owner``), so swapping a directory for a symbolic link while
    we work can only make it delete what the user could delete anyway.
    """
    _check_inside(path, base)
    try:
        owner = base.stat()
    except OSError as exc:
        raise InstallError(f"cannot read {base}: {exc}") from exc
    if not as_owner or os.geteuid() != 0 or owner.st_uid == 0:
        _delete(path)
        return
    result = subprocess.run([sys.executable, "-I", "-c", _DELETE_AS_OWNER, str(path), str(base)],
                            user=owner.st_uid, group=owner.st_gid, extra_groups=[], cwd="/",
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}, capture_output=True,
                            check=False)
    if result.returncode != 0:
        raise InstallError(f"could not delete {path}")


# Run with the rights of the data's owner: the same checks and deletion as above.
_DELETE_AS_OWNER = """
import shutil, sys
from pathlib import Path
path, base = Path(sys.argv[1]), Path(sys.argv[2])
current = base
for part in path.relative_to(base).parts[:-1]:
    current = current / part
    if current.is_symlink() or not current.is_dir():
        sys.exit(3)
if path.is_symlink() or not path.is_dir():
    path.unlink()
else:
    shutil.rmtree(path)
"""


def invoking_home(user: str | None) -> tuple[str, Path] | None:
    """The account that ran sudo/pkexec (its data is in its home directory)."""
    try:
        if user:
            entry = pwd.getpwnam(user)
        elif os.environ.get("SUDO_USER"):
            entry = pwd.getpwnam(os.environ["SUDO_USER"])
        elif os.environ.get("PKEXEC_UID", "").isdigit():
            entry = pwd.getpwuid(int(os.environ["PKEXEC_UID"]))
        else:
            entry = pwd.getpwuid(os.getuid())
    except KeyError:
        return None
    return entry.pw_name, Path(entry.pw_dir)


def other_users_with_data(name: str, skip: Path | None) -> list[str]:
    found = []
    for entry in pwd.getpwall():
        home = Path(entry.pw_dir)
        if home == skip or not home.is_absolute() or home == Path("/"):
            continue
        try:
            if (home / ".local" / "share" / name).is_dir():
                found.append(entry.pw_name)
        except OSError:
            continue
    return sorted(set(found))


# -------------------------------------------------------------------- steps

class Installer:
    def __init__(self, args: argparse.Namespace, layout: Layout, pm: PackageManager | None,
                 ask: Callable[[str], bool], out: Callable[[str], None] = print, run: Runner = _run):
        self.args = args
        self.layout = layout
        self.pm = pm
        self.ask = ask
        self.out = out
        self.run = run
        self.info = layout.info
        self.system = layout.root == Path("/")

    def confirm(self, question: str) -> bool:
        return True if self.args.yes else self.ask(question)

    # -------------------------------------------------------- dependencies

    def dependencies(self) -> None:
        if self.pm is None or self.args.no_deps:
            return
        deps = json.loads(build.DEPS.read_text(encoding="utf-8"))[self.args.family]
        if self.args.offline:
            self.pm.refreshed = True           # use the package lists as they are
        plan = plan_dependencies(self.pm, deps)
        if plan.missing:
            groups = ", ".join(" or ".join(g) for g in plan.missing)
            raise InstallError(f"required packages are not available from the configured repositories: "
                               f"{groups}")
        if plan.install:
            self.out(f"Missing packages: {' '.join(plan.install)}")
            if self.args.offline:
                raise InstallError("install them first, or pass --no-deps to continue without them")
            command = self.pm.install_command(plan.install, self.args.yes)
            if not self.confirm(f"Install them with {self.pm.tool}?"):
                raise InstallError("cancelled; install the packages yourself or use --no-deps")
            if subprocess.run(command, check=False).returncode != 0:
                raise InstallError(f"{' '.join(command)} failed")
        if plan.optional:
            self.out("Optional, not installed: " + ", ".join(plan.optional))

    # -------------------------------------------------------------- wheels

    def wheels(self, arch: str, tmp: Path) -> dict[str, Path] | None:
        if self.args.no_vendor:
            self.out("Leaving out YARA-X and regipy (--no-vendor): YARA rules then need the "
                     "distribution's yara-python, and Windows registry checks are skipped.")
            return None
        # Wheels from elsewhere are copied into our private directory first, and
        # checked and unpacked from that copy, so nobody can swap them in between.
        if self.args.wheels:
            return build.find_wheels(arch, self.args.wheels, copy_to=tmp)
        cache = build.ROOT / "build" / "wheels"
        try:
            return build.find_wheels(arch, cache, copy_to=tmp)
        except build.BuildError:
            pass
        if self.args.offline:
            raise InstallError(f"the vendored wheels are not in {cache}; pass --wheels DIR "
                               "(see 'build.py fetch') or --no-vendor")
        self.out("Downloading the pinned YARA-X and regipy wheels from PyPI.")
        return build.find_wheels(arch, tmp, download=True)

    # ------------------------------------------------------------- install

    def install(self, update: bool) -> int:
        old = load_manifest(self.layout)
        name = self.info["NAME"]
        if old and not update:
            raise InstallError(f"{self.info['DISPLAY_NAME']} {old['version']} is already installed; "
                               "use --update")
        if update and not old:
            raise InstallError("no installation made by install.sh was found; use --install")
        if self.pm is not None and self.pm.owns_app(name):
            raise InstallError(f"{name} is installed as a distribution package; update or remove it "
                               f"with {self.pm.tool} instead")
        arch = build.host_arch()
        action = "Update" if update else "Install"
        version = self.info["VERSION"]
        frm = f" (from {old['version']})" if old else ""
        if not self.confirm(f"{action} {self.info['DISPLAY_NAME']} {version}{frm} into {self.layout.root}?"):
            self.out("Nothing changed.")
            return 1
        self.dependencies()
        with tempfile.TemporaryDirectory(prefix=f"{name}-install-") as tmp:
            wheels = self.wheels(arch, Path(tmp) / "wheels")
            stage_dir = Path(tmp) / "stage"
            entries = build.stage(stage_dir, "manual", arch, wheels, self.info)
            files = {e.path: e.mode for e in entries if e.kind == "file"}
            self._check_conflicts(files, old)
            created = list(old.get("dirs", [])) if old else []
            record = dict(old["files"]) if old else {}
            # Record the new files before copying, so an interrupted run can
            # still be uninstalled.
            for path, mode in files.items():
                record[path] = {"sha256": build.sha256_file(stage_dir / path.lstrip("/")), "mode": mode}
            manifest = {"format": MANIFEST_FORMAT, "name": name, "version": version, "arch": arch,
                        "installed": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                        "source": str(build.ROOT), "files": record, "dirs": created}
            write_manifest(self.layout, manifest)
            for path, mode in files.items():
                target = self.layout.path(path)
                _make_parents(self.layout, target, created)
                _install_file(stage_dir / path.lstrip("/"), target, mode)
            write_manifest(self.layout, manifest)
        if old:
            for path in [p for p in old["files"] if p not in files]:
                if not _remove_if_unchanged(self.layout.path(path), old["files"][path]["sha256"], False):
                    self.out(f"Kept {path}: it was changed after installation")
                del record[path]
        write_manifest(self.layout, manifest)
        self._after_change(compile_python=True)
        self.out(f"Installed {self.info['DISPLAY_NAME']} {version}: {len(files)} files. "
                 f"Remove it with: sudo ./install.sh --uninstall")
        return 0

    def _check_conflicts(self, files: dict[str, int], old: dict | None) -> None:
        conflicts = []
        for path in files:
            target = self.layout.path(path)
            if (target.exists() or target.is_symlink()) and not (old and path in old["files"]):
                conflicts.append(path)
        if conflicts and not self.args.force:
            shown = "\n  ".join(conflicts[:10]) + ("\n  ..." if len(conflicts) > 10 else "")
            raise InstallError(f"these files exist and were not installed by install.sh "
                               f"(use --force to overwrite):\n  {shown}")

    # ----------------------------------------------------------- uninstall

    def uninstall(self) -> int:
        old = load_manifest(self.layout)
        if old is None:
            name = self.info["NAME"]
            if self.pm is not None and self.pm.owns_app(name):
                raise InstallError(f"{name} is installed as a distribution package; remove it with "
                                   f"{self.pm.tool}")
            raise InstallError("no installation made by install.sh was found")
        count = len(old["files"])
        if not self.confirm(f"Remove {self.info['DISPLAY_NAME']} {old['version']} ({count} files)?"):
            self.out("Nothing changed.")
            return 1
        kept = [path for path, meta in old["files"].items()
                if not _remove_if_unchanged(self.layout.path(path), meta["sha256"], self.args.force)]
        _remove_bytecode(self.layout)
        _remove_dirs(self.layout, old.get("dirs", []))
        for path in kept:
            self.out(f"Kept {path}: it was changed after installation (--force removes it)")
        self._user_data()
        self.layout.manifest.unlink()
        try:
            self.layout.state_dir.rmdir()
        except OSError:
            pass
        self._after_change(compile_python=False)
        self.out(f"Removed {self.info['DISPLAY_NAME']}.")
        return 0

    def _user_data(self) -> None:
        account = None if self.args.home else invoking_home(self.args.user)
        home = self.args.home or (account[1] if account else None)
        for item in data_items(self.layout, home):
            present = item.present()
            if not present:
                continue
            where = ", ".join(str(p) for p in present)
            if self.args.purge:
                remove = True
            elif self.args.keep_data or self.args.yes:
                remove = False
            else:
                remove = self.ask(f"{item.question} [{where}, {_size(present) / 1e6:.1f} MB]")
            if remove:
                for path in present:
                    _remove_data(path, item.base, as_owner=item.home)
                self.out(f"Deleted {where}")
            else:
                self.out(f"Kept {where}")
        if home is not None:
            data = home / ".local" / "share" / self.info["NAME"]
            try:
                data.rmdir()
            except OSError:
                pass
        if self.system:
            others = other_users_with_data(self.info["NAME"], home)
            if others:
                self.out("Other accounts keep their own definitions and history in "
                         f"~/.local/share/{self.info['NAME']}: {', '.join(others)}")

    # -------------------------------------------------------------- caches

    def _create_account(self) -> None:
        """The system account the scanners run as (kept on uninstall, like packages do)."""
        name = self.info["SCAN_USER"]
        conf = f"/usr/lib/sysusers.d/{self.info['NAME']}.conf"
        if shutil.which("systemd-sysusers"):
            self.run(["systemd-sysusers", conf])
        try:
            pwd.getpwnam(name)
        except KeyError:
            nologin = next((p for p in ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin")
                            if os.path.exists(p)), "/bin/false")
            self.run(["useradd", "--system", "--no-create-home", "--home-dir", "/", "--shell", nologin,
                      "--user-group", name])

    def _after_change(self, compile_python: bool) -> None:
        if compile_python and self.system:
            self._create_account()
        if compile_python:
            for directory in (self.info["PYTHON_DIR"], self.info["VENDOR_DIR"]):
                target = self.layout.path(directory)
                if target.is_dir():
                    build.compile_tree(target, strip=None if self.system else self.layout.root)
        if not self.system:
            return
        for argv in (["update-desktop-database", "-q", "/usr/share/applications"],
                     ["gtk-update-icon-cache", "-q", "-t", "-f", "/usr/share/icons/hicolor"]):
            if shutil.which(argv[0]):
                self.run(argv)


# --------------------------------------------------------------------- main

def _ask_tty(question: str) -> bool:
    if not sys.stdin.isatty():
        raise InstallError("cannot ask in a non-interactive session; use --yes (on --uninstall "
                           "data is then kept; add --purge to delete it too)")
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="install.sh", description=(
        "Install, update or remove the application from this source tree. Prefer the "
        "distribution packages when you can; this is for everything else."))
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--install", dest="action", action="store_const", const="install",
                        help="install, with the missing distribution packages")
    action.add_argument("--update", dest="action", action="store_const", const="update",
                        help="replace an earlier install.sh installation with this version")
    action.add_argument("--uninstall", dest="action", action="store_const", const="uninstall",
                        help="remove the files that were installed; asks about your data")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="do not ask; on --uninstall data is kept unless --purge is given")
    data = parser.add_mutually_exclusive_group()
    data.add_argument("--purge", action="store_true",
                      help="--uninstall: also delete definitions, quarantine, change log, history "
                           "and reports")
    data.add_argument("--keep-data", action="store_true", help="--uninstall: keep all data without asking")
    parser.add_argument("--no-deps", action="store_true", help="do not install distribution packages")
    parser.add_argument("--offline", action="store_true",
                        help="download nothing: use --wheels or --no-vendor, and report missing packages")
    parser.add_argument("--wheels", type=Path, help="directory with the vendored wheels (see build.py fetch)")
    parser.add_argument("--no-vendor", action="store_true", help="install without YARA-X and regipy")
    parser.add_argument("--force", action="store_true",
                        help="overwrite or remove files even if they were changed or not installed by us")
    parser.add_argument("--family", choices=sorted(MANAGERS), help="distribution family (default: detected)")
    parser.add_argument("--user", help="--uninstall: whose data to ask about (default: the sudo user)")
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--home", type=Path, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o022)                     # installed files and byte-code: never group/world-writable
    args = build_parser().parse_args(argv)
    args.root = args.root.resolve()
    system = args.root == Path("/")
    try:
        if system and os.geteuid() != 0:
            raise InstallError("run this as root (install.sh does that with sudo)")
        if args.family is None and system:
            try:
                args.family = detect_family(parse_os_release(Path("/etc/os-release").read_text()))
            except OSError:
                args.family = None
        pm = None
        if system and args.family is not None:
            pm = MANAGERS[args.family]()
        elif system and args.action != "uninstall" and not args.no_deps:
            raise InstallError("unknown distribution: install the dependencies listed in "
                               "packaging/deps.json yourself and pass --no-deps")
        layout = Layout(args.root, build.values())
        installer = Installer(args, layout, pm, _ask_tty)
        if args.action == "uninstall":
            return installer.uninstall()
        return installer.install(update=args.action == "update")
    except (InstallError, build.BuildError) as exc:
        print(f"install.sh: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("install.sh: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
