"""Packaging: versions, the staged tree, nfpm/PKGBUILD output, scripts and install.sh."""

from __future__ import annotations

import gzip
import itertools
import json
import os
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from offscan import appinfo

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

import build  # noqa: E402
import installer  # noqa: E402
import render  # noqa: E402

assert Path(build.__file__).resolve() == ROOT / "packaging" / "build.py"

EPOCH = 1_700_000_000
VERSIONS = ["0.1.0.dev0", "0.1.0.dev1", "0.1.0rc1", "0.1.0", "0.1.0.post1", "0.1.1", "0.2.0"]


# ------------------------------------------------------------------ versions

@pytest.mark.parametrize(("version", "deb", "pacman"), [
    ("0.1.0.dev0", "0.1.0~dev0", "0.1.0dev0"),
    ("1.2.3rc2", "1.2.3~rc2", "1.2.3rc2"),
    ("1.2.3", "1.2.3", "1.2.3"),
    ("1.2.3.post1", "1.2.3.post1", "1.2.3.post1"),
])
def test_package_versions(version: str, deb: str, pacman: str) -> None:
    assert build.package_version(version, "deb") == deb
    assert build.package_version(version, "rpm") == deb
    assert build.package_version(version, "pacman") == pacman


def test_unsupported_versions_are_refused() -> None:
    for bad in ("1.0a1.dev0", "1.0-1", "v1.0", "1.0+local"):
        with pytest.raises(build.BuildError):
            build.package_version(bad, "deb")


def test_next_version() -> None:
    assert build.next_version("0.1.0.dev0") == "0.1.0.dev1"
    assert build.next_version("1.2.3rc1") == "1.2.3rc2"
    assert build.next_version("1.2.3") == "1.2.4"


def _compare(tool: str, a: str, b: str) -> int:
    if tool == "dpkg":
        lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b], check=False).returncode == 0
        return -1 if lt else 1
    if tool == "rpm":
        out = subprocess.run(["rpm", "--eval", f'%{{lua: print(rpm.vercmp("{a}", "{b}"))}}'],
                             capture_output=True, text=True, check=True)
        return int(out.stdout.strip())
    out = subprocess.run(["vercmp", a, b], capture_output=True, text=True, check=True)
    return int(out.stdout.strip())


@pytest.mark.parametrize(("tool", "fmt"), [("dpkg", "deb"), ("rpm", "rpm"), ("vercmp", "pacman")])
def test_versions_sort_like_pep440(tool: str, fmt: str) -> None:
    if not shutil.which(tool):
        pytest.skip(f"{tool} is not installed")
    mapped = [build.package_version(v, fmt) for v in VERSIONS]
    for older, newer in itertools.pairwise(mapped):
        assert _compare(tool, older, newer) < 0, (older, newer)


# ------------------------------------------------------------------ staging

def fake_wheels(directory: Path) -> dict[str, Path]:
    """Tiny stand-ins for the vendored wheels (the real ones come from PyPI)."""
    directory.mkdir(parents=True, exist_ok=True)
    wheels = {}
    for pkg in build.lock_packages():
        module = pkg["name"].replace("-", "_")
        path = directory / f"{module}-{pkg['version']}-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(f"{module}/__init__.py", "VALUE = 1\n")
            zf.writestr(f"{module}-{pkg['version']}.dist-info/METADATA", f"Name: {pkg['name']}\n")
            if not pkg.get("license_files"):
                zf.writestr(f"{module}-{pkg['version']}.dist-info/LICENSE", "licence text\n")
        wheels[pkg["name"]] = path
    return wheels


@pytest.fixture(scope="module")
def staged(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, list]]:
    base = tmp_path_factory.mktemp("stage")
    wheels = fake_wheels(base / "wheels")
    info = build.values(EPOCH)
    out = {}
    for flavor in ("manual", "deb"):
        dest = base / flavor
        out[flavor] = (dest, build.stage(dest, flavor, "x86_64", wheels, info, EPOCH))
    return out


def test_stage_layout(staged: dict) -> None:
    dest, entries = staged["manual"]
    files = {e.path: e.mode for e in entries if e.kind == "file"}
    for launcher, module in ((f"/usr/bin/{appinfo.NAME}", "offscan.cli.main"),
                             (f"/usr/bin/{appinfo.GUI_NAME}", "offscan.gui.app"),
                             (appinfo.HELPER_PATH, "offscan.helper.main")):
        assert files[launcher] == 0o755
        text = (dest / launcher.lstrip("/")).read_text()
        assert text.startswith("#!/usr/bin/python3 -I\n")
        assert repr(appinfo.PYTHON_DIR) in text and repr(appinfo.VENDOR_DIR) in text
        assert f"from {module} import main" in text
        compile(text, launcher, "exec")
    # The vendored packages come after the standard library and before site-packages.
    probe = (dest / appinfo.HELPER_PATH.lstrip("/")).read_text().split("\nfrom ", 1)[0]
    probe += "\nimport json; print(json.dumps(sys.path))\n"
    out = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True)
    path = json.loads(out.stdout)
    assert path[0] == appinfo.PYTHON_DIR
    vendor = path.index(appinfo.VENDOR_DIR)
    version = f"python{sys.version_info[0]}.{sys.version_info[1]}"
    stdlib = next(i for i, p in enumerate(path) if p.endswith(version))
    assert stdlib < vendor
    assert all(not p.endswith("-packages") for p in path[:vendor])
    sources = {p.relative_to(ROOT / "src").as_posix() for p in build.tracked_files("src/offscan")
               if p.suffix == ".py"}
    staged_sources = {p.removeprefix(appinfo.PYTHON_DIR + "/") for p in files if p.endswith(".py")
                      and p.startswith(appinfo.PYTHON_DIR)}
    assert sources <= staged_sources
    assert not [p for p in files if "__pycache__" in p or p.endswith(".pyc")]
    for path, mode in files.items():
        target = dest / path.lstrip("/")
        assert target.stat().st_mtime == EPOCH, path
        assert (target.stat().st_mode & 0o7777) == mode, path
        assert mode in (0o644, 0o755)
    for pkg in build.lock_packages():
        assert any(p.startswith(f"/usr/share/licenses/{appinfo.NAME}/vendor/{pkg['name']}/") for p in files)
    notice = (dest / f"usr/share/doc/{appinfo.NAME}/THIRD-PARTY.md").read_text()
    assert all(pkg["name"] in notice for pkg in build.lock_packages())


def test_staged_directories_are_only_our_own(staged: dict) -> None:
    _dest, entries = staged["manual"]
    roots = build.owned_roots(build.values(EPOCH))
    dirs = [e.path for e in entries if e.kind == "dir"]
    assert appinfo.LIB_DIR in dirs
    for directory in dirs:
        assert any(directory == r or directory.startswith(r + "/") for r in roots), directory
    for shared in ("/usr", "/usr/bin", "/usr/share", "/usr/share/applications", "/usr/lib"):
        assert shared not in dirs


def test_staged_metadata_files(staged: dict) -> None:
    dest, _entries = staged["manual"]
    policy = ET.parse(dest / f"usr/share/polkit-1/actions/{appinfo.APP_ID}.policy").getroot()
    action = policy.find("action")
    assert action.get("id") == appinfo.POLKIT_ACTION
    annotations = {a.get("key"): a.text for a in action.findall("annotate")}
    assert annotations["org.freedesktop.policykit.exec.path"] == appinfo.HELPER_PATH
    assert action.find("defaults/allow_active").text == "auth_admin_keep"
    meta = ET.parse(dest / f"usr/share/metainfo/{appinfo.APP_ID}.metainfo.xml").getroot()
    assert meta.find("id").text == appinfo.APP_ID
    assert meta.find("launchable").text == appinfo.DESKTOP_FILE
    for image in meta.iter("image"):
        assert (ROOT / "docs" / "screenshots" / image.text.rsplit("/", 1)[1]).is_file()
    desktop = (dest / f"usr/share/applications/{appinfo.DESKTOP_FILE}").read_text()
    assert f"\nExec={appinfo.GUI_NAME}\n" in desktop and f"\nIcon={appinfo.ICON_NAME}\n" in desktop
    for page in (appinfo.NAME, appinfo.GUI_NAME):
        text = gzip.decompress((dest / f"usr/share/man/man1/{page}.1.gz").read_bytes()).decode()
        assert text.startswith(f".TH {page.upper()} 1 ")


def test_man_page_lists_every_command() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    import manpage

    from offscan.cli.main import build_parser
    page = manpage.cli_page()
    commands = next(a for a in build_parser()._actions if a.__class__.__name__ == "_SubParsersAction")
    for name in commands.choices:
        assert f'.SS "{appinfo.NAME} {manpage.esc(name)}"' in page
    assert manpage.esc(".hidden\n'quote") == "\\&.hidden\n\\&'quote"


def test_deb_flavor_has_copyright_and_no_licence_dir(staged: dict) -> None:
    dest, entries = staged["deb"]
    paths = {e.path for e in entries}
    assert f"/usr/share/doc/{appinfo.NAME}/copyright" in paths
    assert not [p for p in paths if p.startswith("/usr/share/licenses/")]
    copyright_text = (dest / f"usr/share/doc/{appinfo.NAME}/copyright").read_text()
    assert copyright_text.startswith("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/")
    assert all(f"\nLicense: {lic}\n" in copyright_text for lic in ("GPL-3.0-or-later", "BSD-3-Clause", "MIT"))


def _wheel(tmp_path: Path, members: dict[str, bytes], symlink: str | None = None) -> Path:
    path = tmp_path / "bad-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
    return path


@pytest.mark.parametrize("members", [
    {"../escape.py": b""}, {"/abs.py": b""}, {"pkg-1.data/scripts/run": b""},
])
def test_unsafe_wheels_are_refused(tmp_path: Path, members: dict) -> None:
    tree = build.Tree(tmp_path / "dest", EPOCH)
    with pytest.raises(build.BuildError):
        build.unpack_wheel(tree, _wheel(tmp_path, members), appinfo.VENDOR_DIR)


def test_symlinks_in_wheels_are_refused(tmp_path: Path) -> None:
    tree = build.Tree(tmp_path / "dest", EPOCH)
    with pytest.raises(build.BuildError, match="symbolic link"):
        build.unpack_wheel(tree, _wheel(tmp_path, {}, symlink="pkg/link"), appinfo.VENDOR_DIR)


def test_wheels_are_checked_against_the_lock(tmp_path: Path) -> None:
    with pytest.raises(build.BuildError, match="is not in"):
        build.find_wheels("x86_64", tmp_path)
    _pkg, entry = build.wheel_entries("x86_64")[0]
    (tmp_path / entry["file"]).write_bytes(b"not the real wheel")
    with pytest.raises(build.BuildError, match="does not match"):
        build.find_wheels("x86_64", tmp_path)


def test_lock_file_is_complete() -> None:
    for pkg in build.lock_packages():
        assert pkg["license"] and pkg["homepage"].startswith("https://")
        for arch in ("x86_64", "aarch64"):
            entry = pkg["files"].get(arch) or pkg["files"]["any"]
            assert len(entry["sha256"]) == 64 and entry["url"].startswith("https://")
            assert entry["url"].endswith("/" + entry["file"])
        for extra in pkg.get("license_files", []):
            assert (ROOT / "packaging" / extra).is_file()


# --------------------------------------------------------------------- nfpm

def test_nfpm_config(staged: dict, tmp_path: Path) -> None:
    info = build.values(EPOCH)
    scripts = build.render_scripts(tmp_path / "scripts", info)
    for target, dest_key in (("deb", "deb"), ("fedora", "manual"), ("opensuse", "manual")):
        dest, entries = staged[dest_key]
        config = build.nfpm_config(dest, entries, target, "x86_64", info, scripts, EPOCH)
        assert config["name"] == appinfo.NAME and config["arch"] == "amd64"
        fmt = "deb" if target == "deb" else "rpm"
        assert config["version"] == build.package_version(appinfo.VERSION, fmt)
        for item in config["contents"]:
            if item.get("type") != "dir":
                assert Path(item["src"]).is_file()
        joined = " ".join(config["depends"])
        if target == "deb":
            assert "python3-pyside6.qtwidgets | python3-pyqt6" in joined and " or " not in joined
        else:
            assert "(python3-pyside6 or " in joined and "|" not in joined
        assert set(config["scripts"]) == {"preinstall", "postinstall", "preremove", "postremove"}
    assert build.package_file_name("deb", "aarch64", info).endswith("_arm64.deb")


def _script(directory: Path, name: str, **overrides: str) -> Path:
    """Render one maintainer script into ``directory`` (paths overridden for the test)."""
    values = {**build.values(EPOCH), **overrides}
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.sh"
    path.write_text(render.render(f"scripts/{name}.sh.in", values))
    return path


def test_maintainer_scripts(tmp_path: Path) -> None:
    lib = tmp_path / "lib"
    state = tmp_path / "state"
    cache = lib / "python" / "pkg" / "__pycache__"
    for name in ("preinstall", "postinstall", "preremove", "postremove"):
        script = _script(tmp_path / "syntax", name)       # rendered, never run
        assert subprocess.run(["sh", "-n", str(script)], check=False).returncode == 0
    preremove = _script(tmp_path / "run", "preremove", LIB_DIR=str(lib))
    for arg, survives in (("1", True), ("2", True), ("upgrade", False), ("0", False), ("", False)):
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "m.cpython-313.pyc").write_bytes(b"")
        subprocess.run(["sh", str(preremove), *([arg] if arg else [])], check=True)
        assert cache.exists() == survives, arg
    preinstall = _script(tmp_path / "run", "preinstall", SYSTEM_STATE_DIR=str(state))
    assert subprocess.run(["sh", str(preinstall), "install"], check=False).returncode == 0
    state.mkdir()
    (state / "install-manifest.json").write_text("{}")
    result = subprocess.run(["sh", str(preinstall), "install"], capture_output=True, text=True, check=False)
    assert result.returncode == 1 and "install.sh --uninstall" in result.stderr
    postremove = _script(tmp_path / "run", "postremove", SYSTEM_STATE_DIR=str(state))
    result = subprocess.run(["sh", str(postremove), "purge"], capture_output=True, text=True, check=True)
    assert f"Kept {state}" in result.stderr
    result = subprocess.run(["sh", str(postremove), "remove"], capture_output=True, text=True, check=True)
    assert result.stderr == ""


def test_unknown_placeholder_is_an_error() -> None:
    with pytest.raises(KeyError):
        render.substitute_at("@NOT_A_VALUE@", {})


# ----------------------------------------------------------------- PKGBUILD

def test_pkgbuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(EPOCH))
    tarball = build.write_tarball(tmp_path / "dist")
    out = tmp_path / "arch"
    build.write_pkgbuild(out, tarball, None)
    pkgbuild = (out / "PKGBUILD").read_text()
    assert subprocess.run(["bash", "-n", str(out / "PKGBUILD")], check=False).returncode == 0
    assert f"pkgver={build.package_version(appinfo.VERSION, 'pacman')}\n" in pkgbuild
    assert build.sha256_file(tarball) in pkgbuild
    for pkg in build.lock_packages():
        for entry in pkg["files"].values():
            assert entry["sha256"] in pkgbuild and entry["file"] in pkgbuild
    srcinfo = (out / ".SRCINFO").read_text()
    assert srcinfo.startswith(f"pkgbase = {appinfo.NAME}\n")
    assert srcinfo.endswith(f"pkgname = {appinfo.NAME}\n")
    assert (out / f"{appinfo.NAME}.install").is_file() and (out / tarball.name).is_file()
    if shutil.which("makepkg") and os.geteuid() != 0:
        result = subprocess.run(["makepkg", "--printsrcinfo"], cwd=out, capture_output=True, text=True,
                                check=True)
        assert result.stdout == srcinfo


def test_no_git_in_a_checkout_of_another_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """sudo ./install.sh must not run git (and its hooks or config) in the user's checkout."""
    calls = []
    real_run = subprocess.run

    def run(argv, **kwargs):
        calls.append(argv)
        return real_run(argv, **kwargs)

    monkeypatch.setattr(build.subprocess, "run", run)
    monkeypatch.setattr(build.os, "geteuid", lambda: os.getuid() + 12345)
    files = build.tracked_files("src/offscan")
    assert not [c for c in calls if "git" in str(c[0])]
    assert ROOT / "src" / "offscan" / "appinfo.py" in files
    assert not [f for f in files if "__pycache__" in f.parts]


def test_tarball_is_reproducible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(EPOCH))
    first = build.write_tarball(tmp_path / "a")
    second = build.write_tarball(tmp_path / "b")
    assert build.sha256_file(first) == build.sha256_file(second)
    with tarfile.open(first) as tar:
        names = tar.getnames()
        prefix = f"{appinfo.NAME}-{appinfo.VERSION}/"
        assert all(n.startswith(prefix) for n in names)
        assert prefix + "install.sh" in names and prefix + "packaging/build.py" in names
        assert tar.getmember(prefix + "install.sh").mode == 0o755
        assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")]


# ---------------------------------------------------------------- installer

@pytest.mark.parametrize(("os_release", "family"), [
    ('ID=ubuntu\nID_LIKE=debian\n', "deb"),
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\n', "deb"),
    ('ID=debian\n', "deb"),
    ('ID=fedora\n', "fedora"),
    ('ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', "opensuse"),
    ('ID="opensuse-leap"\nID_LIKE="suse opensuse"\n', "opensuse"),
    ('ID=arch\n', "arch"),
    ('ID=manjaro\nID_LIKE=arch\n', "arch"),
    ('ID=endeavouros\nID_LIKE=arch\n', "arch"),
    ('ID=gentoo\n', None),
])
def test_detect_family(os_release: str, family: str | None) -> None:
    assert installer.detect_family(installer.parse_os_release(os_release)) == family


class FakePM(installer.PackageManager):
    tool = "fake"

    def __init__(self, installed: set[str], available: set[str]):
        super().__init__(run=lambda argv: subprocess.CompletedProcess(argv, 1, "", ""))
        self._installed = installed
        self._available = available

    def installed(self, name: str) -> bool:
        return name in self._installed

    def available(self, name: str) -> bool:
        return name in self._available


def test_plan_dependencies() -> None:
    deps = {"depends": [["python3 (>= 3.11)"], ["pyside", "pyqt"], ["clamav"], ["gone"]],
            "recommends": [["ntfs-3g"], ["nowhere"]],
            "optdepends": [["dislocker", "BitLocker"]]}
    pm = FakePM(installed={"python3"}, available={"pyqt", "clamav", "ntfs-3g"})
    plan = installer.plan_dependencies(pm, deps)
    assert plan.install == ["pyqt", "clamav", "ntfs-3g"]
    assert plan.missing == [["gone"]]
    assert plan.optional == ["nowhere", "dislocker (BitLocker)"]


def test_apt_queries() -> None:
    calls = []

    def run(argv):
        calls.append(list(argv))
        if argv[0] == "dpkg-query":
            return subprocess.CompletedProcess(argv, 0, "ii " if argv[-1] == "python3" else "un ", "")
        return subprocess.CompletedProcess(argv, 0, "Package: x\n", "")

    apt = installer.Apt(run)
    assert apt.installed("python3") and not apt.installed("clamav")
    apt.refresh()
    apt.refresh()
    assert calls.count(["apt-get", "update", "-q"]) == 1
    assert apt.install_command(["a"], yes=True) == ["apt-get", "install", "-y", "a"]


def _args(tmp_path: Path, *extra: str):
    argv = ["--root", str(tmp_path / "root"), "--home", str(tmp_path / "home"), "--no-vendor", *extra]
    return installer.build_parser().parse_args(argv)


def _run(tmp_path: Path, *argv: str, answers: dict[str, bool] | None = None) -> tuple[int, list[str]]:
    args = _args(tmp_path, *argv)
    args.root = args.root.resolve()
    layout = installer.Layout(args.root, build.values())
    output: list[str] = []
    asked: list[str] = []

    def ask(question: str) -> bool:
        asked.append(question)
        for key, value in (answers or {}).items():
            if key in question:
                return value
        return False

    inst = installer.Installer(args, layout, None, ask, out=output.append)
    code = inst.uninstall() if args.action == "uninstall" else inst.install(args.action == "update")
    return code, output + [f"ASKED {q}" for q in asked]


@pytest.fixture(scope="module")
def stage_cache(tmp_path_factory: pytest.TempPathFactory):
    """Stage once; installs in this module copy the result (staging is slow-ish)."""
    base = tmp_path_factory.mktemp("installer-stage")
    real = build.stage
    cache: dict = {}

    def cached(dest, flavor, arch, wheels, info=None, epoch=None):
        key = (flavor, info["VERSION"] if info else None)
        if key not in cache:
            where = base / str(len(cache))
            cache[key] = (where, real(where, flavor, arch, wheels, info, epoch))
        shutil.copytree(cache[key][0], dest, symlinks=True)
        return cache[key][1]
    return cached


@pytest.fixture
def quick_stage(monkeypatch: pytest.MonkeyPatch, stage_cache) -> None:
    monkeypatch.setattr(build, "stage", stage_cache)
    monkeypatch.setattr(build, "compile_tree", lambda *a, **k: True)


def test_install_update_uninstall(tmp_path: Path, quick_stage: None) -> None:
    root = tmp_path / "root"
    (root / "usr" / "bin").mkdir(parents=True)          # shared directories that already exist
    (root / "var" / "lib").mkdir(parents=True)
    code, _out = _run(tmp_path, "--install", "--yes")
    assert code == 0
    manifest = json.loads((root / appinfo.SYSTEM_STATE_DIR.lstrip("/") / "install-manifest.json").read_text())
    assert manifest["version"] == appinfo.VERSION
    cli = root / "usr" / "bin" / appinfo.NAME
    assert cli.is_file() and (cli.stat().st_mode & 0o777) == 0o755
    assert "/usr/bin" not in manifest["dirs"] and appinfo.LIB_DIR in manifest["dirs"]
    assert (root / appinfo.SYSTEM_STATE_DIR.lstrip("/")).stat().st_mode & 0o777 == 0o700

    # a second --install refuses; --update replaces changed files and drops stale ones
    with pytest.raises(installer.InstallError, match="already installed"):
        _run(tmp_path, "--install", "--yes")
    cli.write_text("changed\n")
    stale = root / appinfo.LIB_DIR.lstrip("/") / "old-module.py"
    stale.write_text("old\n")
    manifest["files"][f"{appinfo.LIB_DIR}/old-module.py"] = {"sha256": build.sha256_file(stale),
                                                              "mode": 0o644}
    (root / appinfo.SYSTEM_STATE_DIR.lstrip("/") / "install-manifest.json").write_text(json.dumps(manifest))
    assert _run(tmp_path, "--update", "--yes")[0] == 0
    assert cli.read_text().startswith("#!/usr/bin/python3")
    assert not stale.exists()

    # a file changed after installation is kept on uninstall; everything else goes
    doc = root / f"usr/share/doc/{appinfo.NAME}/README.md"
    doc.write_text("my notes\n")
    code, out = _run(tmp_path, "--uninstall", "--yes")
    assert code == 0
    assert any("Kept /usr/share/doc" in line for line in out)
    assert doc.exists() and not cli.exists()
    assert not (root / appinfo.LIB_DIR.lstrip("/")).exists()
    assert (root / "usr" / "bin").is_dir()                # not ours: stays
    left = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    assert left == ["usr", "usr/bin", "usr/share", "usr/share/doc", f"usr/share/doc/{appinfo.NAME}",
                    f"usr/share/doc/{appinfo.NAME}/README.md", "var", "var/lib"]


def test_uninstall_asks_about_each_kind_of_data(tmp_path: Path, quick_stage: None) -> None:
    assert _run(tmp_path, "--install", "--yes")[0] == 0
    state = tmp_path / "root" / appinfo.SYSTEM_STATE_DIR.lstrip("/")
    data = tmp_path / "home" / ".local" / "share" / appinfo.NAME
    (state / "quarantine" / "entry").mkdir(parents=True)
    (state / "changes.jsonl").write_text("{}\n")
    (data / "definitions").mkdir(parents=True)
    (data / "reports").mkdir()
    (data / "history.sqlite3").write_text("")
    code, out = _run(tmp_path, "--uninstall", answers={"Remove": True, "quarantine": False,
                                                       "change": False, "definitions": True,
                                                       "history": True})
    assert code == 0
    questions = [line for line in out if line.startswith("ASKED")]
    assert len(questions) == 5                            # remove + 4 kinds of data that exist
    assert (state / "quarantine" / "entry").is_dir() and (state / "changes.jsonl").is_file()
    assert not data.exists()
    assert not (state / "install-manifest.json").exists()


def test_purge_and_keep_data(tmp_path: Path, quick_stage: None) -> None:
    state = tmp_path / "root" / appinfo.SYSTEM_STATE_DIR.lstrip("/")
    definitions = tmp_path / "home" / ".local" / "share" / appinfo.NAME / "definitions"
    for flag, kept in (("--keep-data", True), ("--purge", False)):
        assert _run(tmp_path, "--install", "--yes")[0] == 0
        (state / "quarantine" / "entry").mkdir(parents=True, exist_ok=True)
        definitions.mkdir(parents=True, exist_ok=True)
        code, out = _run(tmp_path, "--uninstall", "--yes", flag)
        assert code == 0 and not [line for line in out if line.startswith("ASKED")]
        assert (state / "quarantine").exists() == kept
        assert definitions.exists() == kept
    assert not state.exists()


def test_data_removal_does_not_follow_links_out_of_home(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "definitions").mkdir(parents=True)
    (outside / "definitions" / "important").write_text("keep me")
    home = tmp_path / "home"
    (home / ".local" / "share").mkdir(parents=True)
    (home / ".local" / "share" / appinfo.NAME).symlink_to(outside)
    target = home / ".local" / "share" / appinfo.NAME / "definitions"
    with pytest.raises(installer.InstallError, match="refusing"):
        installer._remove_data(target, home, as_owner=True)
    assert (outside / "definitions" / "important").exists()
    # a link to a directory is removed itself, never what it points to
    link = home / "linked"
    link.symlink_to(outside)
    installer._remove_data(link, home, as_owner=True)
    assert not link.is_symlink() and (outside / "definitions" / "important").exists()


def test_home_data_may_not_point_into_the_system_state(tmp_path: Path) -> None:
    """A user linking ~/.local/share/<name> to /var/lib/<name> must not get root to delete there."""
    state = tmp_path / "root" / appinfo.SYSTEM_STATE_DIR.lstrip("/")
    (state / "definitions").mkdir(parents=True)
    home = tmp_path / "home"
    (home / ".local" / "share").mkdir(parents=True)
    (home / ".local" / "share" / appinfo.NAME).symlink_to(state)
    layout = installer.Layout(tmp_path / "root", build.values())
    for item in installer.data_items(layout, home):
        for path in item.present():
            with pytest.raises(installer.InstallError):
                installer._remove_data(path, item.base, as_owner=item.home)
    assert (state / "definitions").is_dir()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to drop to another user")
def test_home_data_is_deleted_with_the_owners_rights() -> None:
    import pwd
    import tempfile
    nobody = pwd.getpwnam("nobody")
    base = Path(tempfile.mkdtemp(dir="/var/tmp"))      # pytest's tmp_path is root-only
    os.chmod(base, 0o755)
    try:
        _owner_rights(base / "home", nobody)
    finally:
        shutil.rmtree(base)


def _owner_rights(home: Path, nobody) -> None:
    data = home / ".local" / "share" / appinfo.NAME / "definitions"
    data.mkdir(parents=True)
    (data / "mine").write_text("x")
    for directory in (home, home / ".local", home / ".local" / "share", data.parent, data):
        os.chown(directory, nobody.pw_uid, nobody.pw_gid)
    os.chown(data / "mine", nobody.pw_uid, nobody.pw_gid)
    rootowned = data / "rootowned"            # stands for something only root may delete
    rootowned.mkdir()
    (rootowned / "file").write_text("x")
    with pytest.raises(installer.InstallError, match="could not delete"):
        installer._remove_data(data, home, as_owner=True)
    assert (rootowned / "file").exists()
    rootowned.joinpath("file").unlink()
    rootowned.rmdir()
    installer._remove_data(data, home, as_owner=True)
    assert not data.exists()


def test_wheels_are_checked_on_a_private_copy(tmp_path: Path) -> None:
    _pkg, entry = build.wheel_entries("x86_64")[0]
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / entry["file"]).write_bytes(b"x")
    with pytest.raises(build.BuildError, match="does not match"):
        build.find_wheels("x86_64", shared, copy_to=tmp_path / "private")
    assert (tmp_path / "private" / entry["file"]).is_file()


def test_existing_files_are_not_overwritten(tmp_path: Path, quick_stage: None) -> None:
    target = tmp_path / "root" / "usr" / "bin" / appinfo.NAME
    target.parent.mkdir(parents=True)
    target.write_text("someone else's program\n")
    with pytest.raises(installer.InstallError, match=r"were not installed by install\.sh"):
        _run(tmp_path, "--install", "--yes")
    assert target.read_text() == "someone else's program\n"
    assert _run(tmp_path, "--install", "--yes", "--force")[0] == 0
    assert target.read_text().startswith("#!/usr/bin/python3")


def test_uninstall_without_installation(tmp_path: Path) -> None:
    with pytest.raises(installer.InstallError, match="no installation"):
        _run(tmp_path, "--uninstall", "--yes")


def test_installer_cli_reports_errors(tmp_path: Path) -> None:
    code = installer.main(["--uninstall", "--yes", "--root", str(tmp_path), "--home", str(tmp_path)])
    assert code == 2


# ----------------------------------------------------------------- install.sh

def test_install_sh_syntax_and_help() -> None:
    script = ROOT / "install.sh"
    assert os.access(script, os.X_OK)
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0
    out = subprocess.run([str(script), "--help"], capture_output=True, text=True, check=True)
    for flag in ("--install", "--update", "--uninstall", "--purge", "--keep-data", "--offline"):
        assert flag in out.stdout
    for test_script in (ROOT / "tests" / "packaging").glob("*.sh"):
        assert subprocess.run(["bash", "-n", str(test_script)], check=False).returncode == 0
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", str(script), *map(str, (ROOT / "tests" / "packaging").glob("*.sh"))],
                       check=True)


def test_build_cli_version() -> None:
    out = subprocess.run([sys.executable, "-I", str(ROOT / "packaging" / "build.py"), "version", "deb"],
                         capture_output=True, text=True, check=True)
    assert out.stdout.strip() == build.package_version(appinfo.VERSION, "deb")


def test_release_notes_come_from_the_changelog(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## 0.2.0\n\nNew.\n\n## 0.1.0\n\nFirst release.\n\n* a\n")
    assert build.release_notes("0.1.0", changelog) == "First release.\n\n* a\n"
    assert build.release_notes("0.2.0", changelog) == "New.\n"
    with pytest.raises(build.BuildError):
        build.release_notes("9.9.9", changelog)
    # the real changelog has a section for every released version it mentions
    assert build.release_notes("0.1.0").startswith("First release.")
