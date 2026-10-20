import re
import subprocess
import sys
from pathlib import Path

from offscan import appinfo, log, paths

ROOT = Path(__file__).resolve().parents[2]


def test_pyproject_matches_appinfo() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    assert re.search(rf'(?m)^name = "{re.escape(appinfo.NAME)}"$', text)
    assert re.search(rf'(?m)^{re.escape(appinfo.NAME)} = "offscan.cli.main:main"$', text)
    assert re.search(rf'(?m)^{re.escape(appinfo.GUI_NAME)} = "offscan.gui.app:main"$', text)


def test_name_is_not_hard_coded_elsewhere() -> None:
    """User-visible names and system paths must come from appinfo."""
    offenders = []
    allowed = {ROOT / "src" / "offscan" / "appinfo.py"}
    pattern = re.compile(r'["\'](/usr/lib/offscan|/run/offscan|/var/lib/offscan|/opt/offscan|'
                         r'io\.github\.oreo1298\.offscan|Offscan)\b')
    for path in (ROOT / "src").rglob("*.py"):
        if path in allowed:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


def test_derived_identifiers() -> None:
    assert appinfo.POLKIT_ACTION.startswith(appinfo.APP_ID)
    assert appinfo.HELPER_PATH.startswith(appinfo.LIB_DIR)
    assert appinfo.env("QT_API") == "OFFSCAN_QT_API"


def test_xdg_paths(xdg_home: Path) -> None:
    assert paths.config_dir() == xdg_home / "config" / appinfo.NAME
    assert paths.definitions_dir().is_relative_to(xdg_home / "data")
    assert paths.quarantine_dir().is_relative_to(xdg_home / "var-lib")
    assert paths.mount_root().is_relative_to(xdg_home / "run")


def test_relative_xdg_is_ignored(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert paths.data_dir() == tmp_path / ".local/share" / appinfo.NAME


def test_redaction() -> None:
    log.register_secret("SECRETKEY123")
    assert "SECRETKEY123" not in log.redact("GET /v2/files/exports/SECRETKEY123/x")


def test_cli_version_and_selftest() -> None:
    env_path = str(ROOT / "src")
    out = subprocess.run([sys.executable, "-m", "offscan", "--version"], capture_output=True,
                         text=True, env={"PYTHONPATH": env_path, "PATH": "/usr/bin:/bin"},
                         check=True)
    assert appinfo.VERSION in out.stdout
    out = subprocess.run([sys.executable, "-m", "offscan", "selftest", "--json"],
                         capture_output=True, text=True, check=True,
                         env={"PYTHONPATH": env_path, "PATH": "/usr/bin:/bin",
                              "HOME": "/tmp", "QT_QPA_PLATFORM": "offscreen"})
    assert '"python"' in out.stdout
