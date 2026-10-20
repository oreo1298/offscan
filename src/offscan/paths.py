"""Filesystem locations, derived from :mod:`offscan.appinfo`.

Per-user data (definitions, history, reports, settings) follows the XDG
base directory specification.  Root-owned state (quarantine, the change
log) and runtime state (mount points) live under system directories.
Tests can redirect the system directories with environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import appinfo


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var, "")
    # The spec says relative paths must be ignored.
    if value and os.path.isabs(value):
        return Path(value)
    return Path.home() / fallback


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / appinfo.NAME


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / appinfo.NAME


def cache_dir() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache") / appinfo.NAME


def state_dir() -> Path:
    return _xdg("XDG_STATE_HOME", ".local/state") / appinfo.NAME


def settings_file() -> Path:
    return config_dir() / "settings.json"


def definitions_dir() -> Path:
    return data_dir() / "definitions"


def history_db() -> Path:
    return data_dir() / "history.sqlite3"


def reports_dir() -> Path:
    return data_dir() / "reports"


def log_dir() -> Path:
    return state_dir() / "log"


def _system(env_name: str, default: str) -> Path:
    value = os.environ.get(appinfo.env(env_name), "")
    return Path(value) if value and os.path.isabs(value) else Path(default)


def system_state_dir() -> Path:
    return _system("SYSTEM_STATE_DIR", appinfo.SYSTEM_STATE_DIR)


def runtime_dir() -> Path:
    return _system("RUNTIME_DIR", appinfo.RUNTIME_DIR)


def mount_root() -> Path:
    return runtime_dir() / "mnt"


def quarantine_dir() -> Path:
    return system_state_dir() / "quarantine"


def change_log() -> Path:
    return system_state_dir() / "changes.jsonl"


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create ``path`` (and parents) if missing; tighten the leaf's mode."""
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        if (path.stat().st_mode & 0o777) != mode:
            path.chmod(mode)
    except PermissionError:
        pass
    return path
