"""User settings (JSON) and secrets (API keys, separate file, mode 0600)."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from . import log, paths

DEFAULTS: dict[str, Any] = {
    "sources": {},                 # source id -> {"enabled": bool, "accepted_license": bool, ...}
    "source_overrides": {},        # source id -> {"base_url": "..."} (mirrors, tests)
    "scan": {"mode": "quick", "engines": ["clamav", "yara", "hashes"], "max_file_size": 100 << 20,
             "max_scan_size": 400 << 20, "archive_depth": 17, "workers": 0, "detect_pua": False},
    "clamav_official": "auto",     # auto | system | private | off
    "bundle_include_restricted": True,
    "ui": {},
}

SECRET_KEYS = ("abusech_auth_key", "securiteinfo_id", "malshare_api_key", "github_token")


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _atomic_write(path: Path, data: str, mode: int) -> None:
    paths.ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class Settings:
    def __init__(self, path: Path | None = None, secrets_path: Path | None = None):
        self.path = path or paths.settings_file()
        self.secrets_path = secrets_path or self.path.with_name("secrets.json")
        self._lock = threading.Lock()
        self.data = self._load(self.path, DEFAULTS)
        self.secrets: dict[str, str] = {k: str(v) for k, v in self._load(self.secrets_path, {}).items()
                                        if k in SECRET_KEYS and v}
        for value in self.secrets.values():
            log.register_secret(value)

    @staticmethod
    def _load(path: Path, defaults: dict[str, Any]) -> dict[str, Any]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not an object")
        except FileNotFoundError:
            raw = {}
        except (OSError, ValueError) as exc:
            log.get("settings").warning("ignoring unreadable %s: %s", path, exc)
            raw = {}
        return _merge(defaults, raw)

    def save(self) -> None:
        with self._lock:
            _atomic_write(self.path, json.dumps(self.data, indent=1, sort_keys=True), 0o600)
            _atomic_write(self.secrets_path, json.dumps(self.secrets, indent=1, sort_keys=True), 0o600)

    # -- sources ------------------------------------------------------------

    def source(self, source_id: str) -> dict[str, Any]:
        return self.data["sources"].get(source_id, {})

    def source_enabled(self, source_id: str, default: bool) -> bool:
        value = self.source(source_id).get("enabled")
        return default if value is None else bool(value)

    def set_source(self, source_id: str, **values: Any) -> None:
        with self._lock:
            entry = dict(self.data["sources"].get(source_id, {}))
            entry.update(values)
            self.data["sources"][source_id] = entry

    def override(self, source_id: str) -> dict[str, Any]:
        return self.data.get("source_overrides", {}).get(source_id, {})

    # -- secrets ------------------------------------------------------------

    def secret(self, name: str) -> str | None:
        return self.secrets.get(name) or None

    def set_secret(self, name: str, value: str | None) -> None:
        if name not in SECRET_KEYS:
            raise KeyError(f"unknown secret {name!r}")
        with self._lock:
            if value:
                self.secrets[name] = value.strip()
                log.register_secret(value.strip())
            else:
                self.secrets.pop(name, None)
