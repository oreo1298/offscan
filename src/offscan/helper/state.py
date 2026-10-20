"""Persistent record of everything the helper changed on the system.

Every protection or access layer (read-only flags, loop devices, dm
mappings, mounts) is appended here *before* it is used and removed after it
is torn down, so a crashed helper's leftovers can be cleaned up by the next
one, and volumes the user chose to keep mounted survive between CLI runs.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .. import paths


@dataclass
class Layer:
    kind: str                 # setro | unsetro | loop | crypt | dislocker | lvm | mount
    target: str               # device path, dm name, or mount point
    owner: str                # volume (kernel name) the layer was created for
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class State:
    layers: list[Layer] = field(default_factory=list)
    keep: set[str] = field(default_factory=set)
    parents: dict[str, str] = field(default_factory=dict)   # child kname -> parent kname

    def to_json(self) -> str:
        return json.dumps({"layers": [layer.to_dict() for layer in self.layers],
                           "keep": sorted(self.keep), "parents": self.parents,
                           "pid": os.getpid()}, indent=1)

    @classmethod
    def from_json(cls, text: str) -> State:
        data = json.loads(text)
        layers = [Layer(str(d["kind"]), str(d["target"]), str(d["owner"]), dict(d.get("extra") or {}))
                  for d in data.get("layers", []) if isinstance(d, dict)]
        return cls(layers, {str(k) for k in data.get("keep", [])},
                   {str(k): str(v) for k, v in (data.get("parents") or {}).items()})


class StateStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or paths.runtime_dir()
        self.path = self.directory / "state.json"
        self._lock_fd: int | None = None

    def acquire(self) -> bool:
        """Take the exclusive helper lock; False if another helper holds it."""
        paths.ensure_dir(self.directory, 0o755)
        fd = os.open(self.directory / "helper.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._lock_fd = fd
        return True

    def release(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def load(self) -> State:
        try:
            return State.from_json(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return State()
        except (ValueError, KeyError, TypeError):
            # Corrupt state: keep a copy for diagnosis and start empty.
            os.replace(self.path, self.path.with_suffix(".corrupt"))
            return State()

    def save(self, state: State) -> None:
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(state.to_json())
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        if not state.layers and not state.keep:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
