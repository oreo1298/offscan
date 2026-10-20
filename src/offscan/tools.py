"""Locating and running external programs safely.

All external commands are run without a shell, with an argument list, a
minimal fixed environment (``LC_ALL=C``, a fixed ``PATH``), closed file
descriptors and a timeout.  The privileged helper resolves programs only in
fixed system directories, never through the caller's ``PATH``.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence

SYSTEM_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
SAFE_PATH = ":".join(SYSTEM_DIRS)


class ToolError(Exception):
    def __init__(self, message: str, returncode: int | None = None,
                 stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def find(name: str, extra_dirs: Sequence[str] = (), use_path: bool = False) -> str | None:
    """Return the absolute path of executable ``name`` or ``None``."""
    if "/" in name:
        return name if os.access(name, os.X_OK) else None
    dirs = list(extra_dirs) + list(SYSTEM_DIRS)
    if use_path:
        dirs += [d for d in os.environ.get("PATH", "").split(":") if d and os.path.isabs(d)]
    for directory in dirs:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def require(name: str, extra_dirs: Sequence[str] = ()) -> str:
    path = find(name, extra_dirs)
    if path is None:
        raise ToolError(f"required program {name!r} is not installed")
    return path


def safe_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
    if extra:
        env.update(extra)
    return env


def run(args: Sequence[str], *, timeout: float = 120, input: bytes | None = None,
        check: bool = True, env: Mapping[str, str] | None = None,
        cwd: str | None = None, pass_fds: Sequence[int] = ()) -> subprocess.CompletedProcess[str]:
    """Run a command and capture text output (decoded with surrogateescape)."""
    if not args or not os.path.isabs(args[0]):
        raise ValueError("run() needs an absolute program path")
    try:
        proc = subprocess.run(
            list(args), input=input, capture_output=True, timeout=timeout,
            env=safe_env(env), cwd=cwd, close_fds=True, pass_fds=tuple(pass_fds),
            check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{os.path.basename(args[0])} timed out after {timeout}s") from exc
    except OSError as exc:
        raise ToolError(f"cannot run {args[0]}: {exc}") from exc
    out = proc.stdout.decode("utf-8", "surrogateescape")
    err = proc.stderr.decode("utf-8", "surrogateescape")
    result = subprocess.CompletedProcess(proc.args, proc.returncode, out, err)
    if check and proc.returncode != 0:
        raise ToolError(
            f"{os.path.basename(args[0])} failed with exit code {proc.returncode}: "
            f"{err.strip() or out.strip()}"[:2000],
            proc.returncode, out, err)
    return result


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)*)")


@functools.cache
def version(name: str, flag: str = "--version") -> str | None:
    """Best-effort version string of an installed tool."""
    path = find(name)
    if path is None:
        return None
    try:
        proc = run([path, flag], timeout=15, check=False)
    except ToolError:
        return None
    text = (proc.stdout or proc.stderr).strip().splitlines()
    if not text:
        return None
    match = _VERSION_RE.search(text[0])
    return match.group(1) if match else text[0][:80]


def is_root() -> bool:
    return os.geteuid() == 0


def which_any(*names: str) -> str | None:
    for name in names:
        path = find(name) or shutil.which(name)
        if path:
            return path
    return None
