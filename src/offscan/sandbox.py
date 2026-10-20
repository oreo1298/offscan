"""Run parsers of hostile data in an unprivileged, resource-limited child.

The root helper opens target files itself (safely, read-only) and hands
the file descriptors to a fresh Python process that runs as the invoking
user (or ``nobody``), with ``no_new_privs``, no network (inherited empty
namespace), memory/CPU/file-size limits and no core dumps.  The child gets
a task name from an allow-list, JSON arguments and the fds; it answers with
one JSON document on stdout.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from typing import Any

from . import privdrop

# task name -> "module:function" (only offscan modules are allowed)
TASKS: dict[str, str] = {
    "windows.version": "offscan.drives.osdetect:task_windows_version",
    "windows.persistence": "offscan.persistence.windows:task_persistence",
    "linux.persistence": "offscan.persistence.linux:task_persistence",
    "packages.list": "offscan.persistence.packages:task_list",
    "selftest.echo": "offscan.sandbox:task_echo",
}

DEFAULT_LIMITS = {"memory": 2 << 30, "cpu_seconds": 120, "file_size": 0, "open_files": 256}

# Per-task overrides: hive log replay writes a private temporary copy, and
# persistence tasks receive many descriptors (task XML, cron files, ...).
TASK_LIMITS: dict[str, dict[str, int]] = {
    "windows.version": {"file_size": 2 << 30},
    "windows.persistence": {"file_size": 2 << 30, "open_files": 8192, "cpu_seconds": 600},
    "linux.persistence": {"open_files": 8192, "cpu_seconds": 300},
    "packages.list": {"file_size": 2 << 30, "cpu_seconds": 600, "open_files": 1024},
}

_BOOT = (
    "import json,sys\n"
    "sys.path[:0]=json.loads(sys.argv[1])\n"
    "from offscan.sandbox import child_main\n"
    "child_main()\n"
)


class SandboxError(Exception):
    pass


def _package_paths() -> list[str]:
    import offscan
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(offscan.__file__)))
    out = [pkg_parent]
    # Vendored wheels (yara-x, regipy) live next to the installed package.
    from . import appinfo
    if os.path.isdir(appinfo.VENDOR_DIR):
        out.append(appinfo.VENDOR_DIR)
    for entry in sys.path:
        # Keep the interpreter's own site dirs only (they are implicit with -I);
        # add dev-venv site-packages so tests work from a checkout.
        if entry.endswith("site-packages") and entry.startswith(sys.prefix):
            out.append(entry)
    return out


def run(task: str, args: dict[str, Any] | None = None, fds: list[int] | None = None,
        timeout: float = 180, limits: dict[str, int | None] | None = None) -> Any:
    if task not in TASKS:
        raise SandboxError(f"unknown sandbox task {task!r}")
    fds = list(fds or [])
    ident = privdrop.worker_identity()
    limits = {**DEFAULT_LIMITS, **TASK_LIMITS.get(task, {}), **(limits or {})}
    request = json.dumps({"task": task, "args": args or {}, "fds": fds, "limits": limits}).encode()
    kwargs: dict[str, Any] = {}
    if ident is not None:
        kwargs.update(user=ident.uid, group=ident.gid, extra_groups=[])
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": ident.home if ident else "/",
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _BOOT, json.dumps(_package_paths())],
            input=request, capture_output=True, timeout=timeout, pass_fds=tuple(fds),
            env=env, cwd="/", check=False, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"sandbox task {task} timed out") from exc
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-5:]
        raise SandboxError(f"sandbox task {task} failed: {' | '.join(tail) or proc.returncode}")
    try:
        reply = json.loads(proc.stdout)
    except ValueError as exc:
        raise SandboxError(f"sandbox task {task} returned invalid output") from exc
    if not isinstance(reply, dict) or "ok" not in reply:
        raise SandboxError(f"sandbox task {task} returned a malformed reply")
    if not reply["ok"]:
        raise SandboxError(str(reply.get("error", "unknown error")))
    return reply.get("result")


def child_main() -> None:
    privdrop.set_no_new_privs()
    request = json.loads(sys.stdin.buffer.read())
    limits = request.get("limits") or {}
    privdrop.set_limits(**{k: v for k, v in limits.items() if k in DEFAULT_LIMITS})
    task = request.get("task")
    target = TASKS.get(task)
    out = sys.stdout
    if target is None or not target.startswith("offscan."):
        out.write(json.dumps({"ok": False, "error": "task not allowed"}))
        return
    module_name, func_name = target.split(":")
    try:
        func = getattr(importlib.import_module(module_name), func_name)
        result = func(request.get("args") or {}, [int(fd) for fd in request.get("fds") or []])
        out.write(json.dumps({"ok": True, "result": result}))
    except MemoryError:
        out.write(json.dumps({"ok": False, "error": "out of memory (limit reached)"}))
    except Exception as exc:
        out.write(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))


def task_echo(args: dict[str, Any], fds: list[int]) -> dict[str, Any]:
    data = [os.pread(fd, 64, 0).decode("latin-1") for fd in fds]
    return {"args": args, "data": data, "uid": os.getuid(),
            "no_network": privdrop.has_network_namespace_isolation()}
