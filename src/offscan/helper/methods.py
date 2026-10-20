"""Helper methods exposed over the protocol.

| method | params | result |
|---|---|---|
| ``helper.info`` | – | version, capabilities, isolation status |
| ``helper.sandbox_check`` | – | proves sandbox privilege drop + no network |
| ``drives.list`` | ``probe``: none/cached/wait | ``{"disks": [...]}`` (events ``drives.probed``) |
| ``volume.probe`` | ``volume`` | OS / hibernation / fs state |
| ``volume.mount`` | ``volume``, ``keep`` | mount point and driver |
| ``volume.unmount`` | ``volume`` | – |
| ``volume.unlock`` | ``volume``, ``secret``, ``secret_kind``, ``keep`` | unlocked child volume |
| ``volume.lock`` | ``volume`` | – |
| ``volume.activate_lvm`` | ``volume``, ``keep`` | activated logical volumes |
| ``session.cleanup`` | ``include_kept`` | – |
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any

from .. import appinfo, privdrop, protocol, sandbox, selftest
from ..protocol import Param, RemoteError, Schema
from .server import Context, Server
from .volumes import VolumeError, VolumeManager

_KNAME = re.compile(r"^[A-Za-z0-9!._-]{1,64}$")


def _volume(value: str) -> bool:
    return bool(_KNAME.match(value))


VOLUME = Param(str, check=_volume)


def _wrap(exc: VolumeError) -> RemoteError:
    code = exc.code if exc.code in protocol.ERROR_CODES else protocol.FAILED
    return RemoteError(code, str(exc), exc.details)


def register(server: Server, manager: VolumeManager, isolated: bool) -> None:
    def info(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        report = selftest.collect()
        return {"version": appinfo.VERSION, "protocol": protocol.PROTOCOL_VERSION,
                "root": os.geteuid() == 0, "network_isolated": isolated,
                "invoking_user": (privdrop.invoking_user() or privdrop.nobody()).name,
                "tools": report["tools"], "kernel": report["kernel"], "modules": report["modules"]}

    def sandbox_check(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        with tempfile.TemporaryFile() as fh:
            fh.write(b"sandbox-ok")
            fh.flush()
            return sandbox.run("selftest.echo", {"x": 1}, fds=[fh.fileno()], timeout=60)

    def drives_list(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        try:
            disks = manager.describe()
            if p["probe"] == "wait":
                for disk in disks:
                    for vol in _flatten(disk["volumes"]):
                        ctx.check_cancelled()
                        if vol["role"] != "filesystem" or vol.get("os") is not None:
                            continue
                        result = manager.probe(vol["id"])
                        ctx.emit("drives.probed", {"volume": vol["id"], **result})
                disks = manager.describe()
            return {"disks": disks}
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def probe(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        try:
            return manager.probe(p["volume"])
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def mount(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        try:
            return manager.mount(p["volume"], keep=p["keep"])
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def unmount(ctx: Context, p: dict[str, Any]) -> None:
        try:
            manager.unmount(p["volume"])
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def unlock(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        try:
            result = manager.unlock(p["volume"], p["secret"], p["secret_kind"])
            if p["keep"]:
                manager.keep(p["volume"])
            return result
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def lock(ctx: Context, p: dict[str, Any]) -> None:
        try:
            manager.lock(p["volume"])
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def activate_lvm(ctx: Context, p: dict[str, Any]) -> dict[str, Any]:
        try:
            result = manager.activate_lvm(p["volume"])
            if p["keep"]:
                manager.keep(p["volume"])
            return result
        except VolumeError as exc:
            raise _wrap(exc) from exc

    def cleanup(ctx: Context, p: dict[str, Any]) -> None:
        try:
            manager.cleanup(include_kept=p["include_kept"])
        except VolumeError as exc:
            raise _wrap(exc) from exc

    keep = Param(bool, required=False, default=False)
    server.register("helper.info", Schema(), info)
    server.register("helper.sandbox_check", Schema(), sandbox_check)
    server.register("drives.list", Schema({"probe": Param(str, required=False, default="cached",
                                                          choices=("none", "cached", "wait"))}),
                    drives_list, exclusive=True)
    server.register("volume.probe", Schema({"volume": VOLUME}), probe, exclusive=True)
    server.register("volume.mount", Schema({"volume": VOLUME, "keep": keep}), mount, exclusive=True)
    server.register("volume.unmount", Schema({"volume": VOLUME}), unmount, exclusive=True)
    server.register("volume.unlock", Schema({
        "volume": VOLUME,
        "secret": Param(str, max_len=4096),
        "secret_kind": Param(str, required=False, default="passphrase",
                             choices=("passphrase", "recovery_key", "password")),
        "keep": keep}), unlock, exclusive=True)
    server.register("volume.lock", Schema({"volume": VOLUME}), lock, exclusive=True)
    server.register("volume.activate_lvm", Schema({"volume": VOLUME, "keep": keep}), activate_lvm,
                    exclusive=True)
    server.register("session.cleanup", Schema({"include_kept": keep}), cleanup, exclusive=True)


def _flatten(volumes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for vol in volumes:
        out.append(vol)
        out.extend(_flatten(vol.get("children", [])))
    return out
