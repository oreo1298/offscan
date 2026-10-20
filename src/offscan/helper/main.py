"""Entry point of the privileged helper."""

from __future__ import annotations

import argparse
import os
import signal
import sys

from .. import appinfo, log, privdrop, protocol, tools


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=appinfo.HELPER_NAME, description=(
        f"Privileged helper of {appinfo.DISPLAY_NAME}. It is started by the application "
        "and speaks a JSON-lines protocol on stdin/stdout; do not run it by hand."))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    privdrop.disable_core_dumps()
    privdrop.set_not_dumpable()
    tools.disable_env_tool_dirs()
    os.umask(0o022)

    # The protocol owns the original stdout; anything else printing to fd 1
    # (including child processes) goes to stderr instead.
    proto_out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr

    if os.geteuid() != 0 and not os.environ.get(appinfo.env("HELPER_UNPRIVILEGED")):
        proto_out.write(protocol.encode(protocol.hello(
            appinfo.VERSION, os.getpid(), ready=False, error="the helper must run as root")))
        return 2

    # Before any thread exists: give up network access for good.
    isolated = privdrop.unshare_network() if os.geteuid() == 0 else False

    log.setup("helper", verbose=args.verbose, to_file=False)
    logger = log.get("helper")

    from . import udev
    from .methods import register
    from .server import Server
    from .volumes import VolumeError, VolumeManager
    udev.install()

    manager = VolumeManager()
    try:
        manager.start()
    except VolumeError as exc:
        proto_out.write(protocol.encode(protocol.hello(
            appinfo.VERSION, os.getpid(), ready=False, error=str(exc), code=exc.code)))
        return 3

    server = Server(sys.stdin.buffer, proto_out)
    register(server, manager, isolated)

    def _terminate(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, _terminate)
    try:
        server.serve(ready=True, network_isolated=isolated)
    except KeyboardInterrupt:
        logger.info("terminating on signal")
        server.shutdown()
    finally:
        manager.stop()
    return 0
