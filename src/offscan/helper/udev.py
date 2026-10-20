"""Keep the host's udev, LVM and desktop automounters away from our devices.

A runtime udev rule (in /run, so it vanishes on reboot) marks every
device-mapper device whose name starts with our prefix so that:

* udisks neither shows nor auto-mounts it (``UDISKS_IGNORE``/``UDISKS_AUTO``);
* LVM does not auto-activate volume groups found inside an unlocked target
  volume, and other rules skip it (``DM_UDEV_DISABLE_OTHER_RULES_FLAG``).

Loop devices need no rule: LVM ignores PVs on loop devices by default and
udisks does not auto-mount loop devices it did not set up itself.
"""

from __future__ import annotations

import os

from .. import appinfo, log, tools

logger = log.get("helper.udev")

RULES_DIR = "/run/udev/rules.d"
# After 10-dm.rules (which sets DM_NAME), before 13-dm-disk, 69-lvm and 80-udisks2.
RULE_FILE = f"12-{appinfo.NAME}-ignore.rules"


def rule_text() -> str:
    prefix = appinfo.DEVICE_PREFIX
    return (
        f"# Written by {appinfo.HELPER_NAME}: target volumes opened for scanning must not be\n"
        "# auto-activated or auto-mounted by the host.\n"
        f'SUBSYSTEM=="block", KERNEL=="dm-*", ENV{{DM_NAME}}=="{prefix}*", '
        'ENV{DM_UDEV_DISABLE_OTHER_RULES_FLAG}="1", ENV{UDISKS_IGNORE}="1", '
        'ENV{UDISKS_AUTO}="0", ENV{UDISKS_PRESENTATION_HIDE}="1"\n'
    )


def install(rules_dir: str = RULES_DIR) -> bool:
    path = os.path.join(rules_dir, RULE_FILE)
    try:
        os.makedirs(rules_dir, mode=0o755, exist_ok=True)
        text = rule_text()
        try:
            with open(path, encoding="utf-8") as fh:
                if fh.read() == text:
                    return True
        except FileNotFoundError:
            pass
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("cannot install udev rule %s: %s", path, exc)
        return False
    udevadm = tools.find("udevadm")
    if udevadm:
        tools.run([udevadm, "control", "--reload"], timeout=30, check=False)
    return True
