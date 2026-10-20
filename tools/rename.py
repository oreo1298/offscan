#!/usr/bin/env python3
"""Propagate a rename done in src/offscan/appinfo.py to pyproject.toml.

Usage: edit NAME/DISPLAY_NAME/APP_ID/... in src/offscan/appinfo.py, then run
``python3 tools/rename.py``.  All other generated files (polkit policy,
desktop file, packages, install script) are rendered from appinfo at build
time, so nothing else needs changing.
"""

from __future__ import annotations

import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    info = runpy.run_path(str(ROOT / "src" / "offscan" / "appinfo.py"))
    pyproject = ROOT / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    new = re.sub(r'(?m)^name = "[^"]*"', f'name = "{info["NAME"]}"', text, count=1)
    new = re.sub(r'(?m)^description = "[^"]*"', f'description = "{info["SUMMARY"]}"', new, count=1)
    new = re.sub(r'(?m)^Homepage = "[^"]*"', f'Homepage = "{info["HOMEPAGE"]}"', new, count=1)
    for script, target in ((info["NAME"], "offscan.cli.main:main"),
                           (info["GUI_NAME"], "offscan.gui.app:main")):
        pattern = rf'(?m)^[\w-]+ = "{re.escape(target)}"'
        new = re.sub(pattern, f'{script} = "{target}"', new)
    if new != text:
        pyproject.write_text(new, encoding="utf-8")
        print("updated pyproject.toml")
    else:
        print("pyproject.toml already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
