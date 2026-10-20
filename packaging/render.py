#!/usr/bin/env python3
"""Render packaging templates from src/offscan/appinfo.py.

Every ``${NAME}``-style placeholder in ``packaging/templates/*.in`` is
replaced by the attribute of the same name in appinfo, so renaming the
application only ever means editing appinfo.py.  Shell templates
(``*.sh.in``, ``PKGBUILD.in``, ``pacman.install.in``) use ``@NAME@`` instead,
because ``$`` belongs to the shell there.

Usage: ``python3 packaging/render.py OUTDIR [TEMPLATE ...]``
"""

from __future__ import annotations

import re
import runpy
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "packaging" / "templates"

# template file -> output file name pattern (formatted with appinfo values)
OUTPUTS = {
    "polkit.policy.in": "{APP_ID}.policy",
}


def appinfo_values() -> dict[str, str]:
    info = runpy.run_path(str(ROOT / "src" / "offscan" / "appinfo.py"))
    return {k: str(v) for k, v in info.items() if k.isupper() and isinstance(v, (str, int))}


AT_TEMPLATES = (".sh.in", "PKGBUILD.in", "pacman.install.in")


def substitute_at(text: str, values: dict[str, str]) -> str:
    """Replace ``@NAME@`` placeholders; an unknown name is an error."""
    def value(match: re.Match[str]) -> str:
        if match[1] not in values:
            raise KeyError(f"unknown placeholder @{match[1]}@")
        return values[match[1]]
    return re.sub(r"@([A-Z][A-Z0-9_]*)@", value, text)


def render(template: str, values: dict[str, str] | None = None) -> str:
    values = values or appinfo_values()
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    if template.endswith(AT_TEMPLATES):
        return substitute_at(text, values)
    return string.Template(text).substitute(values)


def output_name(template: str, values: dict[str, str]) -> str:
    return OUTPUTS.get(template, template.removesuffix(".in")).format(**values)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    outdir = Path(argv[0])
    outdir.mkdir(parents=True, exist_ok=True)
    values = appinfo_values()
    for template in argv[1:] or sorted(OUTPUTS):
        target = outdir / output_name(template, values)
        target.write_text(render(template, values), encoding="utf-8")
        print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
