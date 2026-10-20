#!/usr/bin/env python3
"""Generate the man pages from the real argument parsers (so they never drift).

Usage: ``python3 tools/manpage.py OUTDIR``  → OUTDIR/<name>.1 and OUTDIR/<gui-name>.1
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from offscan import appinfo  # noqa: E402


def esc(text: str) -> str:
    text = text.replace("\\", "\\e").replace("-", "\\-")
    lines = []
    for line in text.splitlines() or [""]:
        lines.append("\\&" + line if line[:1] in (".", "'") else line)
    return "\n".join(lines)


def _date() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.datetime.fromtimestamp(int(epoch), datetime.UTC) if epoch
            else datetime.datetime.now(datetime.UTC))
    return when.strftime("%Y-%m-%d")


def _options(parser: argparse.ArgumentParser) -> list[str]:
    out = []
    for act in parser._actions:
        if act.help == argparse.SUPPRESS or isinstance(
                act, (argparse._SubParsersAction, argparse._HelpAction)):
            continue
        if act.option_strings:
            names = ", ".join(f"\\fB{esc(s)}\\fR" for s in act.option_strings)
            if act.nargs != 0:
                names += f" \\fI{esc(act.metavar or act.dest.upper())}\\fR"
        else:
            names = f"\\fI{esc(act.metavar or act.dest)}\\fR"
        out.append(f".TP\n{names}\n{esc(act.help or '')}")
    return out


def _subcommands(parser: argparse.ArgumentParser, prefix: str) -> list[str]:
    out = []
    for act in parser._actions:
        if not isinstance(act, argparse._SubParsersAction):
            continue
        helps = {c.dest: c.help for c in act._choices_actions}
        for name, sub in act.choices.items():
            out.append(f'.SS "{esc(prefix + " " + name)}"')
            if helps.get(name):
                out.append(esc(helps[name]))
            out.append(".PP\n.nf\n" + esc(sub.format_usage().strip()) + "\n.fi")
            if sub.description and sub.description != helps.get(name):
                out.append(".PP\n" + esc(sub.description))
            out.extend(_options(sub))
            out.extend(_subcommands(sub, prefix + " " + name))
    return out


def cli_page() -> str:
    from offscan.cli.main import build_parser
    parser = build_parser()
    parts = [
        f'.TH {appinfo.NAME.upper()} 1 "{_date()}" "{appinfo.NAME} {appinfo.VERSION}" "User Commands"',
        ".SH NAME", f"{appinfo.NAME} \\- {esc(appinfo.SUMMARY.lower())}",
        ".SH SYNOPSIS", f".B {appinfo.NAME}\n[\\fIoptions\\fR] \\fICOMMAND\\fR [\\fIargs\\fR]",
        ".SH DESCRIPTION", esc(
            f"{appinfo.DISPLAY_NAME} scans the drives of Windows and Linux installations that are not "
            "running for malware, autostart persistence and modified system files. Target drives are "
            "only ever mounted read-only; quarantine, delete and restore are explicit, confirmed changes "
            "that are logged. Drive access goes through a privileged helper started with pkexec (or "
            "sudo)."),
        ".SH OPTIONS", *_options(parser),
        ".SH COMMANDS", *_subcommands(parser, appinfo.NAME),
        ".SH EXIT STATUS", ".TP\n0\nclean / success", ".TP\n1\ndetections found", ".TP\n2\nerror",
        ".TP\n3\nincomplete scan (cancelled, or files could not be read)",
        ".TP\n4\nchange refused or not confirmed",
        ".SH FILES",
        f".TP\n\\fI~/.local/share/{appinfo.NAME}/\\fR\ndefinitions, history and reports of the user",
        f".TP\n\\fI{esc(appinfo.SYSTEM_STATE_DIR)}/quarantine/\\fR\nquarantined files (root only)",
        f".TP\n\\fI{esc(appinfo.SYSTEM_STATE_DIR)}/changes.jsonl\\fR\nlog of every change made to a drive",
        ".SH SEE ALSO",
        f"\\fB{appinfo.GUI_NAME}\\fR(1), \\fBclamd\\fR(8), \\fBcryptsetup\\fR(8), \\fBpkexec\\fR(1)",
        ".SH HOMEPAGE", esc(appinfo.HOMEPAGE),
    ]
    return "\n".join(parts) + "\n"


def gui_page() -> str:
    parts = [
        f'.TH {appinfo.GUI_NAME.upper()} 1 "{_date()}" "{appinfo.NAME} {appinfo.VERSION}" "User Commands"',
        ".SH NAME", f"{esc(appinfo.GUI_NAME)} \\- graphical interface of {esc(appinfo.DISPLAY_NAME)}",
        ".SH SYNOPSIS", f".B {esc(appinfo.GUI_NAME)}\n[\\fB\\-\\-no\\-connect\\fR] [\\fB\\-\\-sudo\\fR] "
                        "[\\fB\\-v\\fR] [\\fB\\-\\-self\\-check\\fR]",
        ".SH DESCRIPTION", esc(
            "Pick drives, scan them, review findings, update definitions and look at past scans. The "
            "window follows the desktop's colour scheme, accent colour, fonts and icons. Everything the "
            f"command line can do is available here too; see \\fB{appinfo.NAME}\\fR(1).",
        ).replace("\\e", "\\"),
        ".SH OPTIONS",
        ".TP\n\\fB\\-\\-no\\-connect\\fR\ndo not ask for administrator rights at start-up",
        ".TP\n\\fB\\-\\-sudo\\fR\nuse sudo instead of pkexec",
        ".TP\n\\fB\\-\\-self\\-check\\fR\nbuild the window without showing it, print the Qt binding and exit",
        ".TP\n\\fB\\-v\\fR, \\fB\\-\\-verbose\\fR\nverbose logging",
        ".SH SEE ALSO", f"\\fB{appinfo.NAME}\\fR(1)",
    ]
    return "\n".join(parts) + "\n"


def main(argv: list[str]) -> int:
    out = Path(argv[0] if argv else "build/man")
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{appinfo.NAME}.1").write_text(cli_page(), encoding="utf-8")
    (out / f"{appinfo.GUI_NAME}.1").write_text(gui_page(), encoding="utf-8")
    print(out / f"{appinfo.NAME}.1")
    print(out / f"{appinfo.GUI_NAME}.1")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
