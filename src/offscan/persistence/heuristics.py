"""Heuristics for suspicious autostart commands (Windows and Linux).

These only raise the severity of an entry that is *already* a persistence
mechanism; they never create findings on their own.
"""

from __future__ import annotations

import ntpath
import re

WINDOWS_RULES: list[tuple[re.Pattern[str], str, str]] = [(re.compile(p, re.I), why, sev) for p, why, sev in (
    (r"powershell(\.exe)?\b.*(\s-e(nc|ncodedcommand)?\s|frombase64string|downloadstring|"
     r"downloadfile|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|-ep\s+bypass|"
     r"-executionpolicy\s+bypass|-nop\b)", "PowerShell with encoded, hidden or download arguments", "high"),
    (r"\bmshta(\.exe)?\b", "uses mshta (HTML application host)", "high"),
    (r"\b(wscript|cscript)(\.exe)?\b", "uses the Windows Script Host", "medium"),
    (r"\bregsvr32(\.exe)?\b.*(/i:|scrobj)", "regsvr32 scriptlet execution", "high"),
    (r"\brundll32(\.exe)?\b.*(javascript:|vbscript:|https?:|\\\\\\\\)",
     "rundll32 with a script or remote DLL", "high"),
    (r"\bcertutil(\.exe)?\b.*(-urlcache|-decode|-f\b)", "certutil used to download or decode", "high"),
    (r"\bbitsadmin(\.exe)?\b.*/transfer", "BITS download job", "high"),
    (r"\b(curl|wget)(\.exe)?\s+.*https?://", "downloads from the internet", "high"),
    (r"https?://", "contains an internet address", "medium"),
    (r"\\(appdata\\local\\temp|windows\\temp|temp|users\\public|perflogs|\$recycle\.bin)\\",
     "runs from a temporary, public or recycle-bin folder", "high"),
    (r"\\programdata\\[^\\]+\.(exe|dll|scr|bat|cmd|vbs|js|ps1)\b",
     "runs a program stored directly in ProgramData", "medium"),
    (r"\\appdata\\(roaming|local)\\[^\\]+\.(exe|scr|bat|cmd|vbs|js|ps1)\b",
     "runs a program stored directly in AppData", "medium"),
    (r"\.(vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|scr|pif)\b", "starts a script or screensaver file", "low"),
    (r"\bcmd(\.exe)?\s+/[ck]\b", "starts a command shell", "low"),
)]

LINUX_RULES: list[tuple[re.Pattern[str], str, str]] = [(re.compile(p), why, sev) for p, why, sev in (
    (r"(curl|wget|fetch)\b[^|;\n]*\|\s*(ba|z|da|k)?sh\b", "downloads and runs a script", "high"),
    (r"(curl|wget)\b.*\s-[a-zA-Z]*O\s*-?\s*/(tmp|var/tmp|dev/shm)/",
     "downloads into a temporary folder", "high"),
    (r"base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|", "decodes an embedded payload", "high"),
    (r"/dev/(tcp|udp)/", "opens a network socket from the shell (reverse shell)", "high"),
    (r"\bnc(at)?\b[^\n]*\s-(e|c)\s", "netcat executing a shell", "high"),
    (r"\bsocat\b[^\n]*exec", "socat executing a program", "high"),
    (r"python[23]?(\.\d+)?\s+-c\s+[^\n]*socket", "inline Python network code", "high"),
    (r"perl\s+-e\s+[^\n]*socket", "inline Perl network code", "high"),
    (r"\bmkfifo\b[^\n]*\b(nc|sh|bash)\b", "FIFO-based remote shell", "high"),
    (r"(^|[\s;'\"=])(/tmp|/var/tmp|/dev/shm)/\S+", "runs something from a temporary folder", "high"),
    (r"\b(xmrig|minerd|cpuminer|ccminer|kdevtmpfsi|kinsing)\b|stratum\+tcp://",
     "cryptocurrency miner", "high"),
    (r"\bLD_PRELOAD=", "preloads a shared library", "medium"),
    (r"\bchmod\s+[ugoa]*\+?[0-7]*[sS]|\bchmod\s+[0-7]?[4-7][0-7]{3}\b", "sets the SUID/SGID bit", "medium"),
    (r"\b(curl|wget)\b[^\n]*https?://", "downloads from the internet", "medium"),
    (r"\bnohup\b|\bsetsid\b|&\s*disown", "detaches a background process", "low"),
    (r"(^|\s)\.[A-Za-z0-9_-]+/|/\.\w[^/\s]*/", "uses a hidden directory", "low"),
)]

_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def higher(a: str, b: str) -> str:
    return b if _ORDER.get(b, 0) > _ORDER.get(a, 0) else a


def assess(text: str, rules: list[tuple[re.Pattern[str], str, str]]) -> tuple[str, list[str]]:
    severity = "info"
    reasons: list[str] = []
    for pattern, why, sev in rules:
        if pattern.search(text):
            reasons.append(why)
            if _ORDER[sev] > _ORDER[severity]:
                severity = sev
    return severity, reasons


def assess_windows(text: str) -> tuple[str, list[str]]:
    return assess(text, WINDOWS_RULES)


def assess_linux(text: str) -> tuple[str, list[str]]:
    return assess(text, LINUX_RULES)


# -- Windows command lines -> target paths ---------------------------------------

_ENV = {
    "%systemroot%": "C:\\Windows", "%windir%": "C:\\Windows", "\\systemroot\\": "C:\\Windows\\",
    "%systemdrive%": "C:", "%programfiles%": "C:\\Program Files",
    "%programfiles(x86)%": "C:\\Program Files (x86)", "%programw6432%": "C:\\Program Files",
    "%programdata%": "C:\\ProgramData", "%allusersprofile%": "C:\\ProgramData",
    "%commonprogramfiles%": "C:\\Program Files\\Common Files", "%public%": "C:\\Users\\Public",
}
_USER_ENV = {"%appdata%": "AppData\\Roaming", "%localappdata%": "AppData\\Local",
             "%userprofile%": "", "%temp%": "AppData\\Local\\Temp", "%tmp%": "AppData\\Local\\Temp"}
_EXE_RE = re.compile(r"^(.*?\.(exe|dll|sys|com|scr|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|cpl|ocx|msi|lnk))\b",
                     re.I)


SCRIPT_HOSTS = {"rundll32", "wscript", "cscript", "mshta", "cmd", "powershell", "pwsh", "regsvr32"}
_ARG_RE = re.compile(r'"[^"]*"|[^\s,]+')


def expand_windows(text: str, profile: str | None = None) -> str:
    out = text.strip()
    lower = out.lower()
    for key, value in _ENV.items():
        idx = lower.find(key)
        while idx >= 0:
            out = out[:idx] + value + out[idx + len(key):]
            lower = out.lower()
            idx = lower.find(key, idx + len(value))
    if profile:
        win_profile = "C:" + profile.replace("/", "\\")
        for key, rel in _USER_ENV.items():
            idx = out.lower().find(key)
            if idx >= 0:
                out = out[:idx] + ntpath.join(win_profile, rel).rstrip("\\") + out[idx + len(key):]
    if out.startswith("\\??\\"):
        out = out[4:]
    return out


def command_target(command: str, profile: str | None = None) -> str | None:
    """Executable that a Windows command line starts, as a volume-relative path (``/Windows/...``)."""
    text = expand_windows(command, profile)
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        exe = text[1:end] if end > 0 else text[1:]
    else:
        match = _EXE_RE.match(text)
        exe = match.group(1) if match else text.split(" ", 1)[0]
    exe = exe.strip()
    # Script hosts: the interesting file is the script argument.
    host = ntpath.basename(exe).lower().removesuffix(".exe")
    if host in SCRIPT_HOSTS:
        rest = text[text.lower().find(exe.lower()) + len(exe):].lstrip('"')
        for token in _ARG_RE.findall(rest):
            token = token.strip('"')
            if token[:1] in "/-" and not re.match(r"^[a-zA-Z]:", token):
                continue                      # a switch such as //B, /c or -File
            match = _EXE_RE.match(token)
            if match:
                exe = match.group(1)
                break
    if re.match(r"^[a-zA-Z]:\\", exe):
        if exe[0].lower() != "c":
            return None                       # another drive: unknown mapping
        return exe[2:].replace("\\", "/")
    if exe.lower().startswith(("system32\\", "syswow64\\")):
        return "/Windows/" + exe.replace("\\", "/")
    if "\\" not in exe and exe.lower().endswith((".exe", ".dll", ".sys")):
        return "/Windows/System32/" + exe
    return None
