"""Optional external checkers: chkrootkit (Linux) and Hayabusa / Chainsaw (Windows event logs).

None of them is bundled; each is used only if installed and enabled for the
scan, and only from a root-owned location nobody else can write to.  They run
in the helper's empty network namespace as the unprivileged scan user without
any capability (``setpriv``), with ``no_new_privs``, a file-size limit
(``prlimit``), no standard input, private file modes and a timeout.  They see
the target through a read-only, ``noexec``, ``nosymfollow`` mount, so neither
the target's programs nor its symbolic links can be used against the host.
Their output is treated as untrusted text: size-limited, parsed, never
executed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .. import log, privdrop, tools
from . import Finding

logger = log.get("persistence.external")

MAX_OUTPUT = 32 << 20

# chkrootkit tests that only look at files below -r.  Left out: tests that inspect the
# running host (bindshell, lkm, sniffer, chkutmp, ifconfig) or its login records, and
# "aliens", which pastes the names of files it finds on the target into shell commands
# (chkrootkit 0.58b runs `find ... -exec sh -c '... "{}"'`), so a file name could run code.
CHKROOTKIT_TESTS = (
    "asp rexedcs w55808 scalper slapper OSX_RSPLUG ldsopreload amd basename biff chfn chsh cron "
    "crontab date du dirname echo egrep env find fingerd gpm grep hdparm su inetd inetdconf identd init "
    "killall login ls lsof mail mingetty netstat named passwd pidof pop2 pop3 ps pstree rpcinfo rlogind rshd "
    "slogin sendmail sshd syslogd tar tcpd tcpdump top telnetd timed traceroute vdir w write").split()
SEARCH_DIRS = ("/usr/local/bin", "/usr/bin", "/opt/hayabusa", "/opt/chainsaw", "/usr/local/share/hayabusa",
               "/usr/local/share/chainsaw")


def trusted_binary(path: str) -> bool:
    """True if ``path`` and every directory above it are root-owned and writable by no one else."""
    real = os.path.realpath(path)
    current = real
    while True:
        try:
            st = os.lstat(current)
        except OSError:
            return False
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        if current == "/":
            return os.path.isfile(real) and os.access(real, os.X_OK)
        current = os.path.dirname(current)


def find_tool(name: str, configured: str | None = None) -> str | None:
    if configured:
        return configured if os.path.isabs(configured) and trusted_binary(configured) else None
    found = tools.find(name)
    if found and trusted_binary(found):
        return found
    for directory in SEARCH_DIRS:
        candidate = os.path.join(directory, name)
        if os.access(candidate, os.X_OK) and trusted_binary(candidate):
            return candidate
        for entry in sorted(Path(directory).glob(f"{name}*")) if os.path.isdir(directory) else []:
            if entry.is_file() and trusted_binary(str(entry)):
                return str(entry)
    return None


def restricted(argv: list[str], identity: privdrop.Identity | None) -> list[str]:
    """Wrap a command so it runs unprivileged: no capabilities, no setuid, limited file sizes."""
    setpriv = tools.find("setpriv")
    prlimit = tools.find("prlimit")
    if setpriv is None or prlimit is None:
        raise tools.ToolError("setpriv and prlimit (util-linux) are needed to run external checkers safely")
    uid = identity.uid if identity else 65534
    gid = identity.gid if identity else 65534
    return [prlimit, f"--fsize={MAX_OUTPUT}", "--core=0", "--",
            setpriv, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--inh-caps=-all",
            "--bounding-set=-all", "--no-new-privs", "--", *argv]


def _run(argv: list[str], identity: privdrop.Identity | None, timeout: float, cwd: str = "/",
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    base = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
    old = os.umask(0o077)
    try:
        proc = subprocess.run(restricted(argv, identity), stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, cwd=cwd, env={**base, **(env or {})}, check=False)
    finally:
        os.umask(old)
    proc.stdout = proc.stdout[:MAX_OUTPUT]
    proc.stderr = proc.stderr[-65536:]
    return proc


# ---------------------------------------------------------------- chkrootkit

ID_SHIM = '#!/bin/sh\ncase "$1" in -u|-g) echo 0;; *) echo "uid=0(root) gid=0(root) groups=0(root)";; esac\n'


def run_chkrootkit(root_path: str, identity: privdrop.Identity | None, timeout: float = 1800,
                   binary: str | None = None) -> tuple[list[Finding], dict[str, Any]]:
    exe = find_tool("chkrootkit", binary)
    if exe is None:
        return [], {"error": "chkrootkit is not installed"}
    # chkrootkit insists on uid 0; the shim answers its `id` check while the real rights stay
    # those of an unprivileged reader.
    shim = tempfile.mkdtemp(prefix="chkrootkit-")
    try:
        os.chmod(shim, 0o755)  # noqa: S103 - the unprivileged checker must be able to run the shim
        with open(os.path.join(shim, "id"), "w") as fh:
            fh.write(ID_SHIM)
        os.chmod(os.path.join(shim, "id"), 0o755)  # noqa: S103
        libdir = "/usr/lib/chkrootkit" if os.path.isdir("/usr/lib/chkrootkit") else "/"
        root_arg = root_path.rstrip("/") + "/"
        proc = _run([exe, "-q", "-p", f"{shim}:/usr/bin:/bin", "-r", root_arg, *CHKROOTKIT_TESTS], identity,
                    timeout, cwd=libdir)
    finally:
        shutil.rmtree(shim, ignore_errors=True)
    text = proc.stdout.decode("utf-8", "replace")
    if "needs root privileges" in text:
        return [], {"error": "chkrootkit refused to run"}
    return parse_chkrootkit(text, root_arg), {"exit": proc.returncode}


NOISE = re.compile(r"^(/usr/bin/find: |RTNETLINK|find: |ls: cannot|grep: )")


def parse_chkrootkit(text: str, root_prefix: str) -> list[Finding]:
    findings: list[Finding] = []
    current: Finding | None = None
    for raw in text.splitlines()[:5000]:
        line = raw.strip()
        if not line or NOISE.match(line):
            continue
        if line.startswith(root_prefix) and current is not None:
            path = "/" + line[len(root_prefix):].lstrip("/")
            current.extra.setdefault("files", []).append(path)
            if current.file is None:
                current.file = current.target = path
            continue
        if line.startswith("WARNING:") or "INFECTED" in line or line.lower().startswith("possible"):
            message = line.removeprefix("WARNING:").strip().rstrip(":")
            message = message.replace(root_prefix, "/")
            current = Finding("tool.chkrootkit", f"chkrootkit: {message[:200]}", "chkrootkit", message[:1000],
                              "high" if "INFECTED" in line else "medium", ["reported by chkrootkit"])
            findings.append(current)
    return findings


# ---------------------------------------------------------------- Windows event logs

LEVELS = {"crit": "high", "critical": "high", "high": "high", "med": "medium", "medium": "medium",
          "low": "low", "info": "info", "informational": "info"}


def _private_dir(identity: privdrop.Identity | None) -> str:
    out = tempfile.mkdtemp(prefix="evtx-")
    os.chmod(out, 0o700)
    if identity is not None and os.geteuid() == 0:
        os.chown(out, identity.uid, identity.gid)
    return out


def run_hayabusa(evtx_dir: str, identity: privdrop.Identity | None, min_level: str = "medium",
                 timeout: float = 3600, binary: str | None = None) -> tuple[list[Finding], dict[str, Any]]:
    exe = find_tool("hayabusa", binary)
    if exe is None:
        return [], {"error": "Hayabusa is not installed"}
    home = os.path.dirname(os.path.realpath(exe))
    out_dir = _private_dir(identity)
    out = os.path.join(out_dir, "timeline.jsonl")
    try:
        common = ["-w", "-q", "-Q", "-K", "-C", "-m", min_level, "-o", out]
        if os.path.isdir(os.path.join(home, "rules")):
            common += ["-r", os.path.join(home, "rules")]
        attempts = [[exe, "dfir-timeline", "-d", evtx_dir, "-t", "jsonl", *common],     # 4.x
                    [exe, "json-timeline", "-d", evtx_dir, "-L", *common]]               # 3.x
        proc = None
        for argv in attempts:
            proc = _run(argv, identity, timeout, cwd=home)
            if os.path.exists(out):
                break
        if not os.path.exists(out):
            err = proc.stderr.decode("utf-8", "replace").strip()[-300:] if proc else ""
            return [], {"error": f"Hayabusa produced no timeline: {err}"}
        # The directory belongs to the tool's user: open without following links, regular files only.
        fd = os.open(out, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return [], {"error": "Hayabusa's output is not a regular file"}
            data = fh.read(MAX_OUTPUT)
        return parse_hayabusa(data.decode("utf-8", "replace")), {"exit": proc.returncode if proc else None}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def parse_hayabusa(text: str, limit: int = 2000) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        level = LEVELS.get(str(event.get("Level", "")).lower(), "low")
        title = str(event.get("RuleTitle", "?"))[:200]
        details = event.get("Details")
        detail_text = json.dumps(details, ensure_ascii=False)[:1000] if isinstance(details, dict) \
            else str(details or "")[:1000]
        findings.append(Finding("tool.hayabusa", f"Event log: {title}",
                                f"{event.get('Channel', '?')} event {event.get('EventID', '?')} "
                                f"record {event.get('RecordID', '?')}", detail_text, level,
                                ["Sigma rule match reported by Hayabusa"], None, None, None,
                                None, {"timestamp": str(event.get("Timestamp", ""))[:40],
                                       "computer": str(event.get("Computer", ""))[:200],
                                       "rule_id": str(event.get("RuleID", ""))[:80]}))
        if len(findings) >= limit:
            break
    return findings


def run_chainsaw(evtx_dir: str, identity: privdrop.Identity | None, timeout: float = 3600,
                 binary: str | None = None) -> tuple[list[Finding], dict[str, Any]]:
    exe = find_tool("chainsaw", binary)
    if exe is None:
        return [], {"error": "Chainsaw is not installed"}
    home = os.path.dirname(os.path.realpath(exe))
    rules = next((p for p in (os.path.join(home, "rules"), "/usr/share/chainsaw/rules") if os.path.isdir(p)),
                 None)
    if rules is None:
        return [], {"error": "Chainsaw's rules directory was not found next to the program"}
    argv = [exe, "hunt", rules, evtx_dir, "--json", "-q", "--skip-errors"]
    sigma = os.path.join(home, "sigma")
    mapping = os.path.join(home, "mappings", "sigma-event-logs-all.yml")
    if os.path.isdir(sigma) and os.path.isfile(mapping):
        argv += ["-s", sigma, "--mapping", mapping]
    proc = _run(argv, identity, timeout, cwd=home)
    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
    except ValueError:
        err = proc.stderr.decode("utf-8", "replace").strip()[-300:]
        return [], {"error": f"Chainsaw output could not be read: {err}"}
    return parse_chainsaw(data), {"exit": proc.returncode}


def parse_chainsaw(data: Any, limit: int = 2000) -> list[Finding]:
    findings: list[Finding] = []
    for hit in data if isinstance(data, list) else []:
        if not isinstance(hit, dict):
            continue
        name = str(hit.get("name") or hit.get("title") or "?")[:200]
        level = LEVELS.get(str(hit.get("level", "")).lower(), "low")
        system = (((hit.get("document") or {}).get("data") or {}).get("Event") or {}).get("System") or {}
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text") or event_id.get("value")
        findings.append(Finding("tool.chainsaw", f"Event log: {name}",
                                f"{system.get('Channel', '?')} event {event_id or '?'}",
                                str(hit.get("group", ""))[:500], level, ["rule match reported by Chainsaw"],
                                None, None, None, None,
                                {"timestamp": str(hit.get("timestamp", ""))[:40],
                                 "computer": str(system.get("Computer", ""))[:200]}))
        if len(findings) >= limit:
            break
    return findings
