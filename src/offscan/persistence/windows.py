"""Windows persistence: collection (helper, root) and analysis (sandbox, unprivileged).

Collection opens hives (+ transaction logs) and the WMI repository
read-only through :class:`RootFS`, packs scheduled-task XML into one sealed
memfd and lists the Startup folders.  The sandbox task
:func:`task_persistence` parses everything with regipy and the standard XML
parser.  Transaction logs are replayed into a private temporary copy,
never written back.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
import xml.etree.ElementTree as ET
from typing import Any

from .. import names
from ..safefs import RootFS
from . import Finding, filepack, heuristics

MAX_HIVE = 1 << 30
MAX_TASK_XML = 1 << 20
MAX_TASKS = 5000
MAX_WMI = 512 << 20

# ----------------------------------------------------------------- collection


def _open(root: RootFS, path: bytes | None, limit: int) -> int | None:
    if path is None:
        return None
    try:
        st = root.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        return root.open_regular(path, follow_last=False)
    except OSError:
        return None


def collect(root: RootFS) -> tuple[dict[str, Any], list[int]]:
    """Open everything the analysis needs; returns (args, fds) for the sandbox.

    The caller closes the descriptors.
    """
    fds: list[int] = []
    args: dict[str, Any] = {"hives": [], "tasks": None, "startup": [], "wmi": None}

    def add(fd: int | None) -> int | None:
        if fd is None:
            return None
        fds.append(fd)
        return len(fds) - 1

    def add_hive(path: bytes | None, role: str, **extra: Any) -> None:
        idx = add(_open(root, path, MAX_HIVE))
        if idx is None or path is None:
            return
        logs = []
        for suffix in (b".LOG1", b".LOG2"):
            log = add(_open(root, root.find_ci(path + suffix), MAX_HIVE))
            if log is not None:
                logs.append(log)
        args["hives"].append({"role": role, "fd": idx, "logs": logs, "file": names.to_wire(path), **extra})

    for hive in ("SOFTWARE", "SYSTEM"):
        add_hive(root.find_ci("Windows/System32/config/" + hive), hive)
    users = root.find_ci("Users")
    if users is not None:
        try:
            profiles = root.listdir(users)
        except OSError:
            profiles = []
        for name in profiles:
            if name.lower() in (b"public", b"default user", b"all users"):
                continue
            profile = users + b"/" + name
            user, wire_profile = names.to_wire(name), names.to_wire(profile)
            add_hive(root.find_ci(profile + b"/NTUSER.DAT"), "NTUSER", user=user, profile=wire_profile)
            add_hive(root.find_ci(profile + b"/AppData/Local/Microsoft/Windows/UsrClass.dat"), "USRCLASS",
                     user=user, profile=wire_profile)
            _list_startup(root, root.find_ci(profile + b"/AppData/Roaming/" + STARTUP), user, args)
    _list_startup(root, root.find_ci(b"ProgramData/" + STARTUP), None, args)
    tasks = root.find_ci("Windows/System32/Tasks")
    if tasks is not None:
        pack = filepack.Packer(max_total=64 << 20, max_entries=MAX_TASKS)
        try:
            pack.add_tree(root, tasks, "task", recursive=True, max_size=MAX_TASK_XML, max_depth=12)
            fd, index = pack.finish()
            args["tasks"] = {"fd": add(os.dup(fd)), "index": index, "base": names.to_wire(tasks)}
        finally:
            pack.close()
    wmi = root.find_ci("Windows/System32/wbem/Repository/OBJECTS.DATA")
    idx = add(_open(root, wmi, MAX_WMI))
    if idx is not None and wmi is not None:
        args["wmi"] = {"fd": idx, "file": names.to_wire(wmi)}
    return args, fds


STARTUP = b"Microsoft/Windows/Start Menu/Programs/Startup"


def _list_startup(root: RootFS, path: bytes | None, user: str | None, args: dict[str, Any]) -> None:
    if path is None:
        return
    try:
        entries = root.listdir(path)
    except OSError:
        return
    for name in entries:
        if name.lower() != b"desktop.ini":
            args["startup"].append({"file": names.to_wire(path + b"/" + name), "user": user})


# ------------------------------------------------------------------- analysis

CV = "Microsoft\\Windows\\CurrentVersion"
NT = "Microsoft\\Windows NT\\CurrentVersion"
RUN_KEYS = (f"{CV}\\Run", f"{CV}\\RunOnce", f"{CV}\\RunOnceEx", f"{CV}\\Policies\\Explorer\\Run",
            f"{CV}\\RunServices", f"{CV}\\RunServicesOnce")
DEFAULT_STARTUP = "\\microsoft\\windows\\start menu\\programs\\startup"

KNOWN_LSA = {
    "authentication packages": {"msv1_0", ""},
    "notification packages": {"scecli", "rassfm", ""},
    "security packages": {"kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
                          "negoexts", "livessp", "credssp", '""', ""},
}
KNOWN_PRINT_MONITORS = {"localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll", "apmon.dll",
                        "appmon.dll", "fxsmon.dll", "pjlmon.dll", "inetpp.dll", "monitor.dll",
                        "msonpmon.dll", ""}
KNOWN_NETSH = {"ifmon.dll", "rasmontr.dll", "authfwcfg.dll", "dhcpcmonitor.dll", "dot3cfg.dll",
               "fwcfg.dll", "hnetmon.dll", "netiohlp.dll", "nettrace.dll", "nshhttp.dll", "nshipsec.dll",
               "nshwfp.dll", "p2pnetsh.dll", "rpcnsh.dll", "wcnnetsh.dll", "whhelper.dll", "wlancfg.dll",
               "wshelper.dll", "wwancfg.dll", "peerdistsh.dll", "napmontr.dll", "dhcpmonitor.dll"}
KNOWN_TIME_PROVIDERS = {"w32time.dll", "vmictimeprovider.dll"}
ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe",
                 "displayswitch.exe", "atbroker.exe"}
NORMAL_SERVICE_DIRS = ("\\windows\\", "system32\\", "syswow64\\", "\\program files", "\\systemroot\\",
                       "%systemroot%", "%windir%", "\\driverstore\\")


class _Ctx:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.targets: set[str] = set()
        self.errors: list[str] = []
        self.info: dict[str, Any] = {}

    def add(self, finding: Finding, report_info: bool = True) -> None:
        if finding.target:
            self.targets.add(finding.target)
        if report_info or finding.severity != "info":
            self.findings.append(finding)


def _str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(_str(v) for v in value)
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _get(hive: Any, path: str) -> Any:
    try:
        return hive.get_key("\\" + path.strip("\\"))
    except Exception:              # RegistryKeyNotFoundException and parser errors alike
        return None


def _values(key: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if key is None:
        return out
    try:
        for value in key.iter_values():
            out[value.name] = value.value
    except Exception:
        pass
    return out


def _subkeys(key: Any) -> list[Any]:
    if key is None:
        return []
    try:
        return list(key.iter_subkeys())
    except Exception:
        return []


def _open_hive(fd: int, logs: list[int], tmpdir: str) -> tuple[Any, bool]:
    """Parse a hive; if it is dirty, replay its transaction logs into a private copy."""
    from regipy.registry import RegistryHive
    path, copy = filepack.fd_path(fd, MAX_HIVE)
    copies = [copy]
    try:
        hive = RegistryHive(path)
        dirty = hive.header.primary_sequence_num != hive.header.secondary_sequence_num
        if not (dirty and logs):
            return hive, False
        from regipy.recovery import apply_transaction_logs
        restored = os.path.join(tmpdir, f"restored-{fd}")
        log_paths = []
        for log_fd in logs:
            log_path, log_copy = filepack.fd_path(log_fd, MAX_HIVE)
            copies.append(log_copy)
            log_paths.append(log_path)
        try:
            apply_transaction_logs(path, log_paths[0], log_paths[1] if len(log_paths) > 1 else None,
                                   restored_hive_path=restored)
            return RegistryHive(restored), True
        except Exception:
            return hive, False
    finally:
        for c in copies:              # regipy keeps its own in-memory copy
            os.close(c)


def _entry(ctx: _Ctx, check: str, title: str, location: str, value: str, file: str,
           mitre: str | None, user: str | None = None, profile: str | None = None,
           base: str = "info", extra_reason: str | None = None, report_info: bool = True) -> None:
    severity, reasons = heuristics.assess_windows(value)
    severity = heuristics.higher(severity, base)
    if extra_reason:
        reasons.insert(0, extra_reason)
    target = heuristics.command_target(value, profile) if value else None
    ctx.add(Finding(check, title, location, value[:2000], severity, reasons, file, target, user, mitre),
            report_info)


def analyze_software(hive: Any, file: str, ctx: _Ctx) -> None:
    hklm = "HKLM\\SOFTWARE\\"
    for wow in ("", "Wow6432Node\\"):
        for run in RUN_KEYS:
            path = wow + run
            key = _get(hive, path)
            for name, value in _values(key).items():
                _entry(ctx, "windows.run_key", f'Autostart entry "{name}"', f"{hklm}{path} : {name}",
                       _str(value), file, "T1547.001")
            for sub in _subkeys(key):                         # RunOnceEx style
                for name, value in _values(sub).items():
                    _entry(ctx, "windows.run_key", f'Autostart entry "{sub.name}\\{name}"',
                           f"{hklm}{path}\\{sub.name} : {name}", _str(value), file, "T1547.001")
        _winlogon(_values(_get(hive, f"{wow}{NT}\\Winlogon")), f"{hklm}{wow}{NT}\\Winlogon", file, ctx)
        nt_windows = _values(_get(hive, f"{wow}{NT}\\Windows"))
        appinit = _str(nt_windows.get("AppInit_DLLs", "")).strip()
        if appinit and str(nt_windows.get("LoadAppInit_DLLs", 0)) in ("1", "True"):
            _entry(ctx, "windows.appinit", "AppInit_DLLs loaded into every GUI process",
                   f"{hklm}{wow}{NT}\\Windows : AppInit_DLLs", appinit, file, "T1546.010", base="high")
        _ifeo(hive, wow, file, ctx)
        for sub in _subkeys(_get(hive, f"{wow}Microsoft\\Active Setup\\Installed Components")):
            stub = _str(_values(sub).get("StubPath", ""))
            if stub:
                _entry(ctx, "windows.active_setup", f"Active Setup component {sub.name}",
                       f"{hklm}{wow}Microsoft\\Active Setup\\Installed Components\\{sub.name} : StubPath",
                       stub, file, "T1547.014", report_info=False)
        autorun = _str(_values(_get(hive, f"{wow}Microsoft\\Command Processor")).get("AutoRun", ""))
        if autorun:
            _entry(ctx, "windows.cmd_autorun", "Command Processor AutoRun",
                   f"{hklm}{wow}Microsoft\\Command Processor : AutoRun", autorun, file, "T1546",
                   base="medium")
    for name, value in _values(_get(hive, "Microsoft\\NetSh")).items():
        dll = _str(value).strip().lower().rsplit("\\", 1)[-1]
        if dll and dll not in KNOWN_NETSH:
            _entry(ctx, "windows.netsh", f"Unknown netsh helper {name}", f"{hklm}Microsoft\\NetSh : {name}",
                   _str(value), file, "T1546.007", base="medium",
                   extra_reason="not a standard Windows helper")
    common = _str(_values(_get(hive, f"{CV}\\Explorer\\User Shell Folders")).get("Common Startup", ""))
    if common.strip() and DEFAULT_STARTUP not in common.lower():
        _entry(ctx, "windows.startup_redirect", "All-users Startup folder redirected",
               f"{hklm}{CV}\\Explorer\\User Shell Folders : Common Startup", common.strip(), file,
               "T1547.001", base="medium", extra_reason="programs in the new folder start at every logon")
    for task in _hidden_tasks(_get(hive, f"{NT}\\Schedule\\TaskCache\\Tree"), ""):
        ctx.add(Finding("windows.task_hidden", "Scheduled task hidden from the Task Scheduler",
                        f"{hklm}{NT}\\Schedule\\TaskCache\\Tree\\{task}", "", "high",
                        ["the task's security descriptor (SD) was removed (Tarrask technique)"], file,
                        None, None, "T1053.005"))


def _winlogon(values: dict[str, Any], location: str, file: str, ctx: _Ctx) -> None:
    shell = _str(values.get("Shell", "explorer.exe")).strip()
    if shell and shell.lower().rstrip(",") != "explorer.exe":
        _entry(ctx, "windows.winlogon", "Winlogon shell replaced", f"{location} : Shell", shell, file,
               "T1547.004", base="high", extra_reason="the logon shell is not Explorer")
    userinit = _str(values.get("Userinit", "")).strip()
    if userinit and not re.fullmatch(r"(c:\\windows\\system32\\)?userinit(\.exe)?,?", userinit.lower()):
        _entry(ctx, "windows.winlogon", "Winlogon Userinit modified", f"{location} : Userinit", userinit,
               file, "T1547.004", base="high", extra_reason="extra program started at every logon")
    for name in ("Taskman", "AppSetup"):
        if values.get(name):
            _entry(ctx, "windows.winlogon", f"Winlogon {name} set", f"{location} : {name}",
                   _str(values[name]), file, "T1547.004", base="medium")


def _ifeo(hive: Any, wow: str, file: str, ctx: _Ctx) -> None:
    ifeo = f"{wow}{NT}\\Image File Execution Options"
    for sub in _subkeys(_get(hive, ifeo)):
        vals = _values(sub)
        debugger = _str(vals.get("Debugger", "")).strip()
        if debugger:
            acc = sub.name.lower() in ACCESSIBILITY
            _entry(ctx, "windows.ifeo", f"Debugger attached to {sub.name}",
                   f"HKLM\\SOFTWARE\\{ifeo}\\{sub.name} : Debugger", debugger, file,
                   "T1546.008" if acc else "T1546.012", base="high",
                   extra_reason="accessibility-tool backdoor" if acc else "program start hijacked")
        try:
            flag = int(vals.get("GlobalFlag", 0) or 0)
        except (TypeError, ValueError):
            flag = 0
        if flag & 0x200:                                   # FLG_MONITOR_SILENT_PROCESS_EXIT
            silent = f"{wow}{NT}\\SilentProcessExit\\{sub.name}"
            monitor = _str(_values(_get(hive, silent)).get("MonitorProcess", ""))
            if monitor:
                _entry(ctx, "windows.ifeo", f"Program runs when {sub.name} exits",
                       f"HKLM\\SOFTWARE\\{silent} : MonitorProcess", monitor, file, "T1546.012", base="high")


def _hidden_tasks(key: Any, prefix: str, depth: int = 0) -> list[str]:
    out: list[str] = []
    if key is None or depth > 20:
        return out
    for sub in _subkeys(key):
        vals = _values(sub)
        name = f"{prefix}\\{sub.name}" if prefix else sub.name
        if "Id" in vals and "SD" not in vals:
            out.append(name)
        out.extend(_hidden_tasks(sub, name, depth + 1))
    return out


def analyze_system(hive: Any, file: str, ctx: _Ctx) -> None:
    try:
        current = int(_values(_get(hive, "Select")).get("Current", 1) or 1)
    except (TypeError, ValueError):
        current = 1
    ccs = f"ControlSet{current:03d}"
    ctx.info["control_set"] = ccs
    sys_ = f"HKLM\\SYSTEM\\{ccs}"
    session = f"{ccs}\\Control\\Session Manager"
    boot = _values(_get(hive, session)).get("BootExecute")
    for item in boot if isinstance(boot, list) else [boot] if boot else []:
        text = _str(item).strip()
        if text and text.lower() not in ("autocheck autochk *", "autocheck autochk /q /v *"):
            _entry(ctx, "windows.boot_execute", "Program runs before Windows starts",
                   f"{sys_}\\Control\\Session Manager : BootExecute", text, file, "T1547.001",
                   base="high", extra_reason="BootExecute normally only runs autochk")
    for name, value in _values(_get(hive, f"{session}\\AppCertDlls")).items():
        _entry(ctx, "windows.appcert", f"AppCert DLL {name}",
               f"{sys_}\\Control\\Session Manager\\AppCertDlls : {name}", _str(value), file, "T1546.009",
               base="high")
    _lsa(hive, ccs, file, ctx)
    for sub in _subkeys(_get(hive, f"{ccs}\\Control\\Print\\Monitors")):
        driver = _str(_values(sub).get("Driver", "")).strip()
        if driver.lower().rsplit("\\", 1)[-1] not in KNOWN_PRINT_MONITORS:
            _entry(ctx, "windows.print_monitor", f"Unknown print monitor {sub.name}",
                   f"{sys_}\\Control\\Print\\Monitors\\{sub.name} : Driver", driver, file, "T1547.010",
                   base="medium")
    for sub in _subkeys(_get(hive, f"{ccs}\\Services\\W32Time\\TimeProviders")):
        dll = _str(_values(sub).get("DllName", "")).strip()
        if dll and dll.lower().rsplit("\\", 1)[-1] not in KNOWN_TIME_PROVIDERS:
            _entry(ctx, "windows.time_provider", f"Unknown time provider {sub.name}",
                   f"{sys_}\\Services\\W32Time\\TimeProviders\\{sub.name} : DllName", dll, file,
                   "T1547.003", base="high", extra_reason="loaded into the Windows Time service")
    power = _values(_get(hive, f"{session}\\Power"))
    if "HiberbootEnabled" in power:
        ctx.info["fast_startup"] = str(power["HiberbootEnabled"]) == "1"
    for svc in _subkeys(_get(hive, f"{ccs}\\Services")):
        _service(hive, ccs, svc, file, ctx)


def _lsa(hive: Any, ccs: str, file: str, ctx: _Ctx) -> None:
    lsa = _values(_get(hive, f"{ccs}\\Control\\Lsa"))
    lsa.update({f"OSConfig {k}": v for k, v in _values(_get(hive, f"{ccs}\\Control\\Lsa\\OSConfig")).items()})
    for name, value in lsa.items():
        kind = name.lower().replace("osconfig ", "")
        if kind not in KNOWN_LSA:
            continue
        items = value if isinstance(value, list) else str(value or "").split()
        unknown = [str(i) for i in items if str(i).strip().lower() not in KNOWN_LSA[kind]]
        if unknown:
            _entry(ctx, "windows.lsa", f"Unknown LSA {kind}", f"HKLM\\SYSTEM\\{ccs}\\Control\\Lsa : {name}",
                   ", ".join(unknown), file, "T1547.002" if "auth" in kind else "T1547.005",
                   base="high", extra_reason="loaded into LSASS (can capture passwords)")


def _service(hive: Any, ccs: str, svc: Any, file: str, ctx: _Ctx) -> None:
    vals = _values(svc)
    image = _str(vals.get("ImagePath", "")).strip()
    try:
        start = int(vals["Start"]) if vals.get("Start") is not None else 3
        stype = int(vals.get("Type", 0) or 0)
    except (TypeError, ValueError):
        start, stype = 3, 0
    dll = _str(_values(_get(hive, f"{ccs}\\Services\\{svc.name}\\Parameters")).get("ServiceDll", "")).strip()
    failure = _str(vals.get("FailureCommand", "")).strip()
    location = f"HKLM\\SYSTEM\\{ccs}\\Services\\{svc.name}"
    if failure:
        _entry(ctx, "windows.service_failure", f"Service {svc.name} runs a command on failure",
               f"{location} : FailureCommand", failure, file, "T1543.003", base="medium")
    if not (image or dll) or not (start <= 2 or dll):
        return
    driver = stype in (1, 2)
    kind = "driver" if driver else "service"
    lower = (dll or image).lower().replace("/", "\\")
    base, reason = "info", None
    if not any(p in lower for p in NORMAL_SERVICE_DIRS):
        base, reason = "medium", f"{kind} file outside the Windows and Program Files folders"
    if driver and image and "drivers\\" not in lower and "driverstore\\" not in lower and start <= 2:
        base, reason = "medium", "kernel driver outside System32\\drivers"
    title = f"Auto-start {kind} {svc.name}" if start <= 2 else f"{kind.capitalize()} {svc.name}"
    _entry(ctx, f"windows.{kind}", title, location + (" : ServiceDll" if dll else " : ImagePath"),
           dll or image, file, "T1543.003", base=base, extra_reason=reason, report_info=False)
    if image:
        target = heuristics.command_target(image)
        if target is None and driver:
            stripped = re.sub(r"^(\\systemroot\\|%systemroot%\\)", "", image, flags=re.I)
            if stripped.lower().startswith("system32"):
                target = "/Windows/" + stripped.replace("\\", "/")
        if target:
            ctx.targets.add(target)


def analyze_ntuser(hive: Any, file: str, user: str, profile: str, ctx: _Ctx) -> None:
    def entry(check: str, title: str, location: str, value: str, mitre: str, **kw: Any) -> None:
        _entry(ctx, check, f"{title} ({user})", location, value, file, mitre, user=user, profile=profile,
               **kw)

    for run in RUN_KEYS:
        for name, value in _values(_get(hive, "Software\\" + run)).items():
            entry("windows.run_key", f'Autostart entry "{name}"', f"HKCU\\Software\\{run} : {name}",
                  _str(value), "T1547.001")
    win = _values(_get(hive, f"Software\\{NT}\\Windows"))
    for name in ("Load", "Run"):
        if _str(win.get(name, "")).strip():
            entry("windows.run_key", f"Legacy autostart {name}", f"HKCU\\Software\\{NT}\\Windows : {name}",
                  _str(win[name]), "T1547.001", base="medium")
    shell = _str(_values(_get(hive, f"Software\\{NT}\\Winlogon")).get("Shell", "")).strip()
    if shell:
        entry("windows.winlogon", "Per-user logon shell", f"HKCU\\Software\\{NT}\\Winlogon : Shell", shell,
              "T1547.004", base="high")
    script = _str(_values(_get(hive, "Environment")).get("UserInitMprLogonScript", "")).strip()
    if script:
        entry("windows.logon_script", "Logon script", "HKCU\\Environment : UserInitMprLogonScript", script,
              "T1037.001", base="medium")
    autorun = _str(_values(_get(hive, "Software\\Microsoft\\Command Processor")).get("AutoRun", "")).strip()
    if autorun:
        entry("windows.cmd_autorun", "Command Processor AutoRun",
              "HKCU\\Software\\Microsoft\\Command Processor : AutoRun", autorun, "T1546", base="medium")
    folders = _values(_get(hive, f"Software\\{CV}\\Explorer\\User Shell Folders"))
    startup = _str(folders.get("Startup", "")).strip()
    if startup and DEFAULT_STARTUP not in startup.lower():
        entry("windows.startup_redirect", "Startup folder redirected",
              f"HKCU\\Software\\{CV}\\Explorer\\User Shell Folders : Startup", startup, "T1547.001",
              base="medium", extra_reason="programs in the new folder start at logon")
    _com_hijacks(_get(hive, "Software\\Classes\\CLSID"), file, user, profile, ctx)


def analyze_usrclass(hive: Any, file: str, user: str, profile: str, ctx: _Ctx) -> None:
    _com_hijacks(_get(hive, "CLSID"), file, user, profile, ctx)


def _com_hijacks(clsids: Any, file: str, user: str, profile: str, ctx: _Ctx) -> None:
    for sub in _subkeys(clsids)[:5000]:
        children = {child.name.lower(): child for child in _subkeys(sub)}
        for server in ("InprocServer32", "LocalServer32"):
            key = children.get(server.lower())
            if key is None:
                continue
            vals = _values(key)
            path = _str(vals.get("(default)", "") or vals.get("", "")).strip()
            if not path:
                continue
            lower = path.lower()
            _entry(ctx, "windows.com_hijack", f"Per-user COM server {sub.name} ({user})",
                   f"HKCU\\Software\\Classes\\CLSID\\{sub.name}\\{server}", path, file, "T1546.015",
                   user=user, profile=profile,
                   base="medium" if "\\appdata\\" in lower or "\\users\\" in lower else "low",
                   extra_reason="a per-user COM registration overrides the system one")


TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _xml_text(data: bytes) -> bytes:
    """Task XML is usually UTF-16; normalise to UTF-8 for the parser."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", "replace")
    else:
        text = data.decode("utf-8", "replace")
    text = re.sub(r'^(<\?xml[^>]*?)encoding="[^"]+"', r'\1encoding="utf-8"', text.lstrip("\ufeff"), count=1)
    return text.encode("utf-8")


def analyze_task_xml(data: bytes, file: str, name: str, ctx: _Ctx) -> None:
    text = _xml_text(data)
    head = text[:8192].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        ctx.errors.append(f"{file}: refusing XML with a DTD")
        return
    try:
        # No DTD (checked above) means no entity expansion; expat never fetches external resources.
        tree = ET.fromstring(text)  # noqa: S314
    except ET.ParseError as exc:
        ctx.errors.append(f"{file}: {exc}")
        return
    hidden = (tree.findtext(f"{TASK_NS}Settings/{TASK_NS}Hidden") or "").strip().lower() == "true"
    user = tree.findtext(f"{TASK_NS}Principals/{TASK_NS}Principal/{TASK_NS}UserId")
    for action in tree.iter(f"{TASK_NS}Exec"):
        command = (action.findtext(f"{TASK_NS}Command") or "").strip()
        arguments = (action.findtext(f"{TASK_NS}Arguments") or "").strip()
        _entry(ctx, "windows.scheduled_task", f"Scheduled task {name}", f"Task {name}",
               f"{command} {arguments}".strip(), file, "T1053.005", user=user,
               base="medium" if hidden else "info",
               extra_reason="the task is marked hidden" if hidden else None)


def analyze_wmi(data: bytes, file: str, ctx: _Ctx) -> None:
    for marker in (b"CommandLineEventConsumer", b"ActiveScriptEventConsumer"):
        for match in re.finditer(re.escape(marker), data):
            window = data[match.start():match.start() + 4096]
            strings = [s.decode("ascii", "replace") for s in re.findall(rb"[\x20-\x7e]{8,}", window)]
            wide = [s.decode("utf-16-le", "replace") for s in re.findall(rb"(?:[\x20-\x7e]\x00){8,}", window)]
            detail = " | ".join((strings + wide)[1:6])[:1500]
            if any(n in detail for n in ("SCM Event Log Consumer", "BVTConsumer")):
                continue                       # standard Windows consumers
            ctx.add(Finding("windows.wmi", f"WMI {marker.decode()}", "WMI repository (root\\subscription)",
                            detail, "high", ["WMI event subscriptions run code on system events"], file,
                            None, None, "T1546.003"))
            break


SCRIPT_EXTS = (".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".ps1", ".hta", ".pif", ".wsf")


def analyze_startup(items: list[dict[str, Any]], ctx: _Ctx) -> None:
    for item in items:
        path = item["file"]
        severity, reasons = heuristics.assess_windows(path.replace("/", "\\"))
        if path.lower().endswith(SCRIPT_EXTS):
            severity = heuristics.higher(severity, "medium")
            reasons.insert(0, "a program or script placed directly in a Startup folder")
        ctx.add(Finding("windows.startup_folder", f"Startup folder item {path.rsplit('/', 1)[-1]}", path,
                        path, severity, reasons, path, path, item.get("user"), "T1547.001"))


def task_persistence(args: dict[str, Any], fds: list[int]) -> dict[str, Any]:
    """Sandbox entry point (see offscan.sandbox.TASKS)."""
    ctx = _Ctx()
    analyzers = {"SOFTWARE": analyze_software, "SYSTEM": analyze_system}
    with tempfile.TemporaryDirectory(prefix="hives-") as tmp:
        for spec in args.get("hives", []):
            try:
                hive, replayed = _open_hive(fds[spec["fd"]], [fds[i] for i in spec.get("logs", [])], tmp)
            except Exception as exc:
                ctx.errors.append(f"{spec['file']}: cannot parse hive: {type(exc).__name__}: {exc}"[:300])
                continue
            if replayed:
                ctx.info.setdefault("replayed_logs", []).append(spec["file"])
            role = spec["role"]
            try:
                if role in analyzers:
                    analyzers[role](hive, spec["file"], ctx)
                elif role == "NTUSER":
                    analyze_ntuser(hive, spec["file"], spec.get("user", "?"), spec.get("profile", ""), ctx)
                elif role == "USRCLASS":
                    analyze_usrclass(hive, spec["file"], spec.get("user", "?"), spec.get("profile", ""), ctx)
            except Exception as exc:
                ctx.errors.append(f"{spec['file']}: analysis failed: {type(exc).__name__}: {exc}"[:300])
            del hive
    tasks = args.get("tasks")
    if tasks:
        base = tasks.get("base", "")
        for entry, data in filepack.entries(fds[tasks["fd"]], tasks["index"]):
            name = entry["file"][len(base):] if entry["file"].startswith(base) else entry["file"]
            try:
                analyze_task_xml(data, entry["file"], name, ctx)
            except Exception as exc:
                ctx.errors.append(f"{entry['file']}: {type(exc).__name__}: {exc}"[:300])
    analyze_startup(args.get("startup", []), ctx)
    wmi = args.get("wmi")
    if wmi:
        try:
            fd = fds[wmi["fd"]]
            analyze_wmi(os.pread(fd, min(os.fstat(fd).st_size, MAX_WMI), 0), wmi["file"], ctx)
        except Exception as exc:
            ctx.errors.append(f"WMI repository: {exc}"[:300])
    return {"findings": [f.to_dict() for f in ctx.findings], "targets": sorted(ctx.targets),
            "errors": ctx.errors[:100], "info": ctx.info}
