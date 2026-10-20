# Persistence and integrity checks

Besides the file scan, every quick or full scan looks at how the installations
on the selected volumes start programs, and whether their system files are
the ones their packages installed. Custom (path) scans skip these checks.
They can also be switched off with `--no-persistence` / `--no-integrity`.

Everything is read from the read-only mount. The helper (root) only opens
and reads files. All parsing (registry hives, task XML, cron, systemd units,
package databases) runs in the unprivileged, network-less, resource-limited
sandbox, and nothing from the target is ever executed.

## How findings are rated

| Severity | Meaning |
|---|---|
| high | A known persistence or rootkit technique, or a modified system program. Examples: a Run key starting a program from `C:\Users\Public`, `/etc/ld.so.preload`, an IFEO debugger on `sethc.exe`, a second UID-0 account. |
| medium | Unusual and worth a look. Examples: a service binary outside the system folders, an unknown print monitor, passwordless sudo for everything. |
| low | Noteworthy but often legitimate. Examples: `PermitRootLogin yes`, a program in `/usr/bin` that no package installed. |
| info | Inventory: autostart entries that look normal. They are listed in reports (and with `--all` in the CLI) but don't count as detections or affect the exit code. |

Heuristics raise the severity of an entry. For example, encoded PowerShell,
`curl … | sh`, `/dev/tcp/` reverse shells, programs in temporary or hidden
folders, or miners. Heuristics never create findings on their own. Each
finding carries its MITRE ATT&CK technique where one applies.

Programs that autostart entries start are always scanned with all engines,
even in quick mode and even inside folders a quick scan normally skips.

## Windows

* **Run keys:** Run, RunOnce, RunOnceEx, Policies\Explorer\Run, RunServices(Once), including Wow6432Node and every user's NTUSER.DAT; legacy `Windows\Load`/`Run`.
* **Winlogon:** Shell, Userinit, Taskman, AppSetup, and the per-user Shell.
* **Image File Execution Options:** Debugger values (accessibility-tool backdoors are flagged separately) and the SilentProcessExit monitor.
* **DLL injection points:** AppInit_DLLs, AppCertDlls, LSA authentication/notification/security packages, print monitors, netsh helpers and time providers.
* **Services and drivers:** the current ControlSet's auto-start entries, `ServiceDll`, and `FailureCommand`.
* **Boot and shell hooks:** BootExecute, Command Processor AutoRun, Active Setup, logon scripts (`UserInitMprLogonScript`), and redirected Startup folders.
* **COM hijacking:** per-user CLSID registrations (NTUSER.DAT and UsrClass.dat).
* **Scheduled tasks:** `Windows\System32\Tasks` XML (DTDs refused), hidden tasks, and TaskCache entries with no security descriptor (the "Tarrask" technique).
* **Startup folders:** per-user and all-users.
* **WMI:** event-consumer subscriptions in the repository (string heuristics).
* **Dirty hives:** transaction logs (`.LOG1`/`.LOG2`) are replayed into a private copy, never onto the disk.
* **Drivers:** the scan worker computes the Authenticode hash of native-subsystem PE files (and `*.sys`) and looks it up in the LOLDrivers Authentihash lists. That also catches re-signed copies whose file hash differs. The implementation matches `osslsigncode`'s computed digest.

## Linux

* **Scheduled jobs:** cron (`/etc/crontab`, `cron.d`, the per-period folders, user crontabs on Debian/Fedora/openSUSE), anacron, and at jobs.
* **systemd:** system and user units, drop-ins (`*.d/*.conf` overriding commands), timers, enabled links pointing outside the unit folders, and generators.
* **Boot and session scripts:** `rc.local`, `init.d`, the X session scripts, XDG autostart (system and per user) and KDE env scripts.
* **Shell start-up files:** system and per user (bash, zsh, fish, csh, `environment.d`). Only suspicious lines are reported, such as `alias sudo=…` or `trap … DEBUG`.
* **SSH:** `authorized_keys` keys (fingerprints, `command=` options, keys of service accounts, `authorized_keys2`). Also `sshd_config` and its `.d` files: empty passwords, root password logins, `PermitUserEnvironment`, unusual `AuthorizedKeysFile`, and `AuthorizedKeysCommand`.
* **Library hijacking:** `/etc/ld.so.preload`, and `ld.so.conf` paths in temporary or home folders.
* **Accounts:** extra UID-0 accounts, empty passwords, and service accounts with passwords. Password hashes are never copied out of the sandbox.
* **sudo:** passwordless rules, rules for service accounts, `!authenticate`, `env_keep` of `LD_PRELOAD`, and unsafe file permissions.
* **PAM:** `pam_permit` as a sufficient auth module, modules loaded from outside the security folders, and `pam_exec` (especially with `expose_authtok`).
* **Other hooks:** udev `RUN`/`PROGRAM`, APT and pacman hooks, D-Bus activation files (system and per user), local initramfs-tools hooks, modprobe `install` commands, and GRUB `init=`.
* **polkit:** rules that allow every action.
* **Hiding places:** names like `...` or `.. `, regular files in `/dev`, and executables in `/tmp`, `/var/tmp` and `/dev/shm`.
* **Layouts:** btrfs subvolume installations (`/@`, `/root`, …) and separate home volumes are recognised.

### Package verification

| Package manager | Database read | Digest |
|---|---|---|
| dpkg (Debian, Ubuntu, Mint) | `/var/lib/dpkg/status` (conffiles), `info/*.md5sums`, `info/*.list`, `diversions` | MD5 |
| pacman (Arch and derivatives) | `local/*/desc`, `files` (`%BACKUP%`), gzip'd `mtree` | SHA-256 |
| rpm sqlite (Fedora ≥ 33, RHEL 9) | `rpmdb.sqlite` (+ `-wal`), headers decoded natively | per package, usually SHA-256 |
| rpm ndb (openSUSE) | `Packages.db`, decoded natively | per package |
| rpm Berkeley DB (old releases) | needs the host's `rpm` (read-only query of a private copy) | per package |

The target's own package tools are never run (`rpm --root -Va` would run the
target's scripts). A quick scan verifies system programs and libraries:
`/usr/bin`, `/usr/sbin`, PAM modules, the dynamic loader, libc, libpam,
libcrypt, libnss, libssl, libkeyutils, systemd, OpenSSH and sudo, plus every
program an autostart entry starts. A full scan verifies every packaged file.
Changed configuration files are reported as informational.

### Files no package installed

* **SUID/SGID programs** found during the scan walk. Those in temporary, home or hidden folders, or in system folders, rate high; those in `/usr/local` or `/opt` rate low.
* **PAM modules** in the security folders rate high.
* **Kernel modules** below `/usr/lib/modules` rate medium. DKMS/akmods folders (`updates`, `extra`) are skipped.
* **systemd units and generators** in `/usr/lib/systemd` rate medium.
* **Programs in `/usr/bin` and `/usr/sbin`** rate low.

### Not checked yet

File capabilities (`security.capability` extended attributes), the systemd
journal, and web shells beyond what the YARA and ClamAV rules cover.

## Optional external tools

Not bundled, and used only when installed and requested with
`--tool NAME` (or the matching setting):

| Tool | Licence | Used for |
|---|---|---|
| chkrootkit | BSD-2-Clause | its file-based tests on Linux targets (tests that look at the running host are left out) |
| Hayabusa | AGPL-3.0 | Sigma rules over `Windows\System32\winevt\Logs` (`dfir-timeline … -t jsonl`; 3.x `json-timeline -L`) |
| Chainsaw | GPL-3.0 | its rules (and Sigma, if found next to it) over the same event logs |

They run in the helper's empty network namespace as the unprivileged scan
user with only `CAP_DAC_READ_SEARCH` (`setpriv --no-new-privs`, with the
bounding set reduced to that one capability). So they can read the target
but write nothing outside their private output folder. The target is mounted
`noexec`, so chkrootkit cannot run the target's binaries; it insists on uid 0,
so a one-line `id` shim answers that check. Their output is size-limited and
parsed as untrusted text.
