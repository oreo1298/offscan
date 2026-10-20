# Changelog

All notable changes. Versions follow [PEP 440](https://peps.python.org/pep-0440/);
packages map them to each format (see `packaging/build.py version`).

## 0.1.0

First release.

### Scanning

* Scans the drives of Windows and Linux installations that are not running:
  attached disks, or a computer's own disks after booting from a live USB stick.
* **Read-only by default.**
  * Block devices are set read-only.
  * Mounts go through read-only loop or device-mapper layers, with
    `ro,nosuid,nodev,noexec,nosymfollow` and no journal replay.
  * Every layer is cleaned up after a crash.
* **Drives it opens:** LUKS and BitLocker (read-only; recovery key or password,
  dislocker as a fallback), LVM, and Btrfs subvolumes.
* **Filesystems:** ext2/3/4, XFS, Btrfs, F2FS, NTFS (ntfs3 or ntfs-3g), FAT,
  exFAT and more.
* **Running system detection:** it recognises the running system (including
  its automounted boot partitions), live media, hibernated Windows and Fast
  Startup.
* **Engines:** ClamAV (a private, on-demand clamd), YARA-X (classic YARA as a
  fallback), SHA-256 hash lists and Authenticode hashes of drivers.
* **Scan modes:** quick (programs, scripts and high-risk folders), full, or
  chosen folders.
* **Limits** on file and archive size and archive depth; pause, resume and
  cancel.
* **Persistence checks:**
  * Windows: Run keys, services, drivers, scheduled tasks (including hidden
    ones), WMI, Winlogon, IFEO, AppInit, LSA, print monitors, startup folders and
    more.
  * Linux: cron, systemd, shell start-up files, SSH keys and server
    configuration, sudoers, PAM, udev, `ld.so.preload`, kernel modules, polkit
    and more.
  * Findings come with MITRE ATT&CK ids. Programs that autostart entries start
    are always scanned.
* **Integrity checks:** dpkg, rpm (sqlite, ndb and BDB) and pacman package
  verification, plus SUID/SGID files, PAM and kernel modules, and units that no
  package installed.
* **Optional external checkers:** chkrootkit, Hayabusa and Chainsaw, if
  installed.
* **Reports:** HTML, CSV and JSON, with a scan history and false-positive marks.

### Changes to a drive

* Quarantine, delete and restore of one file. Each is an explicit, confirmed
  change: the volume is mounted writable for that change only, and every change
  is logged in `/var/lib/offscan/changes.jsonl`.
* Changes are refused for the running system, the host's own mounts,
  write-protected devices, hibernated Windows and dislocker volumes.

### Definitions

* **Sources enabled by default:** ClamAV official signatures, the Sanesecurity
  malware subset, Linux Malware Detect, YARA Forge core, LOLDrivers and ESET
  malware-ioc. More can be enabled (abuse.ch, MalShare, SecuriteInfo, Elastic,
  NSRL, ...).
* Each source is verified with its own signatures and checksums.
* Definition sets are activated atomically, with rollback.
* Signed (Ed25519) offline bundles carry definitions to computers without
  internet.
* **No telemetry.** The network is used only for definition updates.

### Interface

* A Qt 6 window, through PySide6 or PyQt6. It follows the desktop's colour
  scheme, accent colour, fonts and icons, and is keyboard and screen-reader
  friendly.
* A command line with the same features; man pages for both.

### Packages

* .deb for Debian 12/13, Ubuntu 24.04/26.04, Linux Mint and LMDE.
* .rpm for Fedora and for openSUSE Tumbleweed and Leap 16.0.
* An AUR PKGBUILD for Arch Linux and its derivatives.
* x86_64 and aarch64.
* `install.sh --install / --update / --uninstall` for installing from a source
  checkout.
* Install, upgrade and removal tests in containers of each distribution.

### Security

See [docs/security.md](docs/security.md). Before the release, four reviews looked
at the root helper, the handling of hostile drive data, the definitions system and
the packaging, and fuzz tests covered every parser. Among the fixes:

* chkrootkit's `aliens` test is no longer run. It pasted target file names
  into shell commands.
* External checkers run without capabilities.
* Scanners, clamd and parsers run as a dedicated `offscan` system account
  instead of the desktop user.
* Only the invoking user can enter mounted drives.
* Restores are bound to the original filesystem, and lose setuid and setgid.
* Bundles cannot reference local files, weaken the scan, or roll definitions
  back unnoticed.
* YARA includes are off, and ClamAV bytecode runs with runtime checks.
* A quadratic regular expression and several parser crashes were fixed.
* CLI output escapes terminal control characters.
