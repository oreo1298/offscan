# offscan — pre-implementation research (2026-10-20)

Every fact here comes from a research pass done before any code was written.
Tags: **[V]** verified (primary source read, package index parsed, or reproduced
in a sandbox experiment), **[S]** official page seen only through search
snippets, **[I]** inferred. Re-check anything tagged [S]/[I] before relying on it.

> Method note: the build sandbox's network policy only reaches GitHub, PyPI,
> the Ubuntu archive, Launchpad and Docker Hub. Debian/Fedora/openSUSE/Arch
> mirrors and every feed host (clamav.net, abuse.ch, sanesecurity, …) were
> unreachable from the shell, so those facts come from upstream source
> repositories on GitHub, mirrors of distro packaging state
> (github.com/archlinux/state, github.com/archlinux/aur,
> github.com/bmwiedemann/openSUSE), Launchpad's Debian mirror, and search.

## 1. Target platforms

| Distro (Oct 2026) | Python | Qt 6 | PySide6 | PyQt6 |
|---|---|---|---|---|
| Arch (rolling) + Manjaro/EndeavourOS | 3.14 [V] | 6.12 | `pyside6` 6.12.0 [V] | `python-pyqt6` |
| Debian 13 trixie (13.7) / LMDE 7 | 3.13 | 6.8.2 | `python3-pyside6.qtwidgets` 6.8.2 [S] | yes |
| Debian 12 bookworm (LTS until 2028-06) | 3.11 | 6.4.2 | **none** [V] | `python3-pyqt6` 6.4.2 [V Launchpad] |
| Ubuntu 24.04 / Mint 22.x | 3.12.3 [V] | 6.4.2 [V] | **none** [V] | `python3-pyqt6` 6.6.1 [V] |
| Ubuntu 26.04 / Mint 23 (Dec 2026) | 3.14.3 [V] | 6.10.2 [V] | 6.10.2 universe [V] | yes |
| Fedora 43 / 44 (45 slipped to late Oct) | 3.14 (45: 3.15) [S] | 6.10/6.11 | `python3-pyside6` [S] | `python3-pyqt6` |
| openSUSE Tumbleweed | 3.13 primary [V] | 6.12.0 [V] | `python313-pyside6` 6.12.0 [V] | yes |
| openSUSE Leap 16.0 | 3.13 | 6.9.1 | `python313-pyside6` 6.9.1 [S] | yes |

* Python floor **3.11** covers everything (Debian 12). [V/I]
* PySide6 on PyPI: 6.12.0, `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`,
  manylinux_2_34. The wheel bundles the gtk3 and xdgdesktopportal platform
  themes but **no KDE platform theme**, so a pip install on KDE gets Fusion. [V]
* PyQt6 is GPL-3.0 (compatible with GPL-3.0-or-later). A tiny binding shim
  lets **every** target distro use distro-packaged Qt bindings. [I]

## 2. Qt theming facts [V qtbase source]

| Feature | Since |
|---|---|
| `QStyleHints::colorScheme()` | 6.5 |
| `QPalette::Accent` (falls back to Highlight) | 6.6 |
| `QStyleHints::setColorScheme()` | 6.8 |
| xdgdesktopportal theme reads portal `color-scheme` | 6.4 (startup), 6.8 (live) |
| gtk3 platform theme maps GTK palette + fonts | 6.5 |
| gnome theme reads portal color-scheme | 6.10 |
| Portal `accent-color` read by any built-in Qt theme | **never** (dev branch, 2026-10-20) |

* On GNOME/Cinnamon/MATE/XFCE Qt picks the `gtk3` platform theme, which uses the Fusion
  style. On Ubuntu 26.04, `libqt6gui6` Recommends `qt6-gtk-platformtheme`. [V]
* KDE: Breeze style + palette via `plasma-integration` (distro Qt only).
* QGnomePlatform and adwaita-qt were **archived 2026-07-01**, so don't depend on them. [V]
* Plan: never set a style or colors; on Qt < 6.5 derive dark/light from palette
  lightness; read `org.freedesktop.appearance accent-color` ourselves over
  QtDBus and apply it to `Accent`/`Highlight` only when the platform theme
  did not already provide one.

## 3. Packaging & privilege tooling

* **nfpm v2.48.0** (2026-10-12, MIT): builds deb, rpm, archlinux. It supports per-format
  `overrides`, and env vars that expand to an empty string are *dropped* from
  depends lists. So one config can serve the Fedora and openSUSE rpms. [V source]
* AUR: hand-written PKGBUILD (`arch=('any')` unless vendored binaries),
  `license=('GPL-3.0-or-later')` SPDX, `python-build`/`python-installer`,
  `.SRCINFO`, namcap, clean-chroot build. [I]
* Layout: private modules in `/usr/lib/<app>/` + launcher in `/usr/bin`
  (Debian Python Policy for programs; avoids per-Python-version site-packages
  in rpm). [I]
* PEP 668 marker: Debian/Ubuntu, Arch, Tumbleweed have it; Fedora and Leap 16 do not.
  A venv is exempt; it must be rebuilt after a distro Python bump. [V/I]
* **polkit 128** (2026-10-15). `pkexec` is a *separate package* on
  Debian/Ubuntu (`pkexec`) and openSUSE (`pkexec`); it is included in `polkit` on
  Arch/Fedora. openSUSE's default admin auth asks for root's password. pkexec
  falls back to a text agent only with a tty. i3/sway/Hyprland etc. have no
  polkit agent. [V source / I]
* Ubuntu 26.04 live (casper) still writes a `.pkla` grant, but the `.pkla`
  backend was removed in Debian polkit 124-3, so use `sudo` (NOPASSWD on live media). [V/I]

## 4. Engines

### ClamAV [V: Cisco-Talos/clamav + clamav-documentation sources, tests in clamav/clamav:1.5 image]
* Stable **1.5.4** (2026-08); LTS **1.4.6** (patches to 2027-08, DB access to
  2028-08); 1.0 LTS DB access ends **2026-11-28**; 1.3 blocked since 2026-02.
* CDN policy: only **freshclam** or cvdupdate; "Use of Wget, Curl, or other
  command line tools that are scripted are explicitly denied". "Run FreshClam
  no more than once an hour". 429 → honour Retry-After (default 4 h cool-down
  stored in `freshclam.dat`); 403 → 24 h.
* 1.5 adds detached `*.cvd.sign` / `*.cdiff.sign` + `--cvdcertsdir`; bundles
  must carry them. `sigtool -i` verifies a CVD.
* One malformed DB file aborts the whole directory load, so test each third-party
  file on its own (`clamscan -d file eicar` → exit 1 expected).
* Private clamd: full DB load ≈ **28 s, ~1 GB RSS** (4 vCPU). Socket is bound
  only after load. Unprivileged clamd + **FILDES** or **INSTREAM** scanned a
  root-only file; path-based SCAN was denied.
* **IDSESSION** replies are out of order → client must read while sending.
* License **GPL-2.0-only** (+OpenSSL exception; bundled unrar is non-free):
  never link libclamav into our GPL-3.0+ code; sockets/subprocesses only.
* `.hsb` SHA-256 sigs: `hash:size:Name`, wildcard size needs `:73` FLEVEL;
  1M entries load in 2.5 s / ~117 MB.
* **Debian/Ubuntu specifics [V: 26.04 .deb maintainer scripts]:**
  * `clamav-daemon` postinst enables + starts the system clamd (idle until a DB
    exists); it depends on `clamav-freshclam`, whose default debconf mode starts
    the freshclam daemon.
  * Enforcing AppArmor profiles:
    * `/usr/sbin/clamd` may read config/DB/socket only under `/tmp/**`,
      `/var/lib/clamav/**`, `@{HOME}/**`, `/etc/clamav/clamd.conf`.
      Passed fds are revalidated, so files on our mounts need INSTREAM.
    * `/usr/bin/freshclam` may only use `/etc/clamav/freshclam.conf` and
      `/var/lib/clamav/**`, so a private freshclam is impossible there.
* Fedora: `clamd@` preset-disabled; package split `clamav`, `clamd`,
  `clamav-freshclam` (renamed from `clamav-update`). openSUSE / Arch: single
  `clamav` package, nothing auto-enabled.

### YARA-X / YARA
* **YARA-X 1.22.0** (released 2026-10-20; 1.0 on 2025-06-04), BSD-3-Clause, PyPI
  abi3 wheel (cp39+, manylinux_2_28 x86_64/aarch64, ~10 MB). **Not packaged by
  any distro** (AUR has only the `yr` CLI). [V]
* Python binding **does not release the GIL**, and `Scanner` is unsendable
  (panics if used from another thread). So use a **process pool**. Measured: 4
  threads 0.56 s vs 4 processes 0.32 s. [V]
* `scan_file` mmaps files over 32 MB (SIGBUS risk on bad media), so read the
  bytes ourselves and call `scan()`. [V]
* Compiled rules: serialization format v8; upstream warns never to deserialize
  rules from a third party. So bundles carry rule *sources* and we recompile. [V]
* Modules: pe, elf, macho, dotnet, dex, lnk, crx, zip, hash, math, string,
  time, console, vt, cuckoo. **No magic, no androguard.** [V]
* Classic YARA 4.5.8 (maintenance mode). yara-python on PyPI is stuck at
  4.5.4 with **no cp314 wheels**, so the fallback engine uses distro
  `python3-yara`/`python-yara` only. yara-python releases the GIL. [V]

### Hashing [V measured, no SHA-NI]
* sha256 ~350 MiB/s/core; hashlib releases the GIL.
* 2M-entry lookups: `set` 3.5M/s (~100 B/entry); sorted 32-byte mmap+bisect
  109k/s (64 MB). Lookup is never the bottleneck.

## 5. Definition sources

| Source | Access / URL | Integrity | License / terms | Proposal |
|---|---|---|---|---|
| ClamAV official | `freshclam` only (or system `/var/lib/clamav`) | CVD RSA sig + `.cvd.sign` | GPL-2.0 (data licence not stated) [S] | default |
| Sanesecurity | rsync `rsync.sanesecurity.net` or HTTP mirror `http://mirror.seichter.de/sanesecurity/`; no official HTTPS found | detached GPG `.sig`; key `4E02 5A1C BA90 A065 3F38 D2D8 D691 DED9 31EA 4D9E` (DSA-1024, 2009) [V] | free, donation asked; "copying/reproduction not permitted without permission" [S] | default: malware subset only (`sigwhitelist.ign2`, `rogue.hdb`, `malwarehash.hsb`, `badmacro.ndb`, `porcupine.hsb`, `bofhland_malware_attach.hdb`, …); email/spam DBs opt-in |
| SecuriteInfo | `https://www.securiteinfo.com/get/signatures/<ID>/<file>` (128-char ID) | `.sha256` sidecar | personal, 1 IP, ~1/h; free tier reportedly now returns a "subscribe" notice (fangfrisch #53, May 2026) [V] | opt-in (user ID), warn |
| URLhaus `.ndb` | `https://urlhaus.abuse.ch/downloads/urlhaus.ndb` (48 h of URLs) | none | abuse.ch fair use [S] | opt-in ("URL indicators", noisy on drives) |
| LMD (rfxn) | `https://cdn.rfxn.com/downloads/maldet-sigpack.tgz` + `maldet.sigs.ver` | `.sha256` sidecar | GPL-2.0 | default (`rfxn.hdb/.hsb/.ndb/.yara` are ClamAV format) |
| twinclams (Splunk) | raw GitHub | git/HTTPS | BSD-2 | opt-in (bonus) |
| MalwareBazaar | **v2 keyed exports** `https://mb-api.abuse.ch/v2/files/exports/<KEY>/sha256_full.txt.zip` + `sha256_recent.txt`; keyless URLs appear to stop 2026-10-21 [3rd-party] | none (HTTPS only) | fair use, free key from auth.abuse.ch [S] | opt-in (user key) |
| ThreatFox | `https://threatfox-api.abuse.ch/v2/files/exports/<KEY>/full.json.zip` (6-month IOC expiry) | none | same | opt-in (same key) |
| YARAify | `https://yaraify.abuse.ch/yarahub/yaraify-rules.zip` (TLP:CLEAR, per-rule licences) | none | per rule | opt-in |
| MalShare | `https://malshare.com/daily/YYYY-MM-DD/malshare_fileList.YYYY-MM-DD.sha256.txt` (+ `hashes.txt`) | sha256 list | ToS asks for credit; "not all files are malicious" [S] | opt-in (API key optional) |
| LOLDrivers | `detections/hashes/*.sha256` in github.com/magicsword-io/LOLDrivers, or `loldrivers.io/api/drivers.json` (33 MB) | git/HTTPS | Apache-2.0 [V] | default; file SHA-256 **and Authentihash** |
| ESET malware-ioc | github.com/eset/malware-ioc `*.sha256` (~6k) | git | BSD-2 [V] | default (bonus) |
| YARA Forge | `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{core,extended,full}.zip` weekly (Sun) | GitHub asset sha256 digest [V] | mixed per-rule (licence text kept per section) | **core default**; tier selectable |
| signature-base | git @commit | git | **DRL 1.1**: must show rule `author` in match output | covered by Forge; raw opt-in |
| Elastic protections-artifacts | git @commit `yara/rules` | git | **Elastic License 2.0** (not OSI) | opt-in with licence acceptance |
| ReversingLabs | git `develop` | git | MIT | covered by Forge extended/full |
| bartblaze | git | git | MIT; `category=INFO` is informational | opt-in |
| Yara-Rules/rules | git (last commit 2022) | git | GPL-2.0 | off; noisy (181/2995 benign files hit) |
| NIST NSRL RDSv3 | `https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_<ver>/RDS_<ver>_modern_minimal.zip` (~18 GiB) + quarterly deltas | `.zip.sha` + `signatures.txt` | public / NIST SD-28 | opt-in "advanced"; allowlist only |
| CIRCL hashlookup | bloom `https://cra.circl.lu/hashlookup/hashlookup-full.bloom` (~1 GB) | none | CC-BY-4.0 | **drop**: SHA-1 only, stale since 2023, online API would break no-network rule |

YARA Forge (20261018): core 5,137 rules / extended 10,811 / full 12,452; 0
compile errors on yara-x 1.22.0 and yara-python 4.5.4; core compiles in ~5 s to
8.7 MB; zero hits on 2,995 benign Linux files. Forge excludes Elastic
(licence) and bartblaze; it includes signature-base and ReversingLabs
(extended/full). [V]

fangfrisch 1.9.2 (GPL-3.0+): writes files in place, no GPG check, no
validation, uneven packaging (no Fedora/openSUSE). So **re-implement its semantics**
(provider table may be adapted with attribution). [V]

## 6. Never-write mounting [V: sandbox experiments with image sha256 before/after; Linux v7.3 source]

* `mount -o ro` **is not enough**:
  * ext4 replays the journal.
  * ext4 `ro,noload` still deletes orphan inodes.
  * XFS replays its log.
  * btrfs replays its tree log.
* Only a read-only block device stops all of it.
* **device-mapper ignores the read-only flag of its lower device** (kernel bios
  only warn). So every dm layer must itself be read-only:
  * `cryptsetup --readonly --disable-locks` (LUKS2 header auto-recovery
    otherwise writes);
  * LVM via `--config 'global{metadata_read_only=1} activation{read_only_volume_list=[...]}'`
    (never `--readonly`, which refuses activation; never `lvchange -p r`);
  * `mdadm --assemble --readonly`.
* `blockdev --setro` is sticky, so record and restore the original state.
* Recipe: `blockdev --setro <disk>` → `losetup -r` per partition → read-only dm
  layers → `mount -i -t <fs> -o ro,nosuid,nodev,noexec,nosymfollow,<no-replay>`, where `<no-replay>` is:
  * ext4: `noload`
  * XFS: `norecovery` (+`nouuid`)
  * btrfs: `rescue=nologreplay`, top level `subvolid=5` shows all subvolumes
  * NTFS: kernel `ntfs` (Linux 7.1+) → `ntfs3` → `ntfs-3g -o ro` (never `recover`/`remove_hiberfile`)
* NTFS driver availability:
  * new `ntfs` driver merged in **7.1**;
  * ntfs3 maintained again (2026);
  * Leap 16.0 kernel has **no** ntfs3;
  * Debian 12 has no ntfs3;
  * Ubuntu needs `linux-modules-extra`;
  * Fedora's config keeps changing.
  * So probe `/proc/filesystems`. On Debian/Ubuntu `mount.ntfs` is a symlink to ntfs-3g, so use `mount -i`.
* `nosymfollow` blocks escaping to the host (confirmed: without it an absolute
  symlink read the host's `/etc/hostname`). Use our own `openat2` (ctypes,
  syscall 437) with `RESOLVE_IN_ROOT` for in-target resolution. Python has `os.unshare` (3.12+) but no `os.openat2`.
* Don't use udisks: it lacks `norecovery`/`nologreplay` in its allowlist. Add a runtime
  udev rule with `UDISKS_IGNORE=1`/`UDISKS_AUTO=0` for our dm/loop devices.
* Running system: `/proc/1/mountinfo` sources of `/ /boot /boot/efi /home /usr /var`,
  holders/slaves chains, `/proc/swaps`, live-medium mountpoints
  (`/cdrom`, `/run/live/medium`, `/run/initramfs/live`, `/run/archiso/bootmnt`),
  loop backing files.
* Optional "consistent view": non-persistent dm-snapshot with RAM COW lets the
  journal replay into memory only (origin opened read-only). Untested.

## 7. Windows targets

* Hibernation/Fast Startup:
  * `hiberfil.sys` magic `HIBR`/`hibr` means a resumable image, `wake`/`RSTR` means invalidated or in progress, all-zero means none. ntfs-3g and the new ntfs driver treat any non-zero header as hibernated.
  * Fast Startup is `SYSTEM\<CCS>\Control\Session Manager\Power\HiberbootEnabled=1`.
  * ntfs-3g also refuses read-write with `$LogFile` v2.0 ("Metadata kept in Windows cache").
  * A read-only mount is safe with all drivers (data may be stale).
  * User fix: full shutdown (`shutdown /s /t 0`, Shift+Shut down, Restart) or disable Fast Startup.
* BitLocker:
  * blkid `TYPE="BitLocker"` (`-FVE-FS-`).
  * cryptsetup BITLK (≥2.3) unlocks with a password, recovery passphrase, startup key or FVEK. **TPM/smartcard are not supported**, so TPM-only volumes (the default on Windows 11 24H2 auto-encryption) need the 48-digit recovery key (aka.ms/myrecoverykey). "cryptsetup never changes BITLK header".
  * dislocker 0.7.3 (`-r`) is the fallback; it is not packaged on openSUSE.
* Registry: **regipy 6.5.0** (MIT, pure Python; deps construct, inflection,
  pytz) applies `.LOG1/.LOG2` in memory. hivex has no transaction-log support
  and its Python binding is per-Python-version. Determine CCS from `SYSTEM\Select\Current`.
* Version: `CurrentBuild >= 22000` means Windows 11 (`ProductName` lies); read `DisplayVersion`, `EditionID`, `UBR`.
* Persistence keys (Autoruns categories / ATT&CK T1547, T1546, T1543, T1053):
  * Run/RunOnce/RunOnceEx/Policies Run (+Wow6432Node)
  * Winlogon Shell/Userinit/Taskman/Notify
  * IFEO Debugger/GlobalFlag + SilentProcessExit
  * AppInit_DLLs, AppCertDlls, KnownDLLs, BootExecute
  * Active Setup StubPath
  * LSA packages
  * Print monitors/processors
  * Netsh helpers, time providers
  * Services ImagePath/ServiceDll/FailureCommand
  * COM hijack (UsrClass.dat vs HKLM)
  * Startup folders + User Shell Folders redirection
  * Tasks XML + TaskCache (flag Tree entries lacking `SD`, the Tarrask technique)
  * WMI OBJECTS.DATA (string heuristics)
* Hayabusa **4.2.0** (AGPL-3.0; 4.x uses `dfir-timeline -d <dir> -t jsonl`); Chainsaw **2.17.1**
  (GPL-3.0; `hunt <dir> -s sigma/ --mapping … --jsonl`). Neither is packaged; detect them if installed.

## 8. Linux targets

* `dpkg --root --verify` / `debsums --root` write nothing, but follow absolute
  symlinks onto the host. So parse `info/*.md5sums` and conffiles ourselves (MD5, advisory).
* `rpm --root -Va` **chroots and runs `%verifyscript` from the target**, and opens
  `rpmdb.sqlite-wal` O_RDWR|O_CREAT. Safe form: `rpm --root M --dbpath P -Va --noscripts --nodeps`
  on the read-only noexec mount, or read the DB and hash files ourselves. Always pass `--dbpath`
  (Debian's rpm defaults to `~/.rpmdb`). Tumbleweed rpmdb is **ndb**, Fedora's is sqlite.
* pacman `-Qkk --root --dbpath --config /dev/null` writes nothing; `local/*/mtree` is
  gzip'd mtree and easy to parse ourselves (pacman is rarely on non-Arch hosts).
* **chkrootkit `-r` executes the target's binaries** (blocked only by noexec)
  and runs host `ps`/`ss`, so part of its output describes the host. It is noisy. Treat it as an
  optional, sandboxed extra; port its file-based checks.
* Persistence checklist (PANIX, Elastic primer, ATT&CK Linux):
  * cron/at/anacron
  * systemd units/timers/generators/drop-ins (system + user)
  * rc.local, init.d, XDG autostart
  * shell rc files
  * SSH authorized_keys + `AuthorizedKeysCommand`/`ForceCommand`
  * ld.so.preload, ld.so.conf.d
  * PAM, extra UID 0 accounts / empty passwords, sudoers, polkit rules
  * udev `RUN+=`, update-motd, NetworkManager dispatcher, APT/DNF hooks, dbus services
  * GRUB `init=`, initramfs hooks
  * modules-load.d, `modprobe.d install`, unknown `.ko`
  * SUID/SGID and file capabilities not owned by a package
  * web shells
* journald offline: `journalctl -D <mnt>/var/log/journal -o json` (host must be ≥ target).

## 9. Licence compatibility (offscan = GPL-3.0-or-later)

| Component | Licence | How used | OK? |
|---|---|---|---|
| PySide6 / PyQt6 | LGPL-3.0 / GPL-3.0 | import | yes |
| yara-x | BSD-3-Clause | import (vendored wheel) | yes (ship notice) |
| yara-python | Apache-2.0 | import | yes (GPLv3-compatible) |
| regipy, construct, inflection | MIT | import (vendored) | yes |
| pytz | MIT | import | yes |
| cryptography | Apache-2.0 OR BSD-3 | import | yes |
| ClamAV | GPL-2.0-only | separate process (socket / subprocess) | yes; **never link libclamav** |
| cryptsetup, lvm2, ntfs-3g, dislocker, util-linux | GPL-2.0(+) | subprocess | yes |
| Hayabusa / Chainsaw | AGPL-3.0 / GPL-3.0 | optional subprocess, not shipped | yes |
| Rule/hash feeds | various (see §5) | downloaded at runtime by the user, never shipped | show licence; obey DRL author attribution |
