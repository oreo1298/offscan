# Plan (approved 2026-10-20)

The research behind these decisions is in `docs/research.md`.

## Decisions

| Topic | Decision |
|---|---|
| Language / UI | Python ≥ 3.11, Qt 6 Widgets through a shim: PySide6 preferred, PyQt6 fallback (`offscan.gui.qt`) |
| Distros | Arch and derivatives; Debian 13 (12 best effort); Ubuntu 24.04/26.04, Mint 22/23, LMDE 7; Fedora 43–45; openSUSE Tumbleweed and Leap 16.0 |
| Privilege | Root helper launched by pkexec on demand (JSON lines over stdio). Run directly when already root; `sudo` fallback when no polkit agent |
| Workers | Scan workers and clamd run unprivileged as the invoking user; the helper passes file descriptors to the workers; the scan side has no network namespace |
| ClamAV | Private on-demand clamd (config and socket in a 0700 `/tmp` runtime dir, files streamed with INSTREAM; AppArmor-compatible). Official DB from the system freshclam where one runs (always on Debian/Ubuntu), otherwise a private freshclam |
| Debian/Ubuntu deps | Depends `clamav`, `clamav-freshclam`; Recommends `clamav-daemon` |
| YARA | YARA-X (vendored abi3 wheel in `/opt/offscan/vendor`); distro yara-python as fallback |
| Registry | regipy (vendored); transaction logs replayed in memory only |
| Packages | Per-architecture (x86_64, aarch64) because of vendored wheels; nfpm for deb/rpm, hand-written PKGBUILD |
| Default feeds | ClamAV official, Sanesecurity malware subset, LMD, YARA Forge core, LOLDrivers, ESET malware-ioc |
| Opt-in feeds | MalwareBazaar, ThreatFox, YARAify (user's abuse.ch key), MalShare, SecuriteInfo (user ID), URLhaus, Sanesecurity email sets, twinclams, YARA Forge extended/full, Elastic (licence acceptance), bartblaze, raw signature-base / ReversingLabs, Yara-Rules (unmaintained), NSRL (advanced) |
| Dropped | CIRCL hashlookup (SHA-1 only, about 1 GB, stale; the online API would break the no-network rule) |
| Offline bundles | Raw upstream files with their own signatures and licences, Ed25519-signed manifest; rules recompiled on import. Sanesecurity included by default with a "for your own machines only" notice (it can be switched off) |
| Log tools | Hayabusa/Chainsaw used if installed, never bundled |
| App ID | `io.github.oreo1298.offscan`, display name "Offscan" (all in `src/offscan/appinfo.py`) |
| Git | Milestone commits on branch `dev` |
| Distro container tests | GitHub Actions (this sandbox can only reach Ubuntu mirrors) |

## Milestones

* **M0 Foundation:** layout, appinfo, Qt shim, protocol, logging, CI.
* **M1 Drives and safe mounting:** enumeration; detection (OS, encryption, hibernation, running system); read-only pipeline; polkit policy; CLI.
* **M2 Scan engine:** walker, workers, hash/YARA/clamd engines, scan modes, limits, reports, CLI.
* **M3 Definitions:** sources, verification, atomic sets with rollback, bundles, CLI.
* **M4 Persistence and integrity:** Windows and Linux checks; package verification; optional tools (see `docs/checks.md`).
* **M5 GUI:** all pages, theming, accessibility, quarantine/delete (see `docs/remediation.md`).
* **M6 Packaging:** nfpm, PKGBUILD, `install.sh`, README, container tests.
* **M7 Hardening:** security review, fuzzing, release.

Every milestone ends with its tests run and the results reported, then a commit.
