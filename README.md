# Offscan

Offscan is a free (GPL-3.0-or-later) Linux desktop app that scans the drives of **non-running**
Windows and Linux installations for malware and persistence. Use it on disks you attach to
your computer, or on your computer's own disks after booting from a live USB stick.

* **Read-only by default.** Target drives are protected at the block layer and mounted
  `ro,nosuid,nodev,noexec,nosymfollow` with journal replay disabled.
* **Several engines.** ClamAV (a private, on-demand `clamd`), YARA-X (classic YARA as a
  fallback) and SHA-256 hash lists.
* **Public definitions from many sources.** These can be updated online or from a signed
  offline bundle on a USB stick.
* **No telemetry.** The network is used only to update definitions.
* **Not a real-time scanner.** There is no resident daemon and no on-access protection.

> Status: under development. Installation instructions arrive with the packaging milestone.
> See `docs/plan.md` for the plan and `docs/research.md` for the research behind it.
