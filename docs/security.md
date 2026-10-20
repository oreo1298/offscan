# Security design

Offscan reads drives that may have been prepared by an attacker, and it needs
root to do so. This page says what it protects, against whom, and how. It also
says what it cannot protect against.

## Who might attack, and what they control

| Adversary | Controls | Must never get |
|---|---|---|
| The drive being scanned | Everything on it: filesystem metadata, file names, contents, registry hives, package databases, links | Code execution anywhere; changes to the drive; access to the host's files; a scan that silently skips what it should check |
| Other local accounts | Their own processes and files, FUSE mounts, `/tmp` | Access to the mounted drives, the quarantine or the change log; a way to keep a drive mounted writable |
| Definition feeds, mirrors, the network | The bytes they serve | Local files pulled into a definition set; scanner settings that weaken it; old definitions served again |
| An offline bundle | Its contents. Its signature is checked against keys you trust | The same as the feeds, even when the signer is trusted |
| Malware in your desktop session | Your user account | Root, by reusing an authorisation you gave Offscan |

## How the privileges are split

| Process | Runs as | Can |
|---|---|---|
| `offscan` / `offscan-gui` | you | Ask the helper for things; read and write your definitions, history and reports |
| `offscan-helper` | root, started by pkexec (or sudo) | Find, unlock and mount drives read-only; open files for scanning; make the one confirmed change. It has its own empty network namespace, writes no core dumps and is not dumpable, and only one runs at a time. |
| Scan workers, `clamd`, the parsing sandbox, chkrootkit / Hayabusa / Chainsaw | the `offscan` system account (`nobody` if it is missing) | Read the files the helper hands them as descriptors. They have no network, `no_new_privs`, resource limits and no capabilities. They are never your desktop account, so a parser compromised by a crafted file gets neither your files nor your session. |

The polkit action requires an administrator password (`auth_admin_keep` for the
active session). pkexec ties the kept authorisation to the process that asked for
it, so another program of yours cannot reuse it. If the helper is not installed,
it is only run from a source checkout when `OFFSCAN_DEV_HELPER=1` is set.

The helper treats its client as authenticated but not trusted: every request is
checked against a schema with size limits, at most 64 requests can be in flight,
and only one scan runs at a time. The helper builds the scan's runtime directory
itself from your definition set, so the client chooses neither the engines'
configuration nor their socket. It opens every file of the set relative to the
set's directory, without following links, and accepts only regular files you
own with plain names.

## Read-only, and the one exception

* Before anything is mounted, the block device is set read-only with `BLKROSET`.
  Mounts then go through a read-only loop device or a read-only device-mapper
  table.
* Mount options are `ro,nosuid,nodev,noexec,nosymfollow`, and journal replay
  is turned off (`noload`, `norecovery`, `nologreplay`). The options are checked
  in `/proc/self/mountinfo` after mounting. Every layer is recorded in a state
  file before it is created, so a crash leaves nothing behind.
* Quarantine, delete and restore are the only writes. Each is an explicit,
  confirmed request, described in [remediation.md](remediation.md). Changes are
  refused for:
  * the running system, including its boot partitions while they are
    automounted but not mounted;
  * the host's own mounts and device stacks;
  * write-protected devices;
  * hibernated Windows;
  * dislocker volumes.
* The file's hash is checked on the read-only view before anything is mounted
  writable.
* The writable mount sits in a root-only directory and has root-only file
  modes. If it cannot be unmounted, it is detached and no read-only view is
  rebuilt next to it.
* A quarantined file can only go back to the filesystem it came from (checked
  by UUID), and never with setuid or setgid.

## Drives the scan reads

* **Opening files.** Root opens target files one path component at a time
  (`openat` with `O_PATH`/`O_NOFOLLOW`; `..` never reaches the kernel). Absolute
  links restart at the target's root. The final open uses
  `O_NOFOLLOW|O_NONBLOCK` and requires a regular file, so FIFOs and device nodes
  are never read. Mounts have `nosymfollow`, and the external checkers do not
  run without it.
* **Parsing.** Everything that parses target data runs in the sandbox, as the
  scan account. This covers registry hives (with transaction-log replay into a
  private copy), task XML (a DTD is refused), cron, systemd units and package
  databases. Event logs are only read by the optional external checkers, as the
  same account. What root parses itself is small and bounded:
  superblocks, hibernation headers, `os-release`, `passwd`. Root reads at most
  512 MiB of a sandbox's reply.
* **Fuzz testing.** Every such parser is fuzz-tested (`tests/fuzz`): it either
  returns a result or raises its documented error. The tests also check that
  escaping never lets control characters through, that archive names stay
  inside their directory, that decompression stays within its limit, and that
  the root-side path patterns run in linear time.
* **External checkers.** Only root-owned copies that nobody else can write are
  run. They get no standard input, a file-size limit and a 077 umask. chkrootkit's
  `aliens` test is left out: it pastes target file names into shell commands.
* **Output.** CLI output goes through a filter that shows terminal control
  characters instead of sending them. The GUI shows target text as plain text and
  tooltips as escaped HTML. HTML reports are escaped and have a
  `default-src 'none'` CSP, and CSV cells cannot start a formula.
* **Mount access.** Mounted drives can only be entered by root, you (through a
  POSIX ACL) and the scan account. Other local accounts cannot read them.

## Definitions

* **Downloads.**
  * HTTPS only, with TLS 1.2 or newer and certificate checks. Redirects never
    downgrade to HTTP.
  * Every download has size limits, an overall deadline and can be cancelled.
  * API keys sent in headers are not repeated after a redirect.
* **Integrity of the feeds.**
  * ClamAV's own databases come only from freshclam and are checked with sigtool.
  * Sanesecurity files are GnuPG-verified against its pinned key. Its mirrors use
    plain HTTP, so a signature older than the installed copy is refused, which
    stops replay.
  * Other feeds are checked against their published checksums or signatures
    where they publish any (see `offscan defs sources`).
* **Building a set.** A definition set may only use plain files inside each
  source's own version directory, and only material that matches the source's
  kind.
* **Rule engines.**
  * YARA `include` is disabled.
  * Compiled YARA rules are always built locally, never loaded from a bundle.
  * clamd runs with `BytecodeSecurity Paranoid`.
* **Offline bundles.**
  * The manifest is signed with Ed25519, and every file must be listed in it with
    its size and SHA-256.
  * Archive paths are checked, and only regular files are extracted.
  * A key is trusted only from at least 40 hex digits of its fingerprint.
  * Bundles older than the installed definitions need `--allow-older`.
  * Allow-lists are accepted only from sources that publish them, and ClamAV
    bytecode only in signed `.cvd` files.
  * The import holds the update lock and puts the previous state back if the new
    set cannot be built.

## Packaging and installation

* **Wheels.** The vendored wheels are pinned by SHA-256. Unpacking refuses
  absolute paths, `..`, links and `.data` directories. install.sh checks and
  unpacks each wheel from a private copy.
* **Launchers.** They run the system Python with `-I` (no environment, no user
  site, not the script's directory). They never write byte-code and put the
  vendored packages after the standard library.
* **install.sh.**
  * It records every file with its SHA-256, and never removes a file that changed
    after installation.
  * It deletes data in your home only after asking, from a process that runs as
    the home's owner, so a link planted in a home directory cannot make root
    delete something else.
  * Run as root in someone else's checkout, it never calls git.
* **CI.** Actions are pinned by commit, checkouts keep no credentials, and the
  nfpm download is checked by SHA-256.

## What remains

* **The kernel parses the drive as root.** Mounting a filesystem is the job of
  the kernel's filesystem driver (or ntfs-3g, which runs as root). A drive
  crafted against a driver bug attacks the kernel. Offscan only mounts the types
  it needs, read-only and without journal replay. Keep your kernel updated.
  A stricter design would mount in a VM (libguestfs) or with a userspace kernel
  (lklfuse).
* **You are trusted.** An administrator who authenticates can write any
  definitions they like. When scanning the running system, a rule could be
  written to tell whether a root-only file matches it. Scanning the running
  system is meant for administrators, and it is less reliable anyway: files
  change during the scan.
* **No seccomp filter yet.** The sandbox and the workers rely on a separate
  account, `no_new_privs`, resource limits and the empty network namespace. A
  syscall filter would narrow the kernel surface further.
* **Scanners can be evaded.** Like any scanner, Offscan finds what its
  definitions and checks know about. Clean results are not a proof.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on the repository (Security >
Report a vulnerability) rather than a public issue; see
[SECURITY.md](../SECURITY.md).

## Review history

Before 0.1.0, four reviews looked at the root helper, the handling of hostile
drive data, the definitions system and the packaging. The fuzz tests found
further crashes. The fixes are listed in the commits "M7 hardening, part 1" to
"part 4" and in [CHANGELOG.md](../CHANGELOG.md). The most serious ones:

* a shell injection through target file names in chkrootkit's `aliens` test;
* other local accounts being able to read mounted drives;
* a trusted bundle being able to pull local files into a definition set;
* parsers running as the desktop user.
