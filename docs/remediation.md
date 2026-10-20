# Quarantine, delete and restore

Target drives are only ever mounted read-only, with one exception: an explicit,
confirmed change to one file. That means moving it to the quarantine, deleting
it, or restoring it from the quarantine. This page describes exactly what then
happens.

## Before anything is written

1. The helper prepares a plan (`remedy.plan`). It reads the file on the
   **read-only** mount and reports its size and SHA-256. It also checks whether
   the volume can be changed at all. Changes are refused for:
   * the running system;
   * volumes the computer itself has mounted or stacked (LVM, RAID, dm-crypt
     opened by the host);
   * write-protected devices (lock switch, read-only flag set before we touched
     them);
   * hibernated Windows or Windows with Fast Startup, where writing would lose
     data when it resumes;
   * BitLocker volumes opened through dislocker;
   * filesystems we don't write to. Supported for writing are ext2/3/4, XFS,
     Btrfs, FAT, exFAT, F2FS and NTFS.
2. The GUI and the CLI show the plan in plain words: which file, its hash, that
   the volume will be mounted writable for a moment, and whether a journal will
   be replayed. Then they ask for an explicit yes. The GUI needs a ticked "I
   understand that this changes the drive" box and a clearly labelled button;
   the CLI needs the action typed in full, or `--yes`.
3. The request carries the SHA-256 the user saw. The helper checks it again on
   the read-only mount **before** mounting anything writable, so a mismatch
   never touches the disk.

## The writable session

* The read-only stack of that device is closed: mounts, mappings and loop
  devices. Two mounts of the same filesystem must never exist at the same time.
  If another of our read-only mounts shares the disk-wide read-only flag, its
  partition is protected individually first, and only then is the disk flag
  lifted.
* A writable chain is built on the raw device. Encrypted volumes are opened
  again with the passphrase the user just typed. The filesystem is mounted
  `rw,nosuid,nodev,noexec,nosymfollow`, so nothing on it can run or gain
  privileges. Every layer is recorded first in the helper's state file, so a
  crash leaves nothing behind (the next start cleans it up).
* The file is opened without following links and must be a regular file. It is
  hashed again and must still match. Then:
  * **quarantine:** a XOR-scrambled copy is written to the root-only
    quarantine (`/var/lib/offscan/quarantine/<id>/`, mode 0700) and verified.
    Only then is the original unlinked, after checking that the name still
    refers to the same inode, and the directory is synced;
  * **delete:** the same checks, then unlink;
  * **restore:** the file is created with `O_EXCL` (never over an existing
    file), then its owner, mode and times are set back.
* Everything is synced and the writable mount and mappings are closed. The
  read-only stack and mounts that existed before are then rebuilt. Device names
  of mappings can change, and the new ones are returned.

## The change log

Every attempt, successful or refused after the volume was opened writable, is
appended to `/var/lib/offscan/changes.jsonl` (mode 0600). Each line records the
time, the action, the volume, device, filesystem UUID and label, the path, size,
mode, owner, modification time, SHA-256, the quarantine id, the writable mount
driver and options, whether a journal was replayed, the requesting user's uid,
and the result or error. View it with `offscan changes`, or on the History page
of the GUI.

## What is never done

* Registry hives are never edited. Registry findings name the program they
  start, and that program can be quarantined; the entry itself must be fixed
  from Windows.
* Files that hold entries but are needed are never removed: `/etc/passwd`,
  `/etc/shadow`, `/etc/sudoers`, PAM files, `/etc/crontab`, `sshd_config`,
  shell start-up files and `authorized_keys`. The GUI says to edit them
  instead.
* Hibernation files are never removed, and journals are never replayed during
  a scan.
