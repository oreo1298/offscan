"""ClamAV-format sources: official databases, Sanesecurity, SecuriteInfo, URLhaus, LMD."""

from __future__ import annotations

import os
import re
import shutil
import time
from importlib import resources
from pathlib import Path
from typing import Any

from ... import log, tools
from .. import layout, net, verify
from .base import DAY, HOUR, FetchContext, Source, SourceError, SourceInfo, Unchanged, write_material

logger = log.get("defs.clamav")
MiB = 1 << 20


# -- official ClamAV ------------------------------------------------------------

def system_db_state(directory: str | None = None) -> dict[str, Any]:
    directory = directory or layout.SYSTEM_CLAMAV_DIR
    files = layout.system_clamav_files(directory)
    names = {p.name for p in files}
    has_main = any(n.startswith("main.") for n in names)
    has_daily = any(n.startswith("daily.") for n in names)
    newest = max((p.stat().st_mtime for p in files), default=0.0)
    return {"present": has_main and has_daily, "newest": newest, "files": sorted(names),
            "dir": directory}


def freshclam_confined() -> bool:
    """True when an AppArmor profile restricts freshclam to the system paths (Debian/Ubuntu)."""
    try:
        with open("/sys/kernel/security/apparmor/profiles", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return os.path.exists("/etc/apparmor.d/usr.bin.freshclam") and \
            os.path.isdir("/sys/kernel/security/apparmor")
    return any("freshclam" in line and "(enforce)" in line for line in text.splitlines())


def _daily_version(directory: Path) -> str:
    for name in ("daily.cld", "daily.cvd"):
        path = directory / name
        if path.exists():
            try:
                info = verify.cvd_info(path)
                return f"daily {info.get('version', '?')}"
            except verify.VerificationError:
                return f"daily ({time.strftime('%Y-%m-%d', time.gmtime(path.stat().st_mtime))})"
    return "unknown"


class ClamAVOfficial(Source):
    info = SourceInfo(
        id="clamav", name="ClamAV official signatures", kind="clamav",
        homepage="https://www.clamav.net/", license="GPL-2.0 (ClamAV)",
        license_url="https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt",
        terms="Downloaded only with ClamAV's own freshclam, as Cisco Talos requires; at most "
              "once per hour. Where the distribution already runs freshclam (Debian, Ubuntu), "
              "its database is used and nothing extra is downloaded.",
        default_enabled=True, min_interval=HOUR, size_hint="about 110 MB", group="ClamAV",
        integrity="digitally signed CVD files, verified by freshclam and sigtool")

    def mode(self) -> str:
        wanted = self.settings.data.get("clamav_official", "auto")
        if wanted in ("system", "private", "off"):
            return wanted
        state = system_db_state()
        if state["present"] and (time.time() - state["newest"] < 7 * DAY or freshclam_confined()):
            return "system"
        if freshclam_confined():
            return "system"
        return "private"

    def private_db(self, store: Path) -> Path:
        return store / "sources" / self.id / "freshclam-db"

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        mode = self.mode()
        if mode == "off":
            raise SourceError("disabled in settings")
        if mode == "system":
            state = system_db_state()
            if not state["present"]:
                raise SourceError(
                    "no ClamAV database in /var/lib/clamav. Enable the distribution's updater: "
                    "'sudo systemctl enable --now clamav-freshclam' (Debian/Ubuntu: package "
                    "clamav-freshclam).")
            version = _daily_version(Path(state["dir"]))
            if ctx.previous and ctx.state.get("version") == version:
                raise Unchanged("system database unchanged")
            return write_material(ctx.staging, {
                "clamav": [], "clamav_official": "system", "version": version,
                "verified": "system freshclam", "updated": state["newest"]})
        return self._fetch_private(ctx)

    def _fetch_private(self, ctx: FetchContext) -> dict[str, Any]:
        freshclam = tools.find("freshclam")
        if freshclam is None:
            raise SourceError("freshclam is not installed (package clamav / clamav-update / "
                              "clamav-freshclam)")
        db = self.private_db(ctx.store)
        db.mkdir(parents=True, exist_ok=True)
        conf = db.parent / "freshclam.conf"
        conf.write_text("\n".join([
            f"DatabaseDirectory {db}",
            f"UpdateLogFile {db.parent / 'freshclam.log'}",
            "LogTime yes",
            "DatabaseMirror database.clamav.net",
            "ScriptedUpdates yes",
            "Bytecode yes",
            "TestDatabases yes",
            "Foreground yes",
        ]) + "\n", encoding="utf-8")
        ctx.progress("Running freshclam…")
        proc = tools.run([freshclam, f"--config-file={conf}", f"--datadir={db}", "--stdout"],
                         timeout=3600, check=False)
        output = proc.stdout + proc.stderr
        match = re.search(r"cool-?down until (.+)", output, re.I)
        if match:
            raise net.RateLimited("database.clamav.net", 4 * HOUR)
        if proc.returncode not in (0, 1):
            tail = output.strip().splitlines()[-3:]
            raise SourceError(f"freshclam failed ({proc.returncode}): {' | '.join(tail)[:400]}")
        files = sorted(p for p in db.iterdir()
                       if p.is_file() and p.suffix in (".cvd", ".cld", ".cud", ".sign"))
        if not any(p.name.startswith("main.") for p in files):
            raise SourceError("freshclam did not produce a main database")
        version = _daily_version(db)
        if ctx.previous and ctx.state.get("version") == version:
            raise Unchanged("up to date")
        names = []
        for path in files:
            shutil.copyfile(path, ctx.staging / path.name)
            names.append(path.name)
        for name in names:
            if name.endswith(".cvd"):
                verify.cvd_info(ctx.staging / name)
        return write_material(ctx.staging, {
            "clamav": names, "clamav_official": "private", "version": version,
            "verified": "freshclam + sigtool"})


# -- Sanesecurity ----------------------------------------------------------------

SANESECURITY_FPR = {"4E025A1CBA90A0653F38D2D8D691DED931EA4D9E"}
SANESECURITY_MIRROR = "http://mirror.seichter.de/sanesecurity/"


def sanesecurity_keyring() -> Path:
    return Path(str(resources.files("offscan") / "data" / "keys" / "sanesecurity.gpg"))


class _Sanesecurity(Source):
    files: tuple[str, ...] = ()

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        base = self.base_url(SANESECURITY_MIRROR).rstrip("/") + "/"
        changed = False
        names = []
        for name in self.files:
            ctx.check_cancel()
            ctx.progress(f"Sanesecurity: {name}")
            try:
                data = ctx.download(base + name, name, max_size=64 * MiB, allow_http=True)
                sig = ctx.download(base + name + ".sig", name + ".sig", max_size=64 * 1024,
                                   allow_http=True, conditional=False)
                verify.gpg_verify(data, sig, sanesecurity_keyring(), SANESECURITY_FPR)
                changed = True
            except Unchanged:
                ctx.reuse(name)
                ctx.reuse(name + ".sig")
            except net.DownloadError as exc:
                if "HTTP 404" in str(exc):
                    logger.warning("Sanesecurity: %s is no longer published; skipping", name)
                    continue
                raise
            names.append(name)
        if not changed:
            raise Unchanged("all files unchanged")
        verify_files = [ctx.staging / n for n in names]
        for path in verify_files:
            verify.clamav_load_test(path)
        version = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ctx.now))
        return write_material(ctx.staging, {"clamav": names, "version": version, "verified": "gpg"})


class SanesecurityMalware(_Sanesecurity):
    info = SourceInfo(
        id="sanesecurity", name="Sanesecurity (malware signatures)", kind="clamav",
        homepage="https://sanesecurity.com/", license="Sanesecurity terms",
        license_url="https://sanesecurity.com/legal/",
        terms="Free to use; a donation is appreciated. Redistribution or public mirroring needs "
              "Sanesecurity's permission; offline bundles are for your own machines only.",
        default_enabled=True, min_interval=4 * HOUR, size_hint="a few MB", group="ClamAV",
        integrity="GnuPG signature of every file (Sanesecurity key 31EA4D9E); mirrors may be "
                  "plain HTTP, which the signature makes safe")
    files = ("sigwhitelist.ign2", "rogue.hdb", "malwarehash.hsb", "badmacro.ndb", "porcupine.hsb",
             "bofhland_malware_attach.hdb", "hackingteam.hsb", "winnow_malware.hdb",
             "winnow_extended_malware.hdb")


class SanesecurityEmail(_Sanesecurity):
    info = SourceInfo(
        id="sanesecurity-email", name="Sanesecurity (e-mail: phishing, spam, scams)", kind="clamav",
        homepage="https://sanesecurity.com/", license="Sanesecurity terms",
        license_url="https://sanesecurity.com/legal/",
        terms="As Sanesecurity (malware). Useful only for scanning stored e-mail (mbox, .eml); "
              "on normal files it mostly adds noise.",
        default_enabled=False, min_interval=4 * HOUR, size_hint="about 20 MB", group="ClamAV",
        integrity="GnuPG signature of every file",
        warning="Matches URLs and spam text; expect hits in browser caches and mailboxes.")
    files = ("sanesecurity.ftm", "junk.ndb", "jurlbl.ndb", "phish.ndb", "scam.ndb", "spamimg.hdb",
             "spamattach.hdb", "blurl.ndb", "lott.ndb", "spear.ndb", "spearl.ndb")


# -- SecuriteInfo -----------------------------------------------------------------

class SecuriteInfo(Source):
    info = SourceInfo(
        id="securiteinfo", name="SecuriteInfo", kind="clamav",
        homepage="https://www.securiteinfo.com/clamav-antivirus/improve-detection-rate-of-zero-day-malwares-for-clamav.shtml",
        license="SecuriteInfo terms (personal use, no redistribution)",
        license_url="https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml",
        terms="Needs your own (free) SecuriteInfo account ID. The free plan allows one IP and "
              "limited downloads; offline bundles are for your own machines only.",
        default_enabled=False, requires_secret="securiteinfo_id", min_interval=4 * HOUR,
        size_hint="about 100 MB", group="ClamAV", integrity="HTTPS + format validation",
        warning="In 2026 the free tier reportedly returns a subscription notice instead of "
                "signatures; this is detected and reported.")
    files = ("securiteinfo.hdb", "securiteinfo.ign2", "javascript.ndb", "securiteinfohtml.hdb",
             "securiteinfoascii.hdb", "securiteinfoandroid.hdb", "securiteinfoold.hdb",
             "securiteinfopdf.hdb")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        ident = ctx.secret("securiteinfo_id")
        if not ident or not re.fullmatch(r"[A-Za-z0-9]{16,256}", ident):
            raise SourceError("set your SecuriteInfo ID (letters and digits) in the settings")
        base = self.base_url("https://www.securiteinfo.com/get/signatures/").rstrip("/")
        names, changed = [], False
        for name in self.files:
            ctx.check_cancel()
            try:
                path = ctx.download(f"{base}/{ident}/{name}", name, max_size=512 * MiB)
                try:
                    verify.sanity_check_clamav_text(path, 0 if name.endswith(".ign2") else 1)
                except verify.VerificationError as exc:
                    raise SourceError(f"{exc}. SecuriteInfo may require a paid subscription for "
                                      "this file now.") from None
                changed = True
            except Unchanged:
                ctx.reuse(name)
            names.append(name)
        if not changed:
            raise Unchanged("all files unchanged")
        for name in names:
            verify.clamav_load_test(ctx.staging / name)
        return write_material(ctx.staging, {"clamav": names, "verified": "https",
                                            "version": time.strftime("%Y-%m-%d %H:%M", time.gmtime(ctx.now))})


# -- URLhaus ------------------------------------------------------------------------

class URLhaus(Source):
    info = SourceInfo(
        id="urlhaus", name="URLhaus (abuse.ch) URL signatures", kind="clamav",
        homepage="https://urlhaus.abuse.ch/", license="abuse.ch terms of use (fair use)",
        license_url="https://abuse.ch/terms-of-use/",
        terms="Free under abuse.ch's fair-use terms; commercial use needs a Spamhaus licence. "
              "Contains URLs of active malware sites (last 48 hours).",
        default_enabled=False, requires_secret="abusech_auth_key", secret_optional=True,
        min_interval=HOUR, size_hint="< 5 MB", group="ClamAV", integrity="HTTPS + format validation",
        warning="Matches URL text inside any file (browser caches, logs, mail): noisy on drives.")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        key = ctx.secret("abusech_auth_key")
        headers = {"Auth-Key": key} if key else None
        url = self.base_url("https://urlhaus.abuse.ch/downloads/").rstrip("/") + "/urlhaus.ndb"
        path = ctx.download(url, "urlhaus.ndb", max_size=64 * MiB, headers=headers)
        verify.clamav_load_test(path)
        return write_material(ctx.staging, {"clamav": ["urlhaus.ndb"], "verified": "https",
                                            "version": time.strftime("%Y-%m-%d %H:%M", time.gmtime(ctx.now))})


# -- Linux Malware Detect -------------------------------------------------------------

class LinuxMalwareDetect(Source):
    info = SourceInfo(
        id="lmd", name="Linux Malware Detect (R-fx Networks)", kind="clamav",
        homepage="https://www.rfxn.com/projects/linux-malware-detect/", license="GPL-2.0",
        license_url="https://github.com/rfxn/linux-malware-detect/blob/master/COPYING.GPL",
        terms="GPL-2.0; usable and redistributable without restrictions.",
        default_enabled=True, min_interval=6 * HOUR, size_hint="about 10 MB", group="ClamAV",
        integrity="SHA-256 checksum file published next to the signature pack")
    wanted = ("rfxn.hdb", "rfxn.hsb", "rfxn.ndb", "rfxn.yara")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        base = self.base_url("https://cdn.rfxn.com/downloads/").rstrip("/") + "/"
        version = ctx.session.fetch_text(base + "maldet.sigs.ver", max_size=4096).strip()[:40]
        if not re.fullmatch(r"[0-9A-Za-z._-]+", version or ""):
            raise SourceError(f"unexpected LMD signature version {version!r}")
        if ctx.previous and ctx.state.get("version") == version:
            raise Unchanged(version)
        pack = ctx.download(base + "maldet-sigpack.tgz", "maldet-sigpack.tgz", max_size=256 * MiB,
                            conditional=False)
        checksum = ctx.session.fetch_text(base + "maldet-sigpack.tgz.sha256", max_size=4096)
        verify.expect_sha256(pack, verify.parse_checksum_file(checksum))
        extracted = verify.extract_tar(
            pack, ctx.staging, lambda rel: rel.name in self.wanted and "sigs" in rel.parts[:-1],
            max_file=128 * MiB, max_total=512 * MiB, flatten=True)
        pack.unlink()
        names = sorted(p.name for p in extracted)
        if not names:
            raise SourceError("the LMD signature pack contained no ClamAV databases")
        for name in names:
            verify.clamav_load_test(ctx.staging / name)
        return write_material(ctx.staging, {"clamav": names, "version": version, "verified": "sha256"})


__all__ = ["ClamAVOfficial", "LinuxMalwareDetect", "SanesecurityEmail", "SanesecurityMalware",
           "SecuriteInfo", "URLhaus"]
