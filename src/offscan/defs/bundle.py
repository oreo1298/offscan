"""Signed offline definition bundles (USB transfer to machines without internet).

A bundle is a plain tar file::

    bundle.json        manifest: sources, versions, licences, and the SHA-256 of every file
    bundle.sig         Ed25519 signature over bundle.json
    data/<source>/...  the verified *raw* material of each source (never compiled rules)

The exporting installation signs with its own Ed25519 key.  Importing
requires that key to be trusted (its fingerprint is shown on the exporting
machine with ``defs fingerprint``; the importer confirms it once).  After
the signature and every file hash check out, upstream signatures are
re-verified where they exist, and the receiving machine builds and tests its
own definition set before activating it.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from .. import appinfo, log, paths
from ..settings import Settings
from . import layout, verify
from .sources.base import load_material
from .updater import Updater

logger = log.get("defs.bundle")
FORMAT = 1
MAX_FILE = 64 << 30
RESTRICTED = {"securiteinfo": "SecuriteInfo's terms forbid redistribution",
              "sanesecurity": "Sanesecurity's terms forbid redistribution without permission",
              "sanesecurity-email": "Sanesecurity's terms forbid redistribution without permission",
              "malwarebazaar": "abuse.ch data: do not redistribute",
              "threatfox": "abuse.ch data: do not redistribute",
              "elastic": "Elastic License 2.0: keep the licence notice"}


class BundleError(Exception):
    pass


class UntrustedKey(BundleError):
    def __init__(self, fingerprint: str):
        super().__init__(f"the bundle was signed by an untrusted key {format_fingerprint(fingerprint)}")
        self.fingerprint = fingerprint


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise BundleError("the 'cryptography' Python package is needed for bundles") from exc
    return ed25519, serialization


def key_path() -> Path:
    return paths.config_dir() / "bundle-signing-key.pem"


def trusted_path() -> Path:
    return paths.config_dir() / "trusted-bundle-keys.json"


def _load_or_create_key():
    ed25519, serialization = _crypto()
    path = key_path()
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    paths.ensure_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


def _raw_public(key) -> bytes:
    _, serialization = _crypto()
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint_of(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()


def format_fingerprint(fpr: str) -> str:
    fpr = fpr.upper()
    return " ".join(fpr[i:i + 4] for i in range(0, min(len(fpr), 40), 4))


def own_fingerprint() -> str:
    return fingerprint_of(_raw_public(_load_or_create_key()))


def trusted_keys() -> list[dict[str, Any]]:
    try:
        data = json.loads(trusted_path().read_text(encoding="utf-8"))
        return [k for k in data if isinstance(k, dict) and "fingerprint" in k]
    except (OSError, ValueError):
        return []


def trust_key(fingerprint: str, name: str = "") -> None:
    keys = [k for k in trusted_keys() if k["fingerprint"] != fingerprint]
    keys.append({"fingerprint": fingerprint, "name": name, "added": time.time()})
    paths.ensure_dir(trusted_path().parent)
    trusted_path().write_text(json.dumps(keys, indent=1), encoding="utf-8")


def _is_trusted(fingerprint: str) -> bool:
    if key_path().exists() and fingerprint == own_fingerprint():
        return True
    return any(k["fingerprint"] == fingerprint for k in trusted_keys())


# ----------------------------------------------------------------------- export

def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def export(path: Path, updater: Updater | None = None,
           include_restricted: bool | None = None) -> dict[str, Any]:
    updater = updater or Updater()
    settings = updater.settings
    if include_restricted is None:
        include_restricted = bool(settings.data.get("bundle_include_restricted", True))
    key = _load_or_create_key()
    files: dict[str, dict[str, Any]] = {}
    sources: dict[str, Any] = {}
    payload: list[tuple[str, Path]] = []
    notices: list[str] = []
    with tempfile.TemporaryDirectory(prefix=f"{appinfo.NAME}-export-") as tmp:
        for source in updater.sources:
            if not source.enabled():
                continue
            state = updater.load_state(source.id)
            vdir = updater.current_dir(source.id, state)
            if vdir is None:
                continue
            if source.id in RESTRICTED and not include_restricted:
                notices.append(f"{source.id}: left out ({RESTRICTED[source.id]})")
                continue
            if source.id in RESTRICTED:
                notices.append(f"{source.id}: included for your own machines only "
                               f"({RESTRICTED[source.id]})")
            material = load_material(vdir)
            if material.get("clamav_official") == "system":
                vdir = _snapshot_system_clamav(Path(tmp) / source.id, material)
                material = load_material(vdir)
            for root, _dirs, names in os.walk(vdir):
                for name in names:
                    full = Path(root) / name
                    rel = full.relative_to(vdir).as_posix()
                    arc = f"data/{source.id}/{rel}"
                    files[arc] = {"sha256": verify.sha256_file(full), "size": full.stat().st_size}
                    payload.append((arc, full))
            sources[source.id] = {"version": state.get("version"), "name": source.info.name,
                                  "license": source.info.license, "license_url": source.info.license_url,
                                  "verified": material.get("verified")}
        if not sources:
            raise BundleError("there are no downloaded definitions to export")
        manifest = {"format": FORMAT, "generator": f"{appinfo.NAME} {appinfo.VERSION}",
                    "created": time.time(), "sources": sources, "files": files,
                    "public_key": base64.b64encode(_raw_public(key)).decode(),
                    "notices": notices}
        blob = json.dumps(manifest, indent=1, sort_keys=True).encode()
        signature = key.sign(blob)
        tmp_out = path.with_name(path.name + ".part")
        with tarfile.open(tmp_out, "w", format=tarfile.PAX_FORMAT) as tar:
            _add_bytes(tar, "bundle.json", blob)
            _add_bytes(tar, "bundle.sig", signature)
            for arc, full in payload:
                tar.add(full, arcname=arc, recursive=False)
        os.replace(tmp_out, path)
    return {"path": str(path), "sources": sorted(sources), "files": len(files),
            "fingerprint": fingerprint_of(_raw_public(key)), "notices": notices}


def _snapshot_system_clamav(out: Path, material: dict[str, Any]) -> Path:
    """The target machine may have no ClamAV updater: ship the system databases."""
    out.mkdir(parents=True)
    names = []
    for src in layout.system_clamav_files():
        shutil.copyfile(src, out / src.name)
        names.append(src.name)
    (out / "material.json").write_text(json.dumps({**material, "clamav": names,
                                                   "clamav_official": "private",
                                                   "verified": "system freshclam (exported)"}))
    return out


# ----------------------------------------------------------------------- import

def read_header(path: Path) -> tuple[dict[str, Any], bytes, bytes]:
    try:
        tar = tarfile.open(path, "r:")
    except (tarfile.TarError, OSError) as exc:
        raise BundleError(f"not a definitions bundle: {exc}") from exc
    with tar:
        first = tar.next()
        second = tar.next()
        if first is None or second is None or first.name != "bundle.json" or second.name != "bundle.sig":
            raise BundleError("not a definitions bundle (missing header)")
        if first.size > 64 << 20 or second.size > 1024:
            raise BundleError("bundle header too large")
        blob = tar.extractfile(first).read()      # type: ignore[union-attr]
        sig = tar.extractfile(second).read()      # type: ignore[union-attr]
    try:
        manifest = json.loads(blob)
    except ValueError as exc:
        raise BundleError("corrupt bundle manifest") from exc
    if manifest.get("format") != FORMAT:
        raise BundleError(f"unsupported bundle format {manifest.get('format')!r}")
    return manifest, blob, sig


def inspect(path: Path) -> dict[str, Any]:
    manifest, blob, sig = read_header(path)
    raw = base64.b64decode(manifest["public_key"])
    fpr = fingerprint_of(raw)
    _verify_signature(raw, blob, sig)
    return {"fingerprint": fpr, "trusted": _is_trusted(fpr), "created": manifest.get("created"),
            "generator": manifest.get("generator"), "sources": manifest.get("sources", {}),
            "files": len(manifest.get("files", {})), "notices": manifest.get("notices", [])}


def _verify_signature(raw_public: bytes, blob: bytes, sig: bytes) -> None:
    ed25519, _ = _crypto()
    from cryptography.exceptions import InvalidSignature
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(raw_public).verify(sig, blob)
    except (InvalidSignature, ValueError) as exc:
        raise BundleError("the bundle signature is invalid (file corrupted or tampered with)") from exc


def import_bundle(path: Path, updater: Updater | None = None, trust: str | None = None) -> dict[str, Any]:
    updater = updater or Updater()
    manifest, blob, sig = read_header(path)
    raw = base64.b64decode(manifest["public_key"])
    fpr = fingerprint_of(raw)
    _verify_signature(raw, blob, sig)
    if not _is_trusted(fpr):
        if trust and trust.replace(" ", "").lower() == fpr[:len(trust.replace(" ", ""))].lower() \
                and len(trust.replace(" ", "")) >= 16:
            trust_key(fpr, "imported bundle")
        else:
            raise UntrustedKey(fpr)
    files: dict[str, Any] = manifest.get("files", {})
    known = {s.id: s for s in updater.sources}
    stamp = int(time.time())
    staged: dict[str, Path] = {}
    try:
        with tarfile.open(path, "r:") as tar:
            for member in tar:
                if member.name in ("bundle.json", "bundle.sig"):
                    continue
                entry = files.get(member.name)
                if entry is None or not member.isreg():
                    raise BundleError(f"unexpected entry in bundle: {member.name[:100]!r}")
                rel = verify.safe_member_name(member.name)
                if rel is None or len(rel.parts) < 3 or rel.parts[0] != "data":
                    raise BundleError(f"unsafe path in bundle: {member.name[:100]!r}")
                sid = rel.parts[1]
                if sid not in known:
                    raise BundleError(f"bundle contains an unknown source {sid!r}")
                if member.size != entry["size"] or member.size > MAX_FILE:
                    raise BundleError(f"size mismatch for {member.name}")
                if sid not in staged:
                    sdir = updater.source_dir(sid)
                    sdir.mkdir(parents=True, exist_ok=True)
                    staged[sid] = Path(tempfile.mkdtemp(prefix=".import-", dir=sdir))
                target = staged[sid].joinpath(*rel.parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(member)
                assert src is not None
                digest = hashlib.sha256()
                with src, open(target, "wb") as out:
                    while chunk := src.read(1 << 20):
                        digest.update(chunk)
                        out.write(chunk)
                if digest.hexdigest() != entry["sha256"]:
                    raise BundleError(f"checksum mismatch for {member.name}")
        missing = []
        for name in files:
            parts = name.split("/")
            sdir = staged.get(parts[1]) if len(parts) > 2 else None
            if sdir is None or not sdir.joinpath(*parts[2:]).exists():
                missing.append(name)
        if missing:
            raise BundleError(f"bundle is incomplete ({len(missing)} files missing)")
        for sid, sdir in staged.items():
            _reverify(sid, sdir)
        installed = []
        for sid, sdir in staged.items():
            version_dir = updater.source_dir(sid) / f"v{stamp}-import"
            os.replace(sdir, version_dir)
            state = updater.load_state(sid)
            material = load_material(version_dir)
            version = manifest["sources"].get(sid, {}).get("version") or material.get("version")
            state.update({"version": version,
                          "dir": version_dir.name, "updated": manifest.get("created"),
                          "imported": time.time(), "error": None, "verified": f"bundle {fpr[:16]}",
                          "size": sum(f.stat().st_size for f in version_dir.rglob("*") if f.is_file())})
            updater.save_state(sid, state)
            installed.append(sid)
        updater._acquire()
        try:
            set_info = updater.build_and_activate()
            updater.gc()
        finally:
            updater._release()
    finally:
        for sdir in staged.values():
            shutil.rmtree(sdir, ignore_errors=True)
    return {"fingerprint": fpr, "sources": installed, "set": set_info}


def _reverify(sid: str, sdir: Path) -> None:
    """Re-check upstream integrity where it exists; validate structure everywhere."""
    material = json.loads((sdir / "material.json").read_text(encoding="utf-8"))
    from .sources.clamav import SANESECURITY_FPR, sanesecurity_keyring
    for name in material.get("clamav", []):
        path = sdir / name
        if not path.exists():
            raise BundleError(f"{sid}: {name} is missing")
        sig = path.with_name(path.name + ".sig")
        if sid.startswith("sanesecurity"):
            if not sig.exists():
                raise BundleError(f"{sid}: {name} has no signature")
            verify.gpg_verify(path, sig, sanesecurity_keyring(), SANESECURITY_FPR)
        if path.suffix == ".cvd":
            verify.cvd_info(path)
        else:
            verify.clamav_load_test(path)
    for item in material.get("hashes", []) + material.get("authentihash", []):
        if (sdir / item["file"]).stat().st_size % 32:
            raise BundleError(f"{sid}: corrupt hash list {item['file']}")
    if material.get("known_good") and (sdir / material["known_good"]).stat().st_size % 32:
        raise BundleError(f"{sid}: corrupt known-good list")


__all__ = ["BundleError", "Settings", "UntrustedKey", "export", "format_fingerprint", "import_bundle",
           "inspect", "own_fingerprint", "trust_key", "trusted_keys"]
