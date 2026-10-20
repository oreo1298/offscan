"""Definition updates against a local HTTPS server: verification, rollback, bundles."""

from __future__ import annotations

import ast
import hashlib
import io
import os
import subprocess
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from offscan import appinfo
from offscan.defs import bundle, net, store, verify
from offscan.defs.sources import clamav as clamav_sources
from offscan.defs.sources import github, hashes, yara
from offscan.defs.updater import Updater
from offscan.settings import Settings

from .httpserver import FileServer

pytest.importorskip("cryptography")
ROOT = Path(__file__).resolve().parents[2]


def _hexes(n: int, seed: str) -> list[str]:
    return [hashlib.sha256(f"{seed}{i}".encode()).hexdigest() for i in range(n)]


def _tgz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FileServer]:
    srv = FileServer(tmp_path)
    monkeypatch.setenv(appinfo.env("CA_BUNDLE"), str(srv.cert))
    yield srv
    srv.close()


@pytest.fixture
def env(tmp_path: Path, xdg_home: Path, server: FileServer, monkeypatch: pytest.MonkeyPatch):
    """Settings + updater wired to the local server, all sources off except chosen ones."""
    monkeypatch.setattr(github, "API", server.url + "/api")
    monkeypatch.setattr(github, "CODELOAD", server.url + "/codeload")
    monkeypatch.setattr(github, "WEB", server.url + "/web")
    monkeypatch.setattr(github, "ASSET_PREFIXES", (server.url + "/",))
    settings = Settings()

    def make(enabled: list[str], overrides: dict[str, str] | None = None) -> Updater:
        for src in Updater(base=tmp_path / "store", settings=settings).sources:
            settings.set_source(src.id, enabled=src.id in enabled)
        for sid, path in (overrides or {}).items():
            settings.data["source_overrides"][sid] = {"base_url": server.url + path}
        return Updater(base=tmp_path / "store", settings=settings, session=net.Session(timeout=10))
    return make


def _serve_lmd(server: FileServer, version: str = "202610201", tamper: bool = False) -> None:
    sig = b"%s:68:Rfxn.Test.Sig\n" % hashlib.sha256(b"rfxn-sample").hexdigest().encode()
    pack = _tgz({"sigs/rfxn.hsb": sig, "sigs/md5v2.dat": b"ignored\n",
                 "sigs/../../escape.hdb": b"x"} if tamper == "traversal" else
                {"sigs/rfxn.hsb": sig, "sigs/md5v2.dat": b"ignored\n"})
    server.files["/lmd/maldet.sigs.ver"] = version.encode() + b"\n"
    server.files["/lmd/maldet-sigpack.tgz"] = pack
    digest = hashlib.sha256(pack).hexdigest() if tamper is not True else "0" * 64
    server.files["/lmd/maldet-sigpack.tgz.sha256"] = f"{digest}  maldet-sigpack.tgz\n".encode()


def _serve_loldrivers(server: FileServer) -> None:
    base = "/lol/"
    for name in ("samples_malicious.sha256", "samples_vulnerable.sha256",
                 "authentihash_samples_malicious.sha256", "authentihash_samples_vulnerable.sha256"):
        server.files[base + name] = "\n".join(_hexes(60, name)).encode()


def test_update_build_activate_and_unchanged(env, server: FileServer) -> None:
    _serve_lmd(server)
    _serve_loldrivers(server)
    up = env(["lmd", "loldrivers"], {"lmd": "/lmd/", "loldrivers": "/lol/"})
    report = up.update()
    assert report["sources"]["lmd"]["result"] == "updated", report
    assert report["sources"]["loldrivers"]["result"] == "updated", report
    active = store.active_set(up.base)
    assert active is not None and (active / "clamav" / "rfxn.hsb").exists()
    assert not (active / "clamav" / "md5v2.dat").exists()
    status = {s["id"]: s for s in up.status()["sources"]}
    assert status["lmd"]["version"] == "202610201" and status["lmd"]["verified"] == "sha256"
    assert status["loldrivers"]["count"] == 240
    # Second run: inside the interval -> skipped; forced -> unchanged (ETag / same version).
    again = up.update()
    assert again["sources"]["lmd"]["result"] == "skipped" and again["set"] is None
    forced = up.update(force=True)
    assert forced["sources"]["lmd"]["result"] == "unchanged"
    assert forced["sources"]["loldrivers"]["result"] == "unchanged"


def test_checksum_mismatch_keeps_previous_version(env, server: FileServer) -> None:
    _serve_lmd(server, "1")
    up = env(["lmd"], {"lmd": "/lmd/"})
    up.update()
    first = store.active_set(up.base)
    _serve_lmd(server, "2", tamper=True)
    report = up.update(force=True)
    assert report["sources"]["lmd"]["result"] == "failed"
    assert "mismatch" in report["sources"]["lmd"]["message"]
    assert store.active_set(up.base) == first
    assert up.status()["sources"][[s.id for s in up.sources].index("lmd")]["version"] == "1"


def test_archive_path_traversal_rejected(env, server: FileServer) -> None:
    _serve_lmd(server, "3", tamper="traversal")
    up = env(["lmd"], {"lmd": "/lmd/"})
    report = up.update()
    assert report["sources"]["lmd"]["result"] == "failed"
    assert "unsafe path" in report["sources"]["lmd"]["message"]


def test_rate_limit_sets_cooldown(env, server: FileServer) -> None:
    server.errors["/lmd/maldet.sigs.ver"] = (429, {"Retry-After": "7200"})
    up = env(["lmd"], {"lmd": "/lmd/"})
    assert up.update()["sources"]["lmd"]["result"] == "rate_limited"
    del server.errors["/lmd/maldet.sigs.ver"]
    _serve_lmd(server)
    report = up.update(force=True)                # forced, but the server asked us to wait
    assert report["sources"]["lmd"]["result"] == "skipped"
    assert "rate limited" in report["sources"]["lmd"]["message"]


def test_rollback(env, server: FileServer) -> None:
    _serve_lmd(server, "10")
    up = env(["lmd"], {"lmd": "/lmd/"})
    up.update()
    first = store.active_set(up.base)
    _serve_lmd(server, "11")
    up.update(force=True)
    second = store.active_set(up.base)
    assert second != first
    assert up.rollback() == first
    assert store.active_set(up.base) == first


def test_malwarebazaar_full_then_recent(env, server: FileServer, monkeypatch: pytest.MonkeyPatch) -> None:
    key = "a1" * 24
    full = "\n".join(["# MalwareBazaar full dump", *_hexes(100_001, "mb")]) + "\n"
    server.files[f"/mb/{key}/sha256_full.txt.zip"] = _zip({"full_sha256.txt": full.encode()})
    up = env(["malwarebazaar"], {"malwarebazaar": "/mb/"})
    up.settings.set_secret("abusech_auth_key", key)
    report = up.update()
    assert report["sources"]["malwarebazaar"]["result"] == "updated", report
    assert key not in str(up.load_state("malwarebazaar")), "API key leaked into state"
    new = _hexes(3, "recent")
    server.files[f"/mb/{key}/sha256_recent.txt"] = ("\n".join(new) + "\n").encode()
    report = up.update(force=True)
    assert report["sources"]["malwarebazaar"]["result"] == "updated"
    assert up.status()["sources"][[s.id for s in up.sources].index("malwarebazaar")]["count"] == 100_004
    server.files[f"/mb/{key}/sha256_recent.txt"] = b"<html>error</html>\n"
    assert up.update(force=True)["sources"]["malwarebazaar"]["result"] == "failed"


def test_yara_forge_with_digest_and_fallback(env, server: FileServer) -> None:
    rules = b'rule forge_test { strings: $a = "forge" condition: $a }\n'
    asset = _zip({"packages/core/yara-rules-core.yar": rules})
    server.files["/assets/yara-forge-rules-core.zip"] = asset
    release = {"tag_name": "20261018", "assets": [{
        "name": "yara-forge-rules-core.zip",
        "browser_download_url": server.url + "/assets/yara-forge-rules-core.zip",
        "digest": "sha256:" + hashlib.sha256(asset).hexdigest()}]}
    import json
    server.files["/api/repos/YARAHQ/yara-forge/releases/latest"] = json.dumps(release).encode()
    up = env(["yara-forge"])
    report = up.update()
    assert report["sources"]["yara-forge"]["result"] == "updated", report
    assert up.load_state("yara-forge")["verified"] == "github-digest"
    assert report["set"]["rules"] == 2      # forge rule + built-in self-test rule
    # Wrong digest -> rejected.
    release["assets"][0]["digest"] = "sha256:" + "0" * 64
    release["tag_name"] = "20261025"
    server.files["/api/repos/YARAHQ/yara-forge/releases/latest"] = json.dumps(release).encode()
    assert up.update(force=True)["sources"]["yara-forge"]["result"] == "failed"
    # API rate limited -> stable 'latest' link without digest.
    server.errors["/api/repos/YARAHQ/yara-forge/releases/latest"] = (403, {})
    server.files["/web/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"] = asset + b""
    rules2 = rules.replace(b"forge_test", b"forge_test_2")
    server.files["/web/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"] = \
        _zip({"packages/core/yara-rules-core.yar": rules2})
    report = up.update(force=True)
    assert report["sources"]["yara-forge"]["result"] == "updated", report
    assert "API unavailable" in up.load_state("yara-forge")["verified"]


def test_broken_rule_file_does_not_break_the_set(env, server: FileServer) -> None:
    sha = "b" * 40
    server.files["/api/repos/bartblaze/Yara-rules/commits/master"] = sha.encode()
    server.files[f"/codeload/bartblaze/Yara-rules/tar.gz/{sha}"] = _tgz({
        "Yara-rules-x/rules/good.yar": b'rule good { strings: $a = "good" condition: $a }\n',
        "Yara-rules-x/rules/bad.yar": b"rule bad { condition: nope( }\n",
        "Yara-rules-x/README.md": b"docs\n"})
    up = env(["bartblaze"])
    report = up.update()
    assert report["sources"]["bartblaze"]["result"] == "updated", report
    assert report["set"]["rules"] == 2 and report["set"]["yara_errors"] == 1


def _gpg_key(tmp: Path, created: str | None = None) -> tuple[Path, str]:
    home = tmp / "gnupg"
    home.mkdir(mode=0o700)
    faked = ["--faked-system-time", created] if created else []
    def run(*a: str) -> subprocess.CompletedProcess:
        return subprocess.run(["gpg", "--homedir", str(home), "--batch", *a],
                              capture_output=True, check=True)
    run(*faked, "--passphrase", "", "--quick-gen-key", "Test Signer <t@example.org>", "ed25519", "sign",
        "never")
    fpr = run("--with-colons", "--fingerprint").stdout.decode()
    fingerprint = next(line.split(":")[9] for line in fpr.splitlines() if line.startswith("fpr"))
    keyring = tmp / "keyring.gpg"
    keyring.write_bytes(run("--export", fingerprint).stdout)
    return keyring, fingerprint


@pytest.mark.skipif(subprocess.run(["which", "gpg"], capture_output=True).returncode != 0,
                    reason="gpg missing")
def test_sanesecurity_gpg_verification(env, server: FileServer, tmp_path: Path,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    keyring, fpr = _gpg_key(tmp_path)
    home = tmp_path / "gnupg"
    monkeypatch.setattr(clamav_sources, "SANESECURITY_FPR", {fpr})
    monkeypatch.setattr(clamav_sources, "sanesecurity_keyring", lambda: keyring)
    monkeypatch.setattr(clamav_sources.SanesecurityMalware, "files", ("rogue.hdb",))
    data = b"%s:68:Sanesecurity.Test.1\n" % hashlib.md5(b"x").hexdigest().encode()
    (tmp_path / "rogue.hdb").write_bytes(data)
    subprocess.run(["gpg", "--homedir", str(home), "--batch", "--yes", "--detach-sign", "-o",
                    str(tmp_path / "rogue.hdb.sig"), str(tmp_path / "rogue.hdb")], check=True,
                   capture_output=True)
    server.files["/ss/rogue.hdb"] = data
    server.files["/ss/rogue.hdb.sig"] = (tmp_path / "rogue.hdb.sig").read_bytes()
    up = env(["sanesecurity"], {"sanesecurity": "/ss/"})
    assert up.update()["sources"]["sanesecurity"]["result"] == "updated"
    server.files["/ss/rogue.hdb"] = data + b"evil:1:x\n"          # signature no longer matches
    report = up.update(force=True)
    assert report["sources"]["sanesecurity"]["result"] == "failed"
    assert "signature" in report["sources"]["sanesecurity"]["message"]


@pytest.mark.skipif(subprocess.run(["which", "gpg"], capture_output=True).returncode != 0,
                    reason="gpg missing")
def test_sanesecurity_refuses_an_older_signature(env, server: FileServer, tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """A mirror (plain HTTP) must not be able to bring back an old, correctly signed file."""
    keyring, fpr = _gpg_key(tmp_path, created="20200101T000000")
    home = tmp_path / "gnupg"
    monkeypatch.setattr(clamav_sources, "SANESECURITY_FPR", {fpr})
    monkeypatch.setattr(clamav_sources, "sanesecurity_keyring", lambda: keyring)
    monkeypatch.setattr(clamav_sources.SanesecurityMalware, "files", ("rogue.hdb",))

    def signed(data: bytes, when: str | None) -> bytes:
        (tmp_path / "f").write_bytes(data)
        faked = ["--faked-system-time", when] if when else []
        subprocess.run(["gpg", "--homedir", str(home), "--batch", "--yes", *faked, "--detach-sign", "-o",
                        str(tmp_path / "f.sig"), str(tmp_path / "f")], check=True, capture_output=True)
        return (tmp_path / "f.sig").read_bytes()
    old = b"%s:68:Sanesecurity.Old\n" % hashlib.md5(b"x").hexdigest().encode()
    new = b"%s:68:Sanesecurity.New\n" % hashlib.md5(b"y").hexdigest().encode()
    old_sig, new_sig = signed(old, "20210101T000000"), signed(new, None)
    server.files["/ss/rogue.hdb"], server.files["/ss/rogue.hdb.sig"] = new, new_sig
    up = env(["sanesecurity"], {"sanesecurity": "/ss/"})
    assert up.update()["sources"]["sanesecurity"]["result"] == "updated"
    server.files["/ss/rogue.hdb"], server.files["/ss/rogue.hdb.sig"] = old, old_sig
    report = up.update(force=True)
    assert report["sources"]["sanesecurity"]["result"] == "failed"
    assert "older than the copy already installed" in report["sources"]["sanesecurity"]["message"]


def test_https_only_and_no_downgrade(server: FileServer, tmp_path: Path) -> None:
    session = net.Session(timeout=5)
    with pytest.raises(net.DownloadError, match="only HTTPS"):
        session.fetch("http://localhost:1/x", tmp_path, max_size=10)
    server.redirects["/redir"] = "http://localhost:1/plain"
    with pytest.raises(net.DownloadError, match="refusing redirect"):
        session.fetch(server.url + "/redir", tmp_path, max_size=10)
    server.files["/big"] = b"x" * 5000
    with pytest.raises(net.DownloadError, match="limit"):
        session.fetch(server.url + "/big", tmp_path, max_size=100)
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".dl-")]


def test_safe_zip_extraction(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(_zip({"../../etc/passwd": b"x"}))
    with pytest.raises(verify.VerificationError, match="unsafe"):
        verify.extract_zip(bad, tmp_path / "o", lambda r: True, max_file=10, max_total=10)
    bomb = tmp_path / "bomb.zip"
    bomb.write_bytes(_zip({"zeros": b"\0" * (4 << 20)}))
    with pytest.raises(verify.VerificationError, match="limit"):
        verify.extract_zip(bomb, tmp_path / "o2", lambda r: True, max_file=1 << 20, max_total=1 << 20)


def test_threatfox_parser_tolerates_shapes() -> None:
    data = {"1": [{"ioc_value": "a" * 64, "ioc_type": "sha256_hash"},
                  {"ioc_value": "evil.com", "ioc_type": "domain"}],
            "2": [{"ioc_value": "B" * 64, "ioc_type": "sha256_hash"}]}
    assert len(hashes.iter_threatfox_sha256(data)) == 2


def test_bundle_roundtrip_trust_and_tamper(env, server: FileServer, tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
    _serve_lmd(server, "42")
    _serve_loldrivers(server)
    up = env(["lmd", "loldrivers"], {"lmd": "/lmd/", "loldrivers": "/lol/"})
    up.update()
    out = tmp_path / "defs.tar"
    result = bundle.export(out, up)
    assert set(result["sources"]) == {"lmd", "loldrivers"}
    exporter_fpr = result["fingerprint"]
    # A second, offline machine: different config dir (other signing key) and store.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "other-config"))
    offline = Updater(base=tmp_path / "other-store", settings=Settings(), session=None)
    for src in offline.sources:
        offline.settings.set_source(src.id, enabled=src.id in ("lmd", "loldrivers"))
    with pytest.raises(bundle.UntrustedKey):
        bundle.import_bundle(out, offline)
    info = bundle.inspect(out)
    assert info["fingerprint"] == exporter_fpr and info["trusted"] is False
    with pytest.raises(bundle.UntrustedKey):                 # a short prefix is not enough
        bundle.import_bundle(out, offline, trust=exporter_fpr[:32])
    imported = bundle.import_bundle(out, offline, trust=bundle.format_fingerprint(exporter_fpr))
    assert set(imported["sources"]) == {"lmd", "loldrivers"}
    active = store.active_set(offline.base)
    assert (active / "clamav" / "rfxn.hsb").exists()
    # Tampering with any byte is detected.
    data = bytearray(out.read_bytes())
    idx = data.find(b"Rfxn.Test.Sig")
    data[idx] ^= 0x20
    bad = tmp_path / "bad.tar"
    bad.write_bytes(bytes(data))
    with pytest.raises(bundle.BundleError, match="checksum"):
        bundle.import_bundle(bad, offline)


def _rebundle(src: Path, dst: Path, change) -> None:
    """Re-sign a bundle (with this machine's key) after ``change(contents, manifest)``."""
    import json
    with tarfile.open(src) as tar:
        manifest = json.loads(tar.extractfile("bundle.json").read())
        contents = {m.name: tar.extractfile(m).read() for m in tar
                    if m.isreg() and m.name.startswith("data/")}
    change(contents, manifest)
    manifest["files"] = {n: {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d)}
                         for n, d in contents.items()}
    key = bundle._load_or_create_key()
    blob = json.dumps(manifest, indent=1, sort_keys=True).encode()
    with tarfile.open(dst, "w", format=tarfile.PAX_FORMAT) as tar:
        bundle._add_bytes(tar, "bundle.json", blob)
        bundle._add_bytes(tar, "bundle.sig", key.sign(blob))
        for name, data in contents.items():
            bundle._add_bytes(tar, name, data)


def _material_change(source: str, edit):
    import json

    def change(contents: dict[str, bytes], _manifest: dict) -> None:
        name = f"data/{source}/material.json"
        material = json.loads(contents[name])
        edit(material, contents)
        contents[name] = json.dumps(material).encode()
    return change


@pytest.mark.parametrize(("source", "edit", "message"), [
    ("loldrivers", lambda m, c: m["hashes"][0].update(file="/etc/hostname"), "unsafe file name"),
    ("loldrivers", lambda m, c: m["hashes"][0].update(file="../../../../etc/hostname"), "unsafe file name"),
    ("lmd", lambda m, c: m.update(yara=[{"file": "rfxn.hsb", "origin": "x"}]), "cannot carry yara"),
    ("lmd", lambda m, c: (m["clamav"].append("evil.ign2"), c.update({"data/lmd/evil.ign2": b"Some.Sig\n"})),
     "allow-list"),
    ("lmd", lambda m, c: (m["clamav"].append("bytecode.cld"), c.update({"data/lmd/bytecode.cld": b"x"})),
     "bytecode"),
])
def test_bundles_cannot_smuggle_material(env, server: FileServer, tmp_path: Path, source, edit,
                                         message: str) -> None:
    """Even a trusted signer cannot point a set at local files, or weaken the scan."""
    _serve_lmd(server, "42")
    _serve_loldrivers(server)
    up = env(["lmd", "loldrivers"], {"lmd": "/lmd/", "loldrivers": "/lol/"})
    up.update()
    good = tmp_path / "good.tar"
    bundle.export(good, up)
    evil = tmp_path / "evil.tar"
    _rebundle(good, evil, _material_change(source, edit))
    before = up.load_state(source)
    with pytest.raises(bundle.BundleError, match=message):
        bundle.import_bundle(evil, up, allow_older=True)
    assert up.load_state(source) == before


def test_older_bundles_need_explicit_consent(env, server: FileServer, tmp_path: Path) -> None:
    _serve_lmd(server, "42")
    up = env(["lmd"], {"lmd": "/lmd/"})
    up.update()
    good = tmp_path / "good.tar"
    bundle.export(good, up)
    old = tmp_path / "old.tar"
    _rebundle(good, old, lambda contents, manifest: manifest.update(created=manifest["created"] - 86400))
    with pytest.raises(bundle.OlderBundle):
        bundle.import_bundle(old, up)
    assert bundle.import_bundle(old, up, allow_older=True)["sources"] == ["lmd"]


def test_failed_import_restores_the_previous_definitions(env, server: FileServer, tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    _serve_lmd(server, "42")
    up = env(["lmd"], {"lmd": "/lmd/"})
    up.update()
    good = tmp_path / "good.tar"
    bundle.export(good, up)
    before = up.load_state("lmd")

    def broken(*args, **kwargs):
        raise RuntimeError("build failed")
    monkeypatch.setattr(up, "build_and_activate", broken)
    with pytest.raises(RuntimeError):
        bundle.import_bundle(good, up)
    assert up.load_state("lmd") == before
    assert not list(up.source_dir("lmd").glob("*-import"))


ALLOWED_NETWORK = {
    "src/offscan/defs/net.py": {"urllib.request", "urllib.error", "ssl"},
}
FORBIDDEN = {"urllib.request", "urllib3", "http.client", "requests", "httpx", "ftplib", "smtplib",
             "aiohttp", "telnetlib", "xmlrpc.client", "ssl"}


def test_only_the_updater_can_use_the_network() -> None:
    """No telemetry: network client libraries may only be imported by defs/net.py."""
    offenders = []
    for path in (ROOT / "src").rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(), filename=rel)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for name in names:
                if name in FORBIDDEN and name not in ALLOWED_NETWORK.get(rel, set()):
                    offenders.append(f"{rel}: {name}")
    assert not offenders, offenders


def test_no_inet_sockets_outside_updater() -> None:
    offenders = []
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text()
        if "AF_INET" in text or "create_connection" in text:
            offenders.append(path.name)
    assert not offenders, offenders


def test_store_dir_for_root_without_user(monkeypatch: pytest.MonkeyPatch, xdg_home: Path) -> None:
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    if os.geteuid() == 0:
        assert str(store.store_dir()).startswith(str(xdg_home / "var-lib"))
    else:
        assert str(store.store_dir()).startswith(str(xdg_home / "data"))


def test_yara_source_classes_have_licences() -> None:
    from offscan.defs.sources import SOURCE_CLASSES
    ids = [cls.info.id for cls in SOURCE_CLASSES]
    assert len(ids) == len(set(ids))
    for cls in SOURCE_CLASSES:
        assert cls.info.license and cls.info.license_url.startswith("https://")
        assert cls.info.terms and cls.info.integrity
    assert yara.ElasticRules.info.requires_acceptance


def _fake_freshclam(bindir: Path, behaviour: str) -> None:
    bindir.mkdir(exist_ok=True)
    script = bindir / "freshclam"
    body = {
        "ok": 'for a in "$@"; do case $a in --datadir=*) d=${a#--datadir=};; esac; done\n'
              'printf "main" > "$d/main.cld"; printf "daily" > "$d/daily.cld"\n'
              'echo "daily.cld updated"; exit 0\n',
        "cooldown": 'echo "WARNING: You are on cool-down until after: 2026-10-20 20:00:00"; exit 17\n',
        "fail": 'echo "ERROR: Can\'t connect"; exit 52\n',
    }[behaviour]
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)


@pytest.mark.parametrize("behaviour,result", [("ok", "updated"), ("cooldown", "rate_limited"),
                                              ("fail", "failed")])
def test_private_freshclam(env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                           behaviour: str, result: str) -> None:
    _fake_freshclam(tmp_path / "bin", behaviour)
    monkeypatch.setenv(appinfo.env("TOOL_DIRS"), str(tmp_path / "bin"))
    up = env(["clamav"])
    up.settings.data["clamav_official"] = "private"
    report = up.update(only=["clamav"])
    assert report["sources"]["clamav"]["result"] == result, report
    if result == "updated":
        vdir = up.current_dir("clamav")
        material = __import__("json").loads((vdir / "material.json").read_text())
        assert material["clamav_official"] == "private"
        assert sorted(material["clamav"]) == ["daily.cld", "main.cld"]
        conf = (up.base / "sources" / "clamav" / "freshclam.conf").read_text()
        assert "DatabaseMirror database.clamav.net" in conf
    if result == "rate_limited":
        assert up.load_state("clamav")["cooldown_until"] > 0


def test_system_clamav_mode(env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from offscan.defs import layout
    sysdb = tmp_path / "var-lib-clamav"
    sysdb.mkdir()
    for name in ("main.cvd", "daily.cld", "bytecode.cvd"):
        (sysdb / name).write_bytes(b"x")
    monkeypatch.setattr(layout, "SYSTEM_CLAMAV_DIR", str(sysdb))
    up = env(["clamav"])
    up.settings.data["clamav_official"] = "system"
    report = up.update(only=["clamav"])
    assert report["sources"]["clamav"]["result"] == "updated", report
    assert report["set"]["clamav_official"] == "system"
