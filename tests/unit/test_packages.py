"""Package database parsing and verification (dpkg, pacman, rpm sqlite/ndb)."""

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from offscan import sandbox
from offscan.persistence import packages
from offscan.safefs import RootFS


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()           # dpkg's own format


def write(root: Path, rel: str, data: bytes | str, mode: int | None = None) -> Path:
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    if mode is not None:
        path.chmod(mode)
    return path


def _list(root_path: Path, in_sandbox: bool = False) -> packages.PackageIndex:
    with RootFS(root_path) as root:
        info = packages.detect(root)
        assert info is not None
        args, fds = packages.collect(root, info)
    try:
        result = (sandbox.run("packages.list", args, fds, timeout=300) if in_sandbox
                  else packages.task_list(args, fds))
    finally:
        for fd in fds:
            os.close(fd)
    return packages.PackageIndex.from_result(result)


LS, CAT, CAT_TROJAN = b"\x7fELF ls", b"\x7fELF cat", b"\x7fELF cat with a backdoor"


@pytest.fixture
def dpkg_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    write(root, "/usr/bin/ls", LS)
    write(root, "/usr/bin/cat", CAT_TROJAN)
    write(root, "/usr/share/doc/coreutils/README", "edited")
    write(root, "/usr/bin/foo.distrib", "original foo")
    write(root, "/usr/bin/foo", "wrapper from another package")
    write(root, "/etc/ssh/sshd_config", "Port 2222\n")
    (root / "bin").symlink_to("usr/bin")
    sshd_md5, old_md5, removed_md5 = md5(b"Port 22\n"), md5(b"x"), md5(b"y")
    write(root, "/var/lib/dpkg/status",
          "Package: coreutils\nStatus: install ok installed\nVersion: 9.4-3\n\n"
          "Package: openssh-server\nStatus: install ok installed\nConffiles:\n"
          f" /etc/ssh/sshd_config {sshd_md5}\n /etc/ssh/old {old_md5} obsolete\n\n"
          "Package: removed\nStatus: deinstall ok config-files\nConffiles:\n"
          f" /etc/removed.conf {removed_md5}\n")
    write(root, "/var/lib/dpkg/diversions", "/usr/bin/foo\n/usr/bin/foo.distrib\nfoo-wrapper\n")
    write(root, "/var/lib/dpkg/info/coreutils:amd64.md5sums",
          f"{md5(LS)}  bin/ls\n{md5(CAT)}  usr/bin/cat\n{md5(b'readme')}  usr/share/doc/coreutils/README\n"
          f"{md5(b'gone')}  usr/bin/missing\n{md5(b'original foo')}  usr/bin/foo\n")
    write(root, "/var/lib/dpkg/info/coreutils:amd64.list",
          "/.\n/bin\n/bin/ls\n/usr/bin/cat\n/usr/bin/missing\n/usr/bin/foo\n/usr/share/doc/coreutils/README\n")
    write(root, "/usr/bin/unowned-tool", "#!/bin/sh\n")
    write(root, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "pam")
    write(root, "/usr/lib/x86_64-linux-gnu/security/pam_backdoor.so", "evil")
    write(root, "/var/lib/dpkg/info/libpam-modules.list", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so\n")
    write(root, "/usr/lib/modules/6.1.0/kernel/drivers/evil.ko", "module")
    write(root, "/usr/lib/modules/6.1.0/updates/dkms/nvidia.ko.zst", "dkms")
    (root / "lib").symlink_to("usr/lib")
    return root


def test_dpkg(dpkg_root: Path) -> None:
    index = _list(dpkg_root)
    assert index.manager == "dpkg" and not index.errors
    assert index.owns("/usr/bin/ls") and index.owns("/bin/cat")          # merged /usr aliases
    assert not any(f[0] == "/etc/removed.conf" for f in index.files)
    with RootFS(dpkg_root) as root:
        findings, counters = packages.verify(root, index, scope="full")
        by_path = {f.location: f for f in findings}
        assert by_path["/usr/bin/cat"].severity == "high"
        assert by_path["/usr/bin/cat"].extra["package"] == "coreutils:amd64"
        assert by_path["/usr/share/doc/coreutils/README"].severity == "low"
        assert by_path["/etc/ssh/sshd_config"].severity == "info"
        assert by_path["/usr/bin/missing"].check == "integrity.package_missing"
        assert "/bin/ls" not in by_path and "/usr/bin/ls" not in by_path
        assert "/usr/bin/foo.distrib" not in by_path                     # diversion followed
        assert counters["modified"] == 3 and counters["missing"] == 1

        quick, _ = packages.verify(root, index, scope="quick")
        assert {f.location for f in quick} == {"/usr/bin/cat", "/usr/bin/missing"}
        extra, _ = packages.verify(root, index, scope="quick", extra=["/etc/ssh/sshd_config"])
        assert "/etc/ssh/sshd_config" in {f.location for f in extra}

        setid = [{"path": "/usr/local/bin/suidtool", "mode": 0o104755, "uid": 0},
                 {"path": "/tmp/.x/rootshell", "mode": 0o104755, "uid": 0},
                 {"path": "/usr/bin/ls", "mode": 0o104755, "uid": 0}]
        lost = {f.location: f for f in packages.unowned(root, index, setid)}
    assert lost["/usr/bin/unowned-tool"].severity == "low"
    assert lost["/usr/lib/x86_64-linux-gnu/security/pam_backdoor.so"].severity == "high"
    assert "/usr/lib/x86_64-linux-gnu/security/pam_unix.so" not in lost
    assert lost["/usr/lib/modules/6.1.0/kernel/drivers/evil.ko"].check == "integrity.unowned_module"
    assert not any("nvidia" in p for p in lost)
    assert lost["/usr/local/bin/suidtool"].severity == "low"
    assert lost["/tmp/.x/rootshell"].severity == "high"
    assert "/usr/bin/ls" not in lost


def test_dpkg_in_sandbox(dpkg_root: Path) -> None:
    direct, boxed = _list(dpkg_root), _list(dpkg_root, in_sandbox=True)
    assert boxed.files == direct.files and boxed.owned == direct.owned


def test_pacman(tmp_path: Path) -> None:
    root = tmp_path / "root"
    bash = b"\x7fELF bash"
    write(root, "/usr/bin/bash", b"\x7fELF bash patched")
    write(root, "/usr/bin/sh x", bash)
    write(root, "/etc/bash.bashrc", "edited")
    sha = hashlib.sha256(bash).hexdigest()
    base = "/var/lib/pacman/local/bash-5.2.037-1"
    write(root, f"{base}/desc", "%NAME%\nbash\n\n%VERSION%\n5.2.037-1\n")
    write(root, f"{base}/files", "%FILES%\nusr/\nusr/bin/\nusr/bin/bash\nusr/bin/sh x\netc/bash.bashrc\n\n"
                                 f"%BACKUP%\netc/bash.bashrc\t{md5(b'orig')}\n")
    mtree = ("#mtree\n/set type=file uid=0 gid=0 mode=644\n"
             "./.BUILDINFO time=1 size=10 md5digest=00 sha256digest=00\n"
             "./usr time=1 mode=755 type=dir\n"
             f"./usr/bin/bash time=1 mode=755 size={len(bash)} md5digest={md5(bash)} sha256digest={sha}\n"
             f"./usr/bin/sh\\040x time=1 mode=755 size={len(bash)} sha256digest={sha}\n"
             f"./etc/bash.bashrc time=1 size=4 sha256digest={hashlib.sha256(b'orig').hexdigest()}\n"
             "./usr/bin/rbash time=1 type=link link=bash\n")
    write(root, f"{base}/mtree", gzip.compress(mtree.encode()))
    index = _list(root)
    assert index.manager == "pacman" and index.packages == ["bash"]
    assert sorted(f[0] for f in index.files) == ["/etc/bash.bashrc", "/usr/bin/bash", "/usr/bin/sh x"]
    with RootFS(root) as rootfs:
        findings, counters = packages.verify(rootfs, index, scope="full")
    by_path = {f.location: f for f in findings}
    assert by_path["/usr/bin/bash"].severity == "high"
    assert by_path["/etc/bash.bashrc"].severity == "info"
    assert "/usr/bin/sh x" not in by_path and counters["checked"] == 3


def test_gzip_bomb_is_bounded() -> None:
    bomb = gzip.compress(b"\0" * (80 << 20))
    with pytest.raises(ValueError):
        packages._gunzip(bomb)


SPEC = """Name: offscan-demo
Version: 1.0
Release: 1
Summary: demo
License: MIT
BuildArch: noarch
%description
demo
%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/demo %{buildroot}/usr/share/doc/demo
printf '#!/bin/sh\\necho hi\\n' > %{buildroot}/usr/bin/demo
printf 'key=value\\n' > %{buildroot}/etc/demo/demo.conf
printf 'readme\\n' > %{buildroot}/usr/share/doc/demo/README
ln -s demo %{buildroot}/usr/bin/demo-link
%files
%attr(4755,root,root) /usr/bin/demo
/usr/bin/demo-link
%config(noreplace) /etc/demo/demo.conf
%doc /usr/share/doc/demo/README
%dir /etc/demo
%ghost /var/log/demo.log
"""


@pytest.fixture(scope="module")
def demo_rpm(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not (shutil.which("rpmbuild") and shutil.which("rpm")):
        pytest.skip("rpm/rpmbuild not installed")
    top = tmp_path_factory.mktemp("rpmbuild")
    (top / "SPECS").mkdir()
    (top / "SPECS/demo.spec").write_text(SPEC)
    subprocess.run(["rpmbuild", "--define", f"_topdir {top}", "-bb", str(top / "SPECS/demo.spec")],
                   check=True, capture_output=True)
    return next((top / "RPMS/noarch").glob("*.rpm"))


@pytest.mark.parametrize(("backend", "dbdir"), [("sqlite", "var/lib/rpm"), ("ndb", "usr/lib/sysimage/rpm")])
def test_rpm(tmp_path: Path, demo_rpm: Path, backend: str, dbdir: str) -> None:
    root = tmp_path / "root"
    db = root / dbdir
    db.mkdir(parents=True)
    define = ["--define", f"_db_backend {backend}"]
    subprocess.run(["rpm", "--dbpath", str(db), *define, "--initdb"], check=True, capture_output=True)
    subprocess.run(["rpm", "--dbpath", str(db), *define, "-i", "--justdb", "--nodeps", "--noscripts",
                    "--ignorearch", "--ignoreos", str(demo_rpm)], check=True, capture_output=True)
    query = ["rpm", "--dbpath", str(db), *define, "-qa", "--qf", "[%{FILENAMES} %{FILEDIGESTS}\\n]"]
    expected = subprocess.run(query, check=True, capture_output=True, text=True)
    write(root, "/usr/bin/demo", "#!/bin/sh\necho owned\n")
    write(root, "/etc/demo/demo.conf", "key=value\n")
    index = _list(root, in_sandbox=True)
    assert index.manager == "rpm" and index.packages == ["offscan-demo-1.0-1.noarch"], index.errors
    digests = {f[0]: f[3] for f in index.files}
    for line in expected.stdout.splitlines():
        path, _, digest = line.partition(" ")
        if digest:
            assert digests[path] == digest
    assert {f[0]: f[4] for f in index.files} == {"/usr/bin/demo": "", "/etc/demo/demo.conf": "c",
                                                 "/usr/share/doc/demo/README": "d"}
    assert index.owns("/usr/bin/demo-link") and not index.owns("/var/log/demo.log")   # ghost
    with RootFS(root) as rootfs:
        findings, counters = packages.verify(rootfs, index, scope="full")
    assert [(f.location, f.severity) for f in findings] == [("/usr/bin/demo", "high")]
    assert findings[0].extra["algorithm"] == "sha256"
    assert counters["missing"] == 1                                       # the README (doc: not reported)


def test_rpm_header_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        packages.parse_rpm_header(b"\0\0\0\x05\0\0\0\x01" + b"\0" * 10)
    with pytest.raises(ValueError):
        list(packages.iter_ndb(b"NotRpm" + b"\0" * 100))
    assert list(packages.iter_ndb(b"RpmP" + b"\0" * 8 + b"\1\0\0\0" + b"\0" * 4080)) == []
