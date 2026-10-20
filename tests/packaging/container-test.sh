#!/usr/bin/env bash
# Install, update and remove the application inside a distribution container.
#
#   container-test.sh package   the native package: install, smoke test, upgrade,
#                               refuse install.sh on top, remove, check nothing is left
#   container-test.sh script    install.sh: install (with dependencies), smoke test,
#                               update, refuse the native package on top, uninstall
#                               keeping data, uninstall with --purge, check nothing is left
#
# Expects the source tree at /src (read-only is fine) and the build output at
# /dist: packages from 'build.py packages', the next version's packages in
# /dist/next, the Arch files in /dist/arch and /dist/arch-next, and the
# wheels in /dist/wheels. Started by .github/workflows/packages.yml and
# tests/packaging/run-containers.sh.
set -euo pipefail

mode=${1:?usage: container-test.sh package|script}
src=${SRC:-/src}
dist=${DIST:-/dist}

field() { sed -n "s/^$1 = \"\(.*\)\"$/\1/p" "$src/src/offscan/appinfo.py"; }
NAME=$(field NAME)
APP_ID=$(field APP_ID)
VERSION=$(field VERSION)
GUI="$NAME-gui"
STATE="/var/lib/$NAME"
export QT_QPA_PLATFORM=offscreen

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# shellcheck disable=SC1091
ids=$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")
family=""
for id in $ids; do
    case "$id" in
        debian|ubuntu) family=deb; break ;;
        fedora) family=fedora; break ;;
        opensuse*|suse) family=opensuse; break ;;
        arch|archlinux) family=arch; break ;;
    esac
done
[ -n "$family" ] || fail "unknown distribution: $ids"
# (os-release is read in a subshell: it defines NAME and VERSION too)
# shellcheck disable=SC1091
pretty=$(. /etc/os-release && echo "${PRETTY_NAME:-$ids}")
step "$pretty ($family), mode $mode, $NAME $VERSION"

# Container images leave out man pages and documentation; this test checks
# that every packaged file arrives, so let them in.
case "$family" in
    deb)
        rm -f /etc/dpkg/dpkg.cfg.d/excludes
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q >/dev/null ;;
    fedora)
        sed -i '/^tsflags=nodocs/d' /etc/dnf/dnf.conf ;;
    opensuse)
        sed -i 's/^rpm.install.excludedocs.*/rpm.install.excludedocs = no/' /etc/zypp/zypp.conf
        zypper --non-interactive --quiet refresh ;;
    arch)
        sed -i '/^NoExtract/d' /etc/pacman.conf
        pacman -Syu --noconfirm --quiet >/dev/null ;;
esac

OWN_PATHS=(
    "/usr/bin/$NAME" "/usr/bin/$GUI" "/usr/lib/$NAME" "/usr/share/doc/$NAME"
    "/usr/share/polkit-1/actions/$APP_ID.policy"
    "/usr/share/applications/$APP_ID.desktop" "/usr/share/metainfo/$APP_ID.metainfo.xml"
    "/usr/share/icons/hicolor/scalable/apps/$APP_ID.svg" "/usr/share/man/man1/$NAME.1.gz"
    "/usr/share/man/man1/$GUI.1.gz"
)
# Debian packages keep licence texts in /usr/share/doc/<package>/copyright.
if [ "$mode" = script ] || [ "$family" != deb ]; then
    OWN_PATHS+=("/usr/share/licenses/$NAME")
else
    OWN_PATHS+=("/usr/share/doc/$NAME/copyright")
fi

pkg_install() {     # install one native package file (or two, for an upgrade)
    case "$family" in
        deb) apt-get install -y -q "$@" ;;
        fedora) dnf install -y -q "$@" ;;
        opensuse) zypper --non-interactive --no-gpg-checks install --allow-unsigned-rpm "$@" ;;
        arch) pacman -U --noconfirm "$@" ;;
    esac
}

pkg_remove() {
    case "$family" in
        deb) apt-get purge -y -q "$NAME" ;;
        fedora) dnf remove -y -q "$NAME" ;;
        opensuse) zypper --non-interactive remove "$NAME" ;;
        arch) pacman -R --noconfirm "$NAME" ;;
    esac
}

pkg_version() {
    case "$family" in
        deb) dpkg-query -W -f='${Version}' "$NAME" ;;
        fedora|opensuse) rpm -q --qf '%{VERSION}-%{RELEASE}' "$NAME" ;;
        arch) pacman -Q "$NAME" | cut -d' ' -f2 ;;
    esac
}

built_arch=""
build_arch_package() {    # $1 = dist/arch or dist/arch-next; prints the package path
    local dir
    dir=/tmp/archbuild-$(basename "$1")
    if [ -z "$built_arch" ]; then
        pacman -S --needed --noconfirm --quiet fakeroot >/dev/null
        id builder >/dev/null 2>&1 || useradd -m builder
        # The runtime dependencies, so that makepkg needs no root rights.
        mapfile -t deps < <(sed -n 's/^\tdepends = //p' "$1/.SRCINFO")
        pacman -S --needed --noconfirm --quiet "${deps[@]}" >/dev/null
        built_arch=1
    fi
    rm -rf "$dir"
    mkdir -p "$dir"
    cp "$1"/PKGBUILD "$1"/.SRCINFO "$1"/*.install "$1"/*.tar.gz "$dist"/wheels/*.whl "$dir"/
    chown -R builder "$dir"
    su builder -c "cd '$dir' && PKGEXT=.pkg.tar.zst makepkg --noconfirm --nocolor" >&2
    ls "$dir"/*.pkg.tar.zst
}

package_file() {    # $1 = directory of the build output
    case "$family" in
        deb) ls "$1"/"${NAME}"_*_amd64.deb ;;
        fedora) ls "$1"/"$NAME"-*.fedora.x86_64.rpm ;;
        opensuse) ls "$1"/"$NAME"-*.opensuse.x86_64.rpm ;;
        arch) if [ "$1" = "$dist" ]; then build_arch_package "$dist/arch"; else build_arch_package "$dist/arch-next"; fi ;;
    esac
}

smoke() {
    step "smoke test"
    "$NAME" --version | grep -F "$VERSION" || fail "$NAME --version"
    "$NAME" selftest
    "$GUI" --self-check | tee /tmp/self-check.txt
    grep -q "self-check: OK" /tmp/self-check.txt || fail "$GUI --self-check"
    [ -x "/usr/lib/$NAME/$NAME-helper" ] || fail "helper missing"
    for path in "${OWN_PATHS[@]}"; do
        [ -e "$path" ] || fail "missing $path"
    done
    python3 -I -c 'import sys, xml.etree.ElementTree as ET; [ET.parse(p) for p in sys.argv[1:]]' \
        "/usr/share/polkit-1/actions/$APP_ID.policy" "/usr/share/metainfo/$APP_ID.metainfo.xml"
    if command -v desktop-file-validate >/dev/null; then
        desktop-file-validate "/usr/share/applications/$APP_ID.desktop"
    fi
    # The helper answers the protocol handshake as root (drive access itself
    # needs a real machine, not a container).
    python3 -I - "$NAME" <<'EOF'
import json, subprocess, sys
name = sys.argv[1]
proc = subprocess.run([f"/usr/lib/{name}/{name}-helper"], input=b"", capture_output=True, timeout=60)
hello = json.loads(proc.stdout.splitlines()[0])
print("helper hello:", {k: hello.get(k) for k in ("version", "ready", "error")})
assert hello.get("version"), hello
EOF
    # EICAR through every engine: hash lists, the vendored YARA-X and ClamAV.
    "$NAME" selftest --engines | tail -4
}

assert_gone() {
    local path
    for path in "${OWN_PATHS[@]}"; do
        [ ! -e "$path" ] || fail "$path is still there after removal"
    done
}

plant_data() {
    mkdir -p "$STATE/quarantine/test-entry" "$HOME/.local/share/$NAME/definitions"
    chmod 700 "$STATE"
    echo test > "$STATE/quarantine/test-entry/meta.json"
    echo test > "$HOME/.local/share/$NAME/definitions/test"
}

if [ "$mode" = package ]; then
    first=$(package_file "$dist")
    next=$(package_file "$dist/next")

    step "install $(basename "$first")"
    pkg_install "$first"
    echo "installed version $(pkg_version)"
    smoke

    step "install.sh must refuse to install over the package"
    if "$src/install.sh" --install --yes --no-deps --wheels "$dist/wheels"; then
        fail "install.sh installed over the native package"
    fi

    step "upgrade to $(basename "$next")"
    before=$(pkg_version)
    pkg_install "$next"
    after=$(pkg_version)
    echo "upgraded $before -> $after"
    [ "$before" != "$after" ] || fail "version did not change"
    smoke

    step "remove (data in $STATE must stay)"
    plant_data
    pkg_remove
    assert_gone
    [ -f "$STATE/quarantine/test-entry/meta.json" ] || fail "the quarantine was deleted"
    echo "removed; quarantine kept"
else
    wheels=(--wheels "$dist/wheels")

    step "install.sh --install"
    "$src/install.sh" --install --yes "${wheels[@]}"
    cp "$STATE/install-manifest.json" /tmp/manifest.json
    smoke

    step "install.sh --install again must refuse"
    if "$src/install.sh" --install --yes "${wheels[@]}"; then
        fail "a second --install did not refuse"
    fi

    step "install.sh --update"
    "$src/install.sh" --update --yes "${wheels[@]}"
    smoke

    step "the native package must refuse to install over install.sh"
    if [ "$family" = arch ]; then
        pkg_file=$(build_arch_package "$dist/arch")
    else
        pkg_file=$(package_file "$dist")
    fi
    if pkg_install "$pkg_file"; then
        fail "the native package installed over install.sh"
    fi

    step "install.sh --uninstall --yes keeps data"
    plant_data
    "$src/install.sh" --uninstall --yes
    assert_gone
    [ -f "$STATE/quarantine/test-entry/meta.json" ] || fail "the quarantine was deleted"
    [ -f "$HOME/.local/share/$NAME/definitions/test" ] || fail "definitions were deleted"

    step "install.sh --uninstall --purge deletes data"
    "$src/install.sh" --install --yes --no-deps "${wheels[@]}"
    "$src/install.sh" --uninstall --yes --purge
    assert_gone
    [ ! -e "$STATE" ] || fail "$STATE is still there after --purge"
    [ ! -e "$HOME/.local/share/$NAME/definitions" ] || fail "definitions are still there after --purge"
    python3 -I - <<'EOF'
import json, os
manifest = json.load(open("/tmp/manifest.json"))
left = [p for p in manifest["files"] if os.path.lexists(p)]
left += [d for d in manifest["dirs"] if os.path.lexists(d)]
assert not left, left
print(f"none of the {len(manifest['files'])} installed files is left")
EOF
fi
step "PASS ($pretty, $mode)"
