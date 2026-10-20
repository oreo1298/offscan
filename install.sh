#!/usr/bin/env bash
# Install, update or remove the application from this source tree, on Arch,
# Debian/Ubuntu/Mint, Fedora and openSUSE. Prefer the distribution packages
# (see README.md) when you can; this is for everything else.
#
#   sudo ./install.sh --install      install, with the missing distribution packages
#   sudo ./install.sh --update       update to the version in this tree
#   sudo ./install.sh --uninstall    remove; asks before deleting definitions,
#                                    the quarantine, the change log, history and reports
#
# Run ./install.sh --help for all options. The work is done by
# packaging/installer.py; this script only makes sure Python 3.11 or newer is
# there and that it runs as root.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
installer="$here/packaging/installer.py"

usage_only=0
assume_yes=0
no_deps=0
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage_only=1 ;;
        -y|--yes) assume_yes=1 ;;
        --no-deps|--offline) no_deps=1 ;;
    esac
done

find_python() {
    local candidate
    for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

if [ "$usage_only" = 1 ]; then
    if python=$(find_python); then
        exec "$python" -I "$installer" --help
    fi
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

if [ "$(id -u)" != 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -- "$0" "$@"
    fi
    echo "install.sh: run this as root (sudo is not installed)" >&2
    exit 2
fi

if ! python=$(find_python); then
    if [ "$no_deps" = 1 ]; then
        echo "install.sh: Python 3.11 or newer is needed" >&2
        exit 2
    fi
    family=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        ids=$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")
        for id in $ids; do
            case "$id" in
                debian|ubuntu) family=deb; break ;;
                fedora) family=fedora; break ;;
                opensuse*|suse|sles) family=opensuse; break ;;
                arch|archlinux) family=arch; break ;;
            esac
        done
    fi
    case "$family" in
        deb) cmd=(apt-get install python3) ;;
        fedora) cmd=(dnf install python3) ;;
        opensuse) cmd=(zypper install python3) ;;
        arch) cmd=(pacman -S --needed python) ;;
        *) echo "install.sh: Python 3.11 or newer is needed; install it first" >&2; exit 2 ;;
    esac
    if [ "$assume_yes" = 1 ]; then
        case "$family" in
            deb) apt-get update -q; cmd=(apt-get install -y python3) ;;
            fedora) cmd=(dnf install -y python3) ;;
            opensuse) cmd=(zypper --non-interactive install python3) ;;
            arch) cmd=(pacman -S --needed --noconfirm python) ;;
        esac
    else
        read -r -p "Python 3 is missing. Install it with '${cmd[*]}'? [y/N] " answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) echo "install.sh: cancelled" >&2; exit 1 ;;
        esac
        if [ "$family" = deb ]; then
            apt-get update -q
        fi
    fi
    "${cmd[@]}"
    python=$(find_python) || { echo "install.sh: Python 3.11 or newer is needed" >&2; exit 2; }
fi

exec "$python" -I "$installer" "$@"
