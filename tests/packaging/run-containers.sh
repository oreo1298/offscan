#!/usr/bin/env bash
# Build the packages, then run the install tests in distribution containers.
#
#   tests/packaging/run-containers.sh build
#       build everything container-test.sh needs into dist/ (nfpm on PATH, or NFPM=...)
#   tests/packaging/run-containers.sh run IMAGE MODE
#       run tests/packaging/container-test.sh MODE (package or script) in IMAGE
#
# DOCKER_ARGS adds options to 'docker run', for example "--network host".
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
case "${1:-}" in
    build)
        nfpm=${NFPM:-nfpm}
        cd "$root"
        rm -rf dist
        python3 packaging/build.py fetch --cache dist/wheels
        python3 packaging/build.py packages --wheels dist/wheels --offline --nfpm "$nfpm" --out dist
        next=$(python3 packaging/build.py version next)
        python3 packaging/build.py packages --wheels dist/wheels --offline --nfpm "$nfpm" \
            --out dist/next --version "$next"
        tarball=$(python3 packaging/build.py tarball --out dist)
        python3 packaging/build.py pkgbuild --tarball "$tarball" --out dist/arch
        python3 packaging/build.py pkgbuild --tarball "$tarball" --out dist/arch-next --version "$next"
        ;;
    run)
        image=${2:?usage: run-containers.sh run IMAGE package|script}
        mode=${3:?usage: run-containers.sh run IMAGE package|script}
        # shellcheck disable=SC2086
        docker run --rm ${DOCKER_ARGS:-} -e HOME=/root -v "$root:/src:ro" -v "$root/dist:/dist:ro" \
            "$image" bash /src/tests/packaging/container-test.sh "$mode"
        ;;
    *)
        sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
