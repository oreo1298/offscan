# Releasing

1. Set `VERSION` in `src/offscan/appinfo.py`, and add a `## <version>` section to
   `CHANGELOG.md` (its text becomes the release notes).
2. Check that CI and the `packages` workflow are green on the commit.
3. Tag the commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "Offscan 0.1.0"
   git push origin v0.1.0
   ```

   The `packages` workflow builds the packages for x86_64 and aarch64 and runs
   the install tests on every distribution. Only if all of them pass does it
   publish a GitHub release with:
   * the `.deb` files;
   * the Fedora and openSUSE `.rpm` files;
   * the source tarball;
   * `<name>-<version>-aur.tar.gz` (PKGBUILD, .SRCINFO and the .install file);
   * `SHA256SUMS`.

   The release job checks that the tag matches `VERSION`.
4. **AUR:** unpack `<name>-<version>-aur.tar.gz` into your clone of the AUR
   repository (`ssh://aur@aur.archlinux.org/offscan.git`), then run:

   ```sh
   makepkg --printsrcinfo | diff - .SRCINFO   # must be identical
   makepkg -sf && namcap PKGBUILD *.pkg.tar.zst
   git commit -am "Update to <version>" && git push
   ```

   The PKGBUILD fetches the source tarball from the GitHub release, and the
   vendored wheels from PyPI. Every one of them is pinned by SHA-256.
5. Bump `VERSION` to the next `.dev0` version.

## Updating a vendored wheel

Edit `packaging/vendor.lock.json` (file name, URL and SHA-256 for every
architecture), run `python3 packaging/build.py fetch`, run the tests, and check
the wheel's licence. Every vendored package must carry a licence text: if its
wheel has none, add one under `packaging/licenses/` and name it in
`license_files`.

## Renaming

Edit the first block of `src/offscan/appinfo.py` and run `python3 tools/rename.py`.
Packages, paths, the polkit action, the desktop file, the AppStream metadata and
the scan account are all derived from it.
