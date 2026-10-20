# Security policy

Offscan runs as root to read drives that may come from an attacker, so security
reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately with GitHub's vulnerability reporting: on the
repository page, open **Security**, then **Report a vulnerability**. Please do
not open a public issue for something that could be exploited.

Helpful details: the version (`offscan --version`), the distribution, and what
an attacker needs to control (a drive, a local account, a definition feed, the
network). A crafted test image is welcome, but please never send real malware.
Use the EICAR test string or harmless stand-ins.

You will get an answer within a week. Fixes are released as soon as they are
ready, and the advisory credits you unless you prefer otherwise.

## Supported versions

Only the latest release gets security fixes.

## Design

[docs/security.md](docs/security.md) describes the threat model, how
privileges are split, and the known limits.
