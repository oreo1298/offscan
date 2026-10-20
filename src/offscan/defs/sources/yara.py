"""YARA rule sources: YARA Forge, GitHub rule repositories, YARAify."""

from __future__ import annotations

import shutil
import time
from pathlib import Path, PurePosixPath
from typing import Any

from ...scan import yara_engine
from .. import net, verify
from .base import DAY, FetchContext, Source, SourceError, SourceInfo, Unchanged, write_material
from .github import (
    api_unavailable,
    branch_tarball_without_api,
    github_head,
    github_tarball,
    latest_asset_without_api,
    latest_release,
    release_asset,
)

MiB = 1 << 20
FORGE_TIERS = ("core", "extended", "full")


def _material_from_rule_files(ctx: FetchContext, files: list[Path], version: str, verified: str,
                              **extra: Any) -> dict[str, Any]:
    rules = []
    count = 0
    for path in sorted(files):
        rel = path.relative_to(ctx.staging).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        count += yara_engine.count_rules(text)
        rules.append({"file": rel, "origin": rel})
    if not rules:
        raise SourceError("no YARA rule files found")
    return write_material(ctx.staging, {"yara": rules, "version": version, "verified": verified,
                                        "rules": count, **extra})


def fetch_repo_tarball(ctx: FetchContext, repo: str, branch: str) -> tuple[Path, str, str]:
    """Tarball pinned to the branch head commit (or, without the API, hashed by content)."""
    try:
        sha = github_head(ctx, repo, branch)
    except (net.DownloadError, SourceError) as exc:
        if not api_unavailable(exc):
            raise
        tarball, version = branch_tarball_without_api(ctx, repo, branch)
        if ctx.previous and ctx.state.get("version") == version:
            raise Unchanged(version) from None
        return tarball, version, "https (GitHub API unavailable)"
    if ctx.previous and ctx.state.get("version") == sha[:12]:
        raise Unchanged(sha)
    return github_tarball(ctx, repo, sha), sha[:12], "github-commit"


class YaraForge(Source):
    info = SourceInfo(
        id="yara-forge", name="YARA Forge", kind="yara",
        homepage="https://yarahq.github.io/", license="Mixed (per rule; see each rule's metadata)",
        license_url="https://github.com/YARAHQ/yara-forge",
        terms="Curated, tested package of public YARA rules from about 40 sources. Every rule "
              "keeps its author and licence metadata, which this program shows with each match "
              "(required by the Detection Rule License used by several sources). Some rules are "
              "non-commercial (CC BY-NC) or have no stated licence: personal use only.",
        default_enabled=True, min_interval=DAY, size_hint="core 2 MB, extended 4 MB, full 4 MB",
        group="YARA", integrity="GitHub release asset SHA-256 digest")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        tier = self.settings.source(self.id).get("tier", "core")
        if tier not in FORGE_TIERS:
            tier = "core"
        asset = f"yara-forge-rules-{tier}.zip"
        try:
            release = latest_release(ctx, "YARAHQ/yara-forge")
        except (net.DownloadError, SourceError) as exc:
            if not api_unavailable(exc):
                raise
            release = None
        if release is not None:
            tag = str(release["tag_name"])
            if ctx.previous and ctx.state.get("version") == f"{tag} {tier}":
                raise Unchanged(tag)
            archive, verified = release_asset(ctx, release, asset)
        else:
            archive = latest_asset_without_api(ctx, "YARAHQ/yara-forge", asset)
            tag = verify.sha256_file(archive)[:12]
            verified = "https (GitHub API unavailable)"
            if ctx.previous and ctx.state.get("version") == f"{tag} {tier}":
                raise Unchanged(tag)
        files = verify.extract_zip(archive, ctx.staging / "rules", lambda r: r.suffix == ".yar",
                                   max_file=128 * MiB, max_total=256 * MiB, flatten=True)
        archive.unlink()
        return _material_from_rule_files(ctx, files, f"{tag} {tier}", verified, tier=tier)


class GitHubRules(Source):
    repo = ""
    branch = "main"
    subdirs: tuple[str, ...] = ()        # only rule files below these top-level paths
    extensions = (".yar", ".yara")
    exclude_names: tuple[str, ...] = ()

    def wanted(self, rel: PurePosixPath) -> bool:
        if rel.suffix.lower() not in self.extensions or rel.name in self.exclude_names:
            return False
        posix = rel.as_posix()
        return not self.subdirs or any(posix.startswith(s.rstrip("/") + "/") for s in self.subdirs)

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        tarball, version, verified = fetch_repo_tarball(ctx, self.repo, self.branch)
        files = verify.extract_tar(tarball, ctx.staging / "rules", self.wanted, max_file=32 * MiB,
                                   max_total=512 * MiB, strip_components=1)
        tarball.unlink()
        self.post_extract(ctx, files)
        files = [f for f in files if f.exists()]
        return _material_from_rule_files(ctx, files, version, verified)

    def post_extract(self, ctx: FetchContext, files: list[Path]) -> None:
        return None


class SignatureBase(GitHubRules):
    info = SourceInfo(
        id="signature-base", name="Neo23x0 signature-base (raw)", kind="yara",
        homepage="https://github.com/Neo23x0/signature-base", license="DRL 1.1",
        license_url="https://github.com/Neo23x0/signature-base/blob/master/LICENSE",
        terms="Detection Rule License 1.1: free to use and share; the rule author must be "
              "shown with every match (this program does). A few rules are CC BY-NC.",
        default_enabled=False, min_interval=DAY, size_hint="about 7 MB", group="YARA",
        integrity="HTTPS from GitHub, pinned to the latest commit",
        warning="YARA Forge already includes the best of these rules; enable this only instead "
                "of YARA Forge, or expect duplicates.")
    repo, branch, subdirs = "Neo23x0/signature-base", "master", ("yara",)

    def post_extract(self, ctx: FetchContext, files: list[Path]) -> None:
        # Rules that need THOR-specific external variables would misfire without them.
        listing = ctx.staging / "rules" / "yara" / "external-variable-rules.txt"
        names = set()
        if listing.exists():
            names = {line.strip() for line in listing.read_text().splitlines() if line.strip()}
        for path in files:
            if path.name in names:
                path.unlink()


class ElasticRules(GitHubRules):
    info = SourceInfo(
        id="elastic", name="Elastic protections-artifacts YARA rules", kind="yara",
        homepage="https://github.com/elastic/protections-artifacts", license="Elastic License 2.0",
        license_url="https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt",
        terms="Elastic License 2.0 (source-available, not open source): you may use the rules "
              "yourself; you may not offer them as a managed service. Licence notices must be "
              "kept when sharing.", default_enabled=False, requires_acceptance=True,
        min_interval=DAY, size_hint="about 3 MB", group="YARA",
        integrity="HTTPS from GitHub, pinned to the latest commit")
    repo, branch, subdirs = "elastic/protections-artifacts", "main", ("yara/rules",)


class ReversingLabsRules(GitHubRules):
    info = SourceInfo(
        id="reversinglabs", name="ReversingLabs YARA rules", kind="yara",
        homepage="https://github.com/reversinglabs/reversinglabs-yara-rules", license="MIT",
        license_url="https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE",
        terms="MIT.", default_enabled=False, min_interval=DAY, size_hint="about 3 MB", group="YARA",
        integrity="HTTPS from GitHub, pinned to the latest commit",
        warning="Already included in YARA Forge 'extended' and 'full'.")
    repo, branch, subdirs = "reversinglabs/reversinglabs-yara-rules", "develop", ("yara",)


class BartblazeRules(GitHubRules):
    info = SourceInfo(
        id="bartblaze", name="bartblaze YARA rules", kind="yara",
        homepage="https://github.com/bartblaze/Yara-rules", license="MIT",
        license_url="https://github.com/bartblaze/Yara-rules/blob/master/LICENSE",
        terms="MIT. Rules marked category INFO are informational and shown as such.",
        default_enabled=False, min_interval=DAY, size_hint="< 1 MB", group="YARA",
        integrity="HTTPS from GitHub, pinned to the latest commit")
    repo, branch, subdirs = "bartblaze/Yara-rules", "master", ("rules",)


class YaraRulesProject(GitHubRules):
    info = SourceInfo(
        id="yara-rules", name="Yara-Rules project (unmaintained)", kind="yara",
        homepage="https://github.com/Yara-Rules/rules", license="GPL-2.0",
        license_url="https://github.com/Yara-Rules/rules/blob/master/LICENSE",
        terms="GPL-2.0.", default_enabled=False, min_interval=DAY, size_hint="about 10 MB",
        group="YARA", integrity="HTTPS from GitHub, pinned to the latest commit",
        warning="Not updated since 2022 and prone to false positives; only the malware, "
                "webshells and maldocs folders are used.")
    repo, branch, subdirs = "Yara-Rules/rules", "master", ("malware", "webshells", "maldocs")


class YARAify(Source):
    info = SourceInfo(
        id="yaraify", name="YARAify / YARAhub (abuse.ch)", kind="yara",
        homepage="https://yaraify.abuse.ch/", license="Per rule (CC0 to CC BY-NC-SA), TLP:CLEAR",
        license_url="https://yaraify.abuse.ch/yarahub/", terms="Community rules shared on "
        "YARAhub; each rule states its own licence. abuse.ch fair-use terms apply.",
        default_enabled=False, requires_secret="abusech_auth_key", secret_optional=True,
        min_interval=DAY, size_hint="a few MB", group="YARA", integrity="HTTPS + compile validation")

    def fetch(self, ctx: FetchContext) -> dict[str, Any]:
        key = ctx.secret("abusech_auth_key")
        url = self.base_url("https://yaraify.abuse.ch/yarahub/").rstrip("/") + "/yaraify-rules.zip"
        archive = ctx.download(url, "rules.zip", max_size=256 * MiB,
                               headers={"Auth-Key": key} if key else None)
        files = verify.extract_zip(archive, ctx.staging / "rules",
                                   lambda r: r.suffix.lower() in (".yar", ".yara"),
                                   max_file=8 * MiB, max_total=256 * MiB)
        archive.unlink()
        return _material_from_rule_files(ctx, files, time.strftime("%Y-%m-%d", time.gmtime(ctx.now)),
                                         "https")


__all__ = ["FORGE_TIERS", "BartblazeRules", "ElasticRules", "GitHubRules", "ReversingLabsRules",
           "SignatureBase", "YARAify", "YaraForge", "YaraRulesProject", "shutil"]
