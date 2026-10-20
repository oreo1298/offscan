"""GitHub helpers: resolve a branch to a commit, download pinned tarballs and release assets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import net, verify
from .base import FetchContext, SourceError

API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"
WEB = "https://github.com"
ASSET_PREFIXES = ("https://github.com/",)
MiB = 1 << 20


def _headers(ctx: FetchContext, accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.secret("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_head(ctx: FetchContext, repo: str, branch: str) -> str:
    """Commit SHA of ``branch`` (pins the following download to that exact tree)."""
    text = ctx.session.fetch_text(f"{API}/repos/{repo}/commits/{branch}", max_size=64 * 1024,
                                  headers=_headers(ctx, "application/vnd.github.sha"))
    sha = text.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SourceError(f"unexpected answer from GitHub for {repo}@{branch}")
    return sha


def github_tarball(ctx: FetchContext, repo: str, sha: str, max_size: int = 512 * MiB) -> Path:
    return ctx.download(f"{CODELOAD}/{repo}/tar.gz/{sha}", f"{repo.replace('/', '_')}.tar.gz",
                        max_size=max_size, conditional=False)


def latest_release(ctx: FetchContext, repo: str) -> dict[str, Any]:
    text = ctx.session.fetch_text(f"{API}/repos/{repo}/releases/latest", max_size=4 * MiB,
                                  headers=_headers(ctx))
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SourceError("unexpected release data from GitHub") from exc
    if not isinstance(data, dict) or "tag_name" not in data:
        raise SourceError("unexpected release data from GitHub")
    return data


def release_asset(ctx: FetchContext, release: dict[str, Any], name: str,
                  max_size: int = 256 * MiB) -> tuple[Path, str]:
    """Download a release asset and verify GitHub's recorded SHA-256 digest when present."""
    for asset in release.get("assets") or []:
        if asset.get("name") == name:
            url = str(asset.get("browser_download_url", ""))
            if not url.startswith(ASSET_PREFIXES):
                raise SourceError("unexpected asset URL")
            path = ctx.download(url, name, max_size=max_size, conditional=False)
            digest = str(asset.get("digest") or "")
            if digest.startswith("sha256:"):
                verify.expect_sha256(path, digest.split(":", 1)[1])
                return path, "github-digest"
            return path, "https"
    raise SourceError(f"release has no asset named {name}")


def latest_asset_without_api(ctx: FetchContext, repo: str, name: str,
                             max_size: int = 256 * MiB) -> Path:
    """Fallback when the API is rate limited: GitHub's stable 'latest' download link."""
    return ctx.download(f"{WEB}/{repo}/releases/latest/download/{name}", name, max_size=max_size,
                        conditional=False)


def branch_tarball_without_api(ctx: FetchContext, repo: str, branch: str,
                               max_size: int = 512 * MiB) -> tuple[Path, str]:
    """Fallback when the API is rate limited: tarball of the branch; version = content hash."""
    path = ctx.download(f"{CODELOAD}/{repo}/tar.gz/refs/heads/{branch}",
                        f"{repo.replace('/', '_')}.tar.gz", max_size=max_size, conditional=False)
    return path, verify.sha256_file(path)[:12]


def api_unavailable(exc: Exception) -> bool:
    text = str(exc)
    return "403" in text or "429" in text or "rate limit" in text.lower()


__all__ = ["api_unavailable", "branch_tarball_without_api", "github_head", "github_tarball",
           "latest_asset_without_api", "latest_release", "net", "release_asset"]
