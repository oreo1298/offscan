"""The only module that talks to the network: definition downloads.

* HTTPS only (plain HTTP is accepted solely for sources that publish no
  HTTPS endpoint *and* sign their files, e.g. Sanesecurity mirrors; the
  signature is then mandatory).
* Redirects may not downgrade to HTTP.
* Downloads stream to a temporary file with a size cap and a SHA-256 of
  the bytes received; conditional requests (ETag / Last-Modified) avoid
  re-downloading unchanged files.
* HTTP 429/503 with Retry-After raise :class:`RateLimited` so the caller can
  record a cool-down instead of retrying.
* API keys that appear in URLs are registered with the log redactor.

No telemetry: nothing is sent except the request for the file itself.
"""

from __future__ import annotations

import email.utils
import hashlib
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .. import appinfo, log

logger = log.get("defs.net")
CHUNK = 1 << 16


class DownloadError(Exception):
    pass


class RateLimited(DownloadError):
    def __init__(self, url: str, retry_after: float):
        super().__init__(f"rate limited by the server; retry after {int(retry_after)}s")
        self.url = url
        self.retry_after = retry_after


class NotModified(Exception):
    pass


@dataclass
class Download:
    url: str
    path: Path
    size: int
    sha256: str
    etag: str | None
    last_modified: str | None
    content_type: str | None


class _NoDowngrade(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if req.full_url.startswith("https://") and not newurl.startswith("https://"):
            raise DownloadError(f"refusing redirect from HTTPS to {newurl.split(':', 1)[0]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    extra = os.environ.get(appinfo.env("CA_BUNDLE"))      # tests / corporate proxies
    if extra:
        ctx.load_verify_locations(cafile=extra)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class Session:
    def __init__(self, timeout: float = 60, allow_http: bool = False):
        self.timeout = timeout
        self.allow_http = allow_http
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_context()), _NoDowngrade())
        self.opener.addheaders = [("User-Agent", appinfo.USER_AGENT)]

    def _check_url(self, url: str, allow_http: bool) -> None:
        if url.startswith("https://"):
            return
        if url.startswith("http://") and (allow_http or self.allow_http):
            return
        raise DownloadError("only HTTPS downloads are allowed")

    def fetch(self, url: str, dest_dir: Path, *, max_size: int, etag: str | None = None,
              last_modified: str | None = None, allow_http: bool = False,
              headers: dict[str, str] | None = None) -> Download:
        """Download ``url`` into a new file in ``dest_dir``; raises NotModified."""
        self._check_url(url, allow_http)
        request = urllib.request.Request(url, headers=dict(headers or {}))  # noqa: S310 (checked above)
        if etag:
            request.add_header("If-None-Match", etag)
        if last_modified:
            request.add_header("If-Modified-Since", last_modified)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                raise NotModified(url) from None
            if exc.code in (429, 503):
                raise RateLimited(url, _retry_after(exc.headers.get("Retry-After"), 3600)) from None
            if exc.code == 403:
                raise DownloadError("access denied by the server (403): check the key, or the "
                                    "server may be blocking this IP for too many downloads") from None
            if exc.code == 401:
                raise DownloadError("the server requires a valid key (401)") from None
            raise DownloadError(f"HTTP {exc.code} {exc.reason}") from None
        except urllib.error.URLError as exc:
            raise DownloadError(f"cannot connect: {exc.reason}") from None
        except (TimeoutError, OSError) as exc:
            raise DownloadError(f"network error: {exc}") from None
        with response:
            final = response.geturl()
            self._check_url(final, allow_http)
            length = response.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > max_size:
                raise DownloadError(f"file is larger than the {max_size} byte limit")
            dest_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=dest_dir)
            digest = hashlib.sha256()
            size = 0
            try:
                with os.fdopen(fd, "wb") as out:
                    while True:
                        chunk = response.read(CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_size:
                            raise DownloadError(f"file is larger than the {max_size} byte limit")
                        digest.update(chunk)
                        out.write(chunk)
                if length and length.isdigit() and int(length) != size:
                    raise DownloadError(f"download truncated ({size} of {length} bytes)")
            except BaseException:
                os.unlink(tmp)
                raise
            return Download(url=final, path=Path(tmp), size=size, sha256=digest.hexdigest(),
                            etag=response.headers.get("ETag"),
                            last_modified=response.headers.get("Last-Modified"),
                            content_type=response.headers.get("Content-Type"))

    def fetch_text(self, url: str, max_size: int = 1 << 20, allow_http: bool = False,
                   headers: dict[str, str] | None = None) -> str:
        with tempfile.TemporaryDirectory(prefix=f"{appinfo.NAME}-txt-") as tmp:
            dl = self.fetch(url, Path(tmp), max_size=max_size, allow_http=allow_http, headers=headers)
            return dl.path.read_text(encoding="utf-8", errors="replace")


def _retry_after(value: str | None, default: float) -> float:
    if not value:
        return default
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError):
        return default
