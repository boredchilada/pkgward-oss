# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm registry download with SRI (sha512) / shasum (sha1) integrity verification.

Tarballs are gzip tarballs whose members are prefixed with ``package/`` — the
pipeline strips that top dir for hashing/version-diff (``npm_tarball`` is in the
strip set, mirroring ``crate``/``gomod_zip``).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import tempfile
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import httpx

from pkgsentry.adapter import ArchivePath, FetchResult, IntegrityError, NoFilesError
from pkgsentry.logging_setup import get_logger
from pkgsentry.util.user_agent import user_agent

log = get_logger("npm.fetch")

USER_AGENT = user_agent()
REGISTRY_BASE = "https://registry.npmjs.org"
WORK_ROOT = Path(tempfile.gettempdir()) / "pkgsentry_npm"

# npm registry has no published per-IP rate limit, but be a good citizen.
_registry_limiter = asyncio.Semaphore(10)


async def get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[dict] = None,
    timeout: float = 20.0,
    max_retries: int = 4,
):
    """GET that backs off on 429/503, honoring ``Retry-After`` when present.

    The npm registry (especially ``/-/v1/search``) rate-limits bursts; without
    backoff a watchlist refresh / queue seed gets a wall of 429s. Returns the
    final response (the caller inspects ``status_code``)."""
    delay = 1.0
    resp = None
    for attempt in range(max_retries + 1):
        resp = await client.get(url, params=params, timeout=timeout)
        if resp.status_code not in (429, 503):
            return resp
        if attempt == max_retries:
            return resp
        ra = resp.headers.get("Retry-After", "")
        wait = float(ra) if ra.isdigit() else delay
        await asyncio.sleep(min(wait, 30.0))
        delay = min(delay * 2, 30.0)
    return resp


def _encode_name(name: str) -> str:
    """URL-encode a package name for registry paths.

    Scoped names ``@scope/pkg`` encode the separator slash as ``%2f`` while
    keeping the leading ``@``. Unscoped names are returned unchanged.
    """
    if name.startswith("@"):
        scope, _, pkg = name[1:].partition("/")
        if pkg:
            return f"@{quote(scope, safe='')}%2f{quote(pkg, safe='')}"
    return quote(name, safe="")


def _short_name(name: str) -> str:
    """Last path segment of a (possibly scoped) name, for tarball filenames."""
    return name.rsplit("/", 1)[-1]


def _verify_integrity(content: bytes, dist: dict, label: str) -> None:
    """Verify a tarball against the version's ``dist`` block.

    Prefers SRI ``integrity`` (``sha512-<base64>``); falls back to the legacy
    hex ``shasum`` (sha1). Raises :class:`IntegrityError` on mismatch, and when
    neither field is present (an unverifiable download is treated as a failure).
    """
    integrity = dist.get("integrity")
    if integrity and "-" in integrity:
        algo, _, b64 = integrity.partition("-")
        try:
            expected = base64.b64decode(b64)
        except Exception as e:  # malformed SRI
            raise IntegrityError(f"malformed integrity for {label}: {integrity!r}") from e
        try:
            actual = hashlib.new(algo, content).digest()
        except ValueError as e:  # unknown algo
            raise IntegrityError(f"unsupported integrity algo for {label}: {algo}") from e
        if actual != expected:
            raise IntegrityError(f"{algo} integrity mismatch for {label}")
        return

    shasum = dist.get("shasum")
    if shasum:
        actual = hashlib.sha1(content).hexdigest()
        if actual != shasum.lower():
            raise IntegrityError(
                f"shasum mismatch for {label}: expected {shasum}, got {actual}"
            )
        return

    raise IntegrityError(f"no integrity/shasum to verify {label}")


async def _get_manifest(client: httpx.AsyncClient, name: str, version: str) -> dict:
    """Fetch a single-version manifest from the registry.

    ``GET /{pkg}/{version}`` (or ``/{pkg}/latest``) returns just that version's
    document, including the ``dist`` block — far lighter than the full packument.
    """
    encoded = _encode_name(name)
    async with _registry_limiter:
        resp = await get_with_retry(client, f"{REGISTRY_BASE}/{encoded}/{version}", timeout=30.0)
    if resp.status_code == 404:
        raise NoFilesError(f"npm package/version not found: {name}@{version}")
    resp.raise_for_status()
    return resp.json()


def _normalize_metadata(manifest: dict) -> dict:
    """Map an npm version manifest onto the shared metadata keys."""
    author = manifest.get("author")
    if isinstance(author, dict):
        author_name = author.get("name") or ""
        author_email = author.get("email") or None
    elif isinstance(author, str):
        author_name = author
        author_email = None
    else:
        author_name = ""
        author_email = None

    license_val = manifest.get("license")
    if isinstance(license_val, dict):  # legacy {type, url}
        license_val = license_val.get("type") or ""

    keywords = manifest.get("keywords")
    if isinstance(keywords, list):
        keywords = ", ".join(str(k) for k in keywords)

    repo = manifest.get("repository")
    if isinstance(repo, dict):
        home_page = repo.get("url") or manifest.get("homepage") or ""
    else:
        home_page = manifest.get("homepage") or (repo if isinstance(repo, str) else "")

    deps = manifest.get("dependencies")
    requires_dist = sorted(deps.keys()) if isinstance(deps, dict) else None

    return {
        "summary": manifest.get("description") or "",
        "home_page": home_page,
        "keywords": keywords or "",
        "license": license_val or "",
        "author": author_name or None,
        "author_email": author_email,
        "requires_dist": requires_dist,
        "_raw_npm": manifest,
    }


async def download_tarball(name: str, version: str) -> FetchResult:
    """Download an npm ``.tgz`` and verify its integrity.

    ``version='latest'`` resolves via the ``/{pkg}/latest`` dist-tag endpoint.
    """
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        manifest = await _get_manifest(client, name, version)
        resolved = manifest.get("version") or version
        if version == "latest":
            log.info("resolved_latest", name=name, version=resolved)

        dist = manifest.get("dist") or {}
        tarball_url = dist.get("tarball")
        if not tarball_url:
            raise NoFilesError(f"no tarball url for {name}@{resolved}")

        work_dir = Path(tempfile.mkdtemp(dir=WORK_ROOT, prefix=f"{_short_name(name)}-{resolved}-"))
        work_dir.chmod(0o755)

        async with _registry_limiter:
            resp = await client.get(tarball_url, timeout=120.0, follow_redirects=True)
        if resp.status_code == 404:
            raise NoFilesError(f"tarball not found: {name}@{resolved}")
        resp.raise_for_status()
        content = resp.content

        _verify_integrity(content, dist, f"{name}@{resolved}")

        dest = work_dir / f"{_short_name(name)}-{resolved}.tgz"
        dest.write_bytes(content)
        sha256 = hashlib.sha256(content).hexdigest()
        metadata = _normalize_metadata(manifest)

    archive = ArchivePath(path=dest, kind="npm_tarball", sha256=sha256)
    size_mb = round(dest.stat().st_size / (1024 * 1024), 1)
    log.info("downloaded", ecosystem="npm", name=name, version=resolved,
             total_mb=size_mb, archives=[f"npm_tarball:{dest.name}({size_mb}MB)"])
    return FetchResult(archives=[archive], metadata=metadata)


def sweep_orphans(max_age_seconds: float = 3600.0) -> int:
    """Remove stale work directories."""
    import shutil
    if not WORK_ROOT.exists():
        return 0
    now = time.time()
    removed = 0
    for entry in WORK_ROOT.iterdir():
        try:
            age = now - entry.stat().st_mtime
            if age > max_age_seconds:
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        except Exception:
            pass
    return removed
