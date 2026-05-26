# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io CDN download with SHA256 verification."""
from __future__ import annotations

import asyncio
import hashlib
import tempfile
import time
from pathlib import Path

import httpx

from pkgsentry.adapter import ArchivePath, FetchResult, IntegrityError, NoFilesError
from pkgsentry.logging_setup import get_logger
from pkgsentry.util.user_agent import user_agent

log = get_logger("crates.fetch")

USER_AGENT = user_agent()
CDN_BASE = "https://static.crates.io/crates"
API_BASE = "https://crates.io/api/v1/crates"
WORK_ROOT = Path(tempfile.gettempdir()) / "pkgsentry_crates"

# Rate limiters
_api_limiter = asyncio.Semaphore(1)   # 1 req/s to API
_cdn_limiter = asyncio.Semaphore(10)  # 10 concurrent to CDN


def _build_download_url(name: str, version: str) -> str:
    return f"{CDN_BASE}/{name}/{name}-{version}.crate"


def _build_api_url(name: str, version: str) -> str:
    return f"{API_BASE}/{name}/{version}"


async def _get_expected_checksum(client: httpx.AsyncClient, name: str, version: str) -> str:
    """Fetch expected SHA256 checksum from crates.io API."""
    async with _api_limiter:
        resp = await client.get(
            _build_api_url(name, version),
            timeout=30.0,
        )
        await asyncio.sleep(1.0)  # respect 1 req/s
    resp.raise_for_status()
    data = resp.json()
    cksum = data.get("version", {}).get("checksum", "")
    if not cksum:
        raise NoFilesError(f"no checksum for {name}=={version}")
    return cksum


async def _resolve_latest(client: httpx.AsyncClient, name: str) -> str:
    """Resolve 'latest' to the actual newest version string."""
    async with _api_limiter:
        resp = await client.get(f"{API_BASE}/{name}", timeout=30.0)
        await asyncio.sleep(1.0)
    resp.raise_for_status()
    data = resp.json()
    ver = data.get("crate", {}).get("newest_version", "")
    if not ver:
        raise NoFilesError(f"cannot resolve latest version for {name}")
    return ver


async def download_crate(name: str, version: str) -> FetchResult:
    """Download a .crate file and verify its SHA256 checksum."""
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        if version == "latest":
            version = await _resolve_latest(client, name)
            log.info("resolved_latest", name=name, version=version)

        work_dir = Path(tempfile.mkdtemp(dir=WORK_ROOT, prefix=f"{name}-{version}-"))
        work_dir.chmod(0o755)
        # Get expected checksum from API
        expected_sha = await _get_expected_checksum(client, name, version)

        # Download from CDN
        url = _build_download_url(name, version)
        dest = work_dir / f"{name}-{version}.crate"

        async with _cdn_limiter:
            resp = await client.get(url, timeout=120.0, follow_redirects=True)

        if resp.status_code == 404:
            raise NoFilesError(f"crate not found: {name}=={version}")
        resp.raise_for_status()

        dest.write_bytes(resp.content)

        # Verify SHA256
        actual_sha = hashlib.sha256(resp.content).hexdigest()
        if actual_sha != expected_sha:
            raise IntegrityError(
                f"SHA256 mismatch for {name}-{version}.crate: "
                f"expected {expected_sha}, got {actual_sha}"
            )

        # Fetch metadata from API (already have version data)
        async with _api_limiter:
            crate_resp = await client.get(
                f"{API_BASE}/{name}",
                timeout=30.0,
            )
            await asyncio.sleep(1.0)
        metadata = {}
        if crate_resp.status_code == 200:
            crate_data = crate_resp.json().get("crate", {})
            # Normalize to match PyPI metadata keys
            metadata = {
                "summary": crate_data.get("description", ""),
                "home_page": crate_data.get("repository") or crate_data.get("homepage", ""),
                "keywords": ", ".join(crate_data.get("keywords", [])),
                "license": crate_data.get("license", ""),
                "author": ", ".join(
                    o.get("name", "") for o in crate_data.get("owners", [])
                ) if "owners" in crate_data else None,
                # Preserve full raw data
                "_raw_crate": crate_data,
            }

    archive = ArchivePath(path=dest, kind="crate", sha256=actual_sha)
    size_mb = round(dest.stat().st_size / (1024 * 1024), 1)
    log.info("downloaded", ecosystem="crates", name=name, version=version,
             total_mb=size_mb, archives=[f"crate:{dest.name}({size_mb}MB)"])
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
