# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import hashlib
import tempfile
import time
from pathlib import Path
from typing import Optional

import httpx

from pkgsentry.adapter import ArchivePath, IntegrityError, NoFilesError, FetchResult
from pkgsentry.logging_setup import get_logger
from pkgsentry.util.user_agent import user_agent

log = get_logger("fetch.download")

WORK_ROOT: Path = Path(tempfile.gettempdir()) / "pkgsentry"
JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
RATE_LIMIT_PER_SEC = 10.0
_HOSTNAME = "files.pythonhosted.org"


def sweep_orphans(max_age_seconds: float = 3600.0) -> int:
    """Remove WORK_ROOT entries older than `max_age_seconds`. Defensive cleanup
    for archives the pipeline failed to remove (crash / SIGKILL mid-scan).
    Returns the count of dirs removed.
    """
    import shutil
    if not WORK_ROOT.exists():
        return 0
    now = time.time()
    removed = 0
    for entry in WORK_ROOT.iterdir():
        try:
            age = now - entry.stat().st_mtime
        except OSError:
            continue
        if age > max_age_seconds:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    if removed:
        log.info("workroot_swept", removed=removed)
    return removed


class _RateLimiter:
    def __init__(self, per_sec: float) -> None:
        self._interval = 1.0 / per_sec if per_sec > 0 else 0.0
        self._lock: Optional[asyncio.Lock] = None
        self._loop_id: Optional[int] = None
        self._next: float = 0.0

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or id(loop) != self._loop_id:
            self._lock = asyncio.Lock()
            self._loop_id = id(loop)
        return self._lock

    async def acquire(self) -> None:
        if self._interval == 0:
            return
        async with self._get_lock():
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self._interval


_files_limiter = _RateLimiter(RATE_LIMIT_PER_SEC)


async def _get_json(client: httpx.AsyncClient, name: str, version: str) -> dict:
    url = JSON_URL.format(name=name, version=version)
    r = await client.get(url, timeout=20.0)
    r.raise_for_status()
    return r.json()


async def _download_url(client: httpx.AsyncClient, url: str, dest: Path) -> None:
    if _HOSTNAME in url:
        await _files_limiter.acquire()
    r = await client.get(url, timeout=60.0)
    r.raise_for_status()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(r.content)


def _pick_url(urls: list[dict], packagetype: str) -> Optional[dict]:
    for u in urls:
        if u.get("packagetype") == packagetype:
            return u
    return None


async def download_all(name: str, version: str) -> FetchResult:
    """Download sdist + wheel concurrently. Raises IntegrityError on sha256 mismatch.

    Returns a FetchResult with the archives and the raw PyPI ``info{}`` block
    so callers can persist metadata alongside the scan.
    """
    import shutil

    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"{name}-{version}-", dir=WORK_ROOT))
    work.chmod(0o755)

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": user_agent()},
            follow_redirects=True,
        ) as client:
            meta = await _get_json(client, name, version)
            urls = meta.get("urls") or []
            sdist = _pick_url(urls, "sdist")
            wheel = _pick_url(urls, "bdist_wheel")

            tasks = []
            targets: list[tuple[dict, str, Path]] = []
            for entry, kind in ((sdist, "sdist"), (wheel, "wheel")):
                if entry is None:
                    continue
                dest = work / entry["filename"]
                tasks.append(_download_url(client, entry["url"], dest))
                targets.append((entry, kind, dest))
            if not tasks:
                raise NoFilesError(f"no_urls_for {name} {version}")
            await asyncio.gather(*tasks)

        results: list[ArchivePath] = []
        archive_details: list[str] = []
        total_bytes = 0
        for entry, kind, dest in targets:
            data = dest.read_bytes()
            expected = (entry.get("digests") or {}).get("sha256")
            actual = hashlib.sha256(data).hexdigest()
            if expected and expected.lower() != actual.lower():
                raise IntegrityError(
                    f"sha256_mismatch {name} {version} {kind} expected={expected} actual={actual}"
                )
            results.append(ArchivePath(path=dest, kind=kind, sha256=actual))
            size_mb = len(data) / (1024 * 1024)
            total_bytes += len(data)
            archive_details.append(f"{kind}:{entry['filename']}({size_mb:.1f}MB)")
        log.info(
            "downloaded", ecosystem="pypi", name=name, version=version,
            archives=archive_details,
            total_mb=round(total_bytes / (1024 * 1024), 1),
        )
        return FetchResult(archives=results, metadata=meta.get("info") or {})
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
