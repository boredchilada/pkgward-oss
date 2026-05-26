# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import tempfile
import time
from pathlib import Path

import httpx

from pkgsentry.adapter import ArchivePath, FetchResult, NoFilesError
from pkgsentry.logging_setup import get_logger
from pkgsentry.util.user_agent import user_agent

log = get_logger("gomod.fetch")

USER_AGENT = user_agent()
PROXY_BASE = "https://proxy.golang.org"
WORK_ROOT = Path(tempfile.gettempdir()) / "pkgsentry_gomod"


def case_encode(path: str) -> str:
    """Apply Go module case encoding: uppercase letters become '!' + lowercase.

    Required by the GOPROXY protocol for constructing download URLs.
    e.g. 'github.com/BurntSushi/toml' → 'github.com/!burnt!sushi/toml'
    """
    out = []
    for ch in path:
        if ch.isupper():
            out.append("!")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def _build_zip_url(module_path: str, version: str) -> str:
    encoded = case_encode(module_path)
    return f"{PROXY_BASE}/{encoded}/@v/{version}.zip"


def _build_info_url(module_path: str, version: str) -> str:
    encoded = case_encode(module_path)
    return f"{PROXY_BASE}/{encoded}/@v/{version}.info"


async def download_module(name: str, version: str) -> FetchResult:
    """Download a Go module zip from proxy.golang.org."""
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(dir=WORK_ROOT, prefix=f"{name.replace('/', '_')}-{version}-"))
    work_dir.chmod(0o755)

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        # Download the module zip
        zip_url = _build_zip_url(name, version)
        resp = await client.get(zip_url, timeout=120.0)

        if resp.status_code == 404:
            raise NoFilesError(f"module not found: {name}@{version}")
        if resp.status_code == 410:
            raise NoFilesError(f"module gone (yanked): {name}@{version}")
        resp.raise_for_status()

        safe_name = name.replace("/", "_")
        dest = work_dir / f"{safe_name}-{version}.zip"
        dest.write_bytes(resp.content)
        sha256 = hashlib.sha256(resp.content).hexdigest()

        # Fetch metadata from .info endpoint
        metadata: dict = {}
        try:
            info_resp = await client.get(_build_info_url(name, version), timeout=15.0)
            if info_resp.status_code == 200:
                info = info_resp.json()
                metadata = {
                    "home_page": f"https://pkg.go.dev/{name}",
                    "summary": "",
                    "_raw_info": info,
                }
        except Exception:
            pass

    archive = ArchivePath(path=dest, kind="gomod_zip", sha256=sha256)
    size_mb = round(dest.stat().st_size / (1024 * 1024), 1)
    log.info("downloaded", ecosystem="gomod", name=name, version=version,
             total_mb=size_mb, archives=[f"gomod_zip:{dest.name}({size_mb}MB)"])
    return FetchResult(archives=[archive], metadata=metadata)


def sweep_orphans(max_age_seconds: float = 3600.0) -> int:
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
