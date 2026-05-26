# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io watchlist -- top crates by downloads."""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from sqlalchemy import select, delete

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Watchlist
from pkgsentry.util.user_agent import user_agent

log = get_logger("crates.watchlist")

ECOSYSTEM = "crates"


def is_watchlist(session, name: str) -> Optional[int]:
    row = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM, Watchlist.name == name)
    ).first()
    return row.rank if row else None
USER_AGENT = user_agent()
API_BASE = "https://crates.io/api/v1"
TOP_N = 10000
PER_PAGE = 100

# Rate limit: 1 req/s to crates.io API
_api_semaphore = asyncio.Semaphore(1)


def parse_crates_page(data: dict) -> list[tuple[str, int]]:
    """Extract (name, downloads) from a crates.io API response page."""
    return [
        (c["name"], c.get("downloads", 0))
        for c in data.get("crates", [])
    ]


async def refresh_watchlist() -> int:
    """Fetch top crates by downloads and update the Watchlist table.
    Returns count of crates written."""
    all_crates: list[tuple[str, int]] = []
    page = 1

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=30.0,
    ) as client:
        while len(all_crates) < TOP_N:
            async with _api_semaphore:
                try:
                    resp = await client.get(
                        f"{API_BASE}/crates",
                        params={"sort": "downloads", "per_page": PER_PAGE, "page": page},
                    )
                    resp.raise_for_status()
                except Exception as e:
                    log.warning("watchlist_fetch_error", page=page, error=str(e))
                    break
                await asyncio.sleep(1.0)  # 1 req/s rate limit

            data = resp.json()
            batch = parse_crates_page(data)
            if not batch:
                break
            all_crates.extend(batch)
            page += 1

    if not all_crates:
        log.warning("watchlist_empty")
        return 0

    with sess.session_scope() as s:
        s.execute(delete(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM))
        for rank, (name, downloads) in enumerate(all_crates[:TOP_N], start=1):
            s.add(Watchlist(
                ecosystem=ECOSYSTEM,
                name=name,
                rank=rank,
                downloads_last_30d=downloads,
            ))

    log.info("crates_watchlist_refreshed", count=len(all_crates[:TOP_N]))
    return len(all_crates[:TOP_N])


async def poll_watchlist_releases() -> int:
    """Check latest versions of watchlist crates and enqueue new ones.
    Returns count enqueued."""
    with sess.session_scope() as s:
        rows = s.scalars(
            select(Watchlist)
            .where(Watchlist.ecosystem == ECOSYSTEM)
            .order_by(Watchlist.rank.asc())
        ).all()

    if not rows:
        return 0

    count = 0
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=30.0,
    ) as client:
        for wl in rows:
            async with _api_semaphore:
                try:
                    resp = await client.get(f"{API_BASE}/crates/{wl.name}")
                    resp.raise_for_status()
                except Exception as e:
                    continue
                await asyncio.sleep(1.0)

            data = resp.json()
            crate = data.get("crate", {})
            newest = crate.get("newest_version")
            if newest:
                with sess.session_scope() as s:
                    try:
                        enqueue(s, ecosystem=ECOSYSTEM, name=wl.name,
                                version=newest, priority="high")
                        count += 1
                    except Exception:
                        pass  # duplicate

    if count:
        log.info("crates_watchlist_releases", enqueued=count)
    return count


async def seed_missing_watchlist() -> int:
    """Re-seed watchlist crates that have no scan_queue entry yet.

    Defensive gap-healing for the watchlist baseline: enqueues at HIGH
    priority any watchlist crate with no scan_queue row (regardless of
    status). Runs on boot when the Watchlist table is populated.
    """
    from pkgsentry.store.models import ScanQueue

    with sess.session_scope() as s:
        already = set(
            s.scalars(
                select(ScanQueue.name).where(ScanQueue.ecosystem == ECOSYSTEM)
            ).all()
        )
        wl_names = [
            r.name for r in s.scalars(
                select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM)
            ).all()
        ]

    missing = [n for n in wl_names if n not in already]
    if not missing:
        return 0

    log.info("crates_seed_missing_start", missing=len(missing), total=len(wl_names))

    enq = 0
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=30.0,
    ) as client:
        for name in missing:
            async with _api_semaphore:
                try:
                    resp = await client.get(f"{API_BASE}/crates/{name}")
                    resp.raise_for_status()
                except Exception:
                    await asyncio.sleep(1.0)
                    continue
                await asyncio.sleep(1.0)

            data = resp.json()
            crate = data.get("crate", {})
            newest = crate.get("newest_version")
            if not newest:
                continue
            try:
                with sess.session_scope() as s:
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=name,
                                  version=newest, priority="high")
                    if row is not None and row.status == "pending":
                        enq += 1
            except Exception as e:
                log.warning("crates_seed_missing_enqueue_failed",
                            name=name, error=str(e))

    log.info("crates_seed_missing_done", enqueued=enq, missing=len(missing))
    return enq
