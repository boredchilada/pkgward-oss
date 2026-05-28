# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Watchlist
from pkgsentry.util.user_agent import user_agent
from pkgsentry.watchlist_auto import AUTO_MALICIOUS_RANK

log = get_logger("ingest.watchlist")
ECOSYSTEM = "pypi"

# hugovk/top-pypi-packages snapshot (no auth required).
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


def is_watchlist(session: Session, name: str, ecosystem: str = ECOSYSTEM) -> Optional[int]:
    row = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem, Watchlist.name == name)
    ).first()
    return row.rank if row else None


async def refresh_watchlist(top_n: int = 10000) -> int:
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": user_agent()},
            follow_redirects=True,
        ) as client:
            r = await client.get(TOP_URL, timeout=30.0)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        log.warning("watchlist_fetch_failed", error=str(e))
        return 0

    rows = data.get("rows") or data.get("packages") or []
    now = datetime.now(timezone.utc)
    written = 0
    with sess.session_scope() as s:
        # Wipe and reinsert — simpler than diffing.
        # Skip auto-added confirmed-malicious rows so popularity refresh doesn't
        # evict them (they belong to the auto-watchlist gate, not this top-N).
        existing = {
            w.name: w for w in s.scalars(
                select(Watchlist).where(
                    Watchlist.ecosystem == ECOSYSTEM,
                    Watchlist.rank != AUTO_MALICIOUS_RANK,
                )
            ).all()
        }
        seen: set[str] = set()
        for idx, entry in enumerate(rows[:top_n], start=1):
            name = entry.get("project") or entry.get("name")
            dl = int(entry.get("download_count") or entry.get("downloads", 0) or 0)
            if not name:
                continue
            seen.add(name)
            row = existing.get(name)
            if row is None:
                row = Watchlist(
                    ecosystem=ECOSYSTEM, name=name, rank=idx,
                    downloads_last_30d=dl, refreshed_at=now,
                )
                s.add(row)
            else:
                row.rank = idx
                row.downloads_last_30d = dl
                row.refreshed_at = now
            written += 1
        # Drop entries no longer in top-N.
        for name, row in existing.items():
            if name not in seen:
                s.delete(row)
    log.info("watchlist_refreshed", count=written)
    return written


async def _fetch_latest_version(client: httpx.AsyncClient, name: str) -> Optional[str]:
    try:
        r = await client.get(f"https://pypi.org/pypi/{name}/json", timeout=15.0)
        if r.status_code != 200:
            return None
        info = r.json().get("info") or {}
        v = info.get("version")
        return str(v) if v else None
    except Exception as e:
        log.warning("watchlist_pkg_fetch_failed", name=name, error=str(e))
        return None


async def poll_watchlist_releases(limit: Optional[int] = None, concurrency: int = 20) -> int:
    """Poll pypi.org/pypi/<name>/json for each watchlist package; enqueue latest version high-priority."""
    with sess.session_scope() as s:
        q = select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM).order_by(Watchlist.rank.asc())
        if limit is not None:
            q = q.limit(limit)
        names = [w.name for w in s.scalars(q).all()]

    enq = 0
    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, Optional[str]]] = []

    async def _fetch_one(client: httpx.AsyncClient, name: str):
        async with sem:
            v = await _fetch_latest_version(client, name)
            results.append((name, v))

    async with httpx.AsyncClient(
        headers={"User-Agent": user_agent()},
        follow_redirects=True,
    ) as client:
        tasks = [_fetch_one(client, n) for n in names]
        await asyncio.gather(*tasks)

    batch: list[tuple[str, str]] = [(n, v) for n, v in results if v]
    for i in range(0, len(batch), 100):
        chunk = batch[i:i + 100]
        for attempt in range(5):
            try:
                with sess.session_scope() as s:
                    for name, v in chunk:
                        row = enqueue(s, ecosystem=ECOSYSTEM, name=name, version=v, priority="high")
                        if row is not None and row.status == "pending":
                            enq += 1
                break
            except Exception as e:
                if attempt < 4:
                    await asyncio.sleep(2 * (attempt + 1))
                else:
                    log.warning("watchlist_enqueue_batch_failed", offset=i, error=str(e))
    log.info("watchlist_poll", enqueued=enq, candidates=len(names))
    return enq
