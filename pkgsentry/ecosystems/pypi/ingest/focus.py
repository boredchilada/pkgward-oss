# SPDX-License-Identifier: AGPL-3.0-or-later
"""PyPI focus poller — enqueue the latest release of every focus package.

Mirrors ``poll_watchlist_releases`` but iterates ``FocusList`` instead of
``Watchlist``. Runs in both additive and exclusive modes so new releases of an
operator's dependencies are caught beyond the live feeds.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from sqlalchemy import select

from pkgsentry.ecosystems.pypi.ingest.watchlist import _fetch_latest_version
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import FocusList
from pkgsentry.util.user_agent import user_agent

log = get_logger("pypi.focus")
ECOSYSTEM = "pypi"


async def poll_focus_releases(concurrency: int = 20) -> int:
    """Enqueue the latest version of every pypi focus package at high priority."""
    with sess.session_scope() as s:
        names = [
            r.name
            for r in s.scalars(
                select(FocusList).where(FocusList.ecosystem == ECOSYSTEM)
            ).all()
        ]
    if not names:
        return 0

    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, Optional[str]]] = []

    async def _fetch_one(client: httpx.AsyncClient, name: str):
        async with sem:
            results.append((name, await _fetch_latest_version(client, name)))

    async with httpx.AsyncClient(
        headers={"User-Agent": user_agent()}, follow_redirects=True,
    ) as client:
        await asyncio.gather(*[_fetch_one(client, n) for n in names])

    enq = 0
    batch = [(n, v) for n, v in results if v]
    for i in range(0, len(batch), 100):
        with sess.session_scope() as s:
            for name, v in batch[i:i + 100]:
                row = enqueue(s, ecosystem=ECOSYSTEM, name=name, version=v, priority="high")
                if row is not None and row.status == "pending":
                    enq += 1
    log.info("focus_poll", enqueued=enq, candidates=len(names))
    return enq
