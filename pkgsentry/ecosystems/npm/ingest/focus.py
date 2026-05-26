# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm focus poller — enqueue the latest release of every focus package.

Mirrors gomod/crates focus pollers but resolves npm ``dist-tags.latest``.
"""
from __future__ import annotations

import asyncio

import httpx
from sqlalchemy import select

from pkgsentry.ecosystems.npm.ingest.watchlist import REGISTRY_BASE, USER_AGENT, _resolve_latest
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import FocusList

log = get_logger("npm.focus")
ECOSYSTEM = "npm"


async def poll_focus_releases(concurrency: int = 10) -> int:
    """Enqueue the newest version of every npm focus package at high priority."""
    with sess.session_scope() as s:
        names = [
            r.name for r in s.scalars(
                select(FocusList).where(FocusList.ecosystem == ECOSYSTEM)
            ).all()
        ]
    if not names:
        return 0

    sem = asyncio.Semaphore(concurrency)
    resolved: list[tuple[str, str]] = []
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        async def _one(name: str):
            async with sem:
                v = await _resolve_latest(client, name)
            if v:
                resolved.append((name, v))
        await asyncio.gather(*[_one(n) for n in names])

    count = 0
    if resolved:
        with sess.session_scope() as s:
            for name, v in resolved:
                try:
                    enqueue(s, ecosystem=ECOSYSTEM, name=name, version=v, priority="high")
                    count += 1
                except Exception:
                    pass
    if count:
        log.info("focus_poll", enqueued=count, candidates=len(names))
    return count
