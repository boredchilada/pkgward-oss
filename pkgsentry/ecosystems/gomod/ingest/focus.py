# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go modules focus poller — enqueue the latest release of every focus module.

Mirrors ``seed_watchlist_queue`` but iterates ``FocusList``, reusing
``_resolve_latest_canonical`` (proxy.golang.org/@latest, handles /vN paths).
The resolved canonical path is enqueued so the worker can fetch it; the
FocusList row is left as the operator typed it.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from sqlalchemy import select

from pkgsentry.ecosystems.gomod.ingest.watchlist import (
    USER_AGENT,
    _resolve_latest_canonical,
)
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import FocusList

log = get_logger("gomod.focus")
ECOSYSTEM = "gomod"


async def poll_focus_releases(concurrency: int = 20) -> int:
    """Enqueue the latest version of every gomod focus module at high priority."""
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
    results: list[tuple[Optional[str], Optional[str]]] = []

    async def _resolve(client: httpx.AsyncClient, mod_path: str):
        async with sem:
            canonical, version, _reason = await _resolve_latest_canonical(client, mod_path)
            results.append((canonical, version))

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, follow_redirects=True,
    ) as client:
        await asyncio.gather(*[_resolve(client, n) for n in names])

    enq = 0
    successes = [(c, v) for c, v in results if c and v]
    for i in range(0, len(successes), 100):
        with sess.session_scope() as s:
            for canonical, version in successes[i:i + 100]:
                row = enqueue(s, ecosystem=ECOSYSTEM, name=canonical, version=version, priority="high")
                if row is not None and row.status == "pending":
                    enq += 1
    log.info("focus_poll", enqueued=enq, candidates=len(names))
    return enq
