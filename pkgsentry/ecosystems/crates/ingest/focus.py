# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates focus poller — enqueue the latest release of every focus crate.

Mirrors ``poll_watchlist_releases`` (crates) but iterates ``FocusList``.
Respects the 1 req/s crates.io API semaphore.
"""
from __future__ import annotations

import asyncio

import httpx
from sqlalchemy import select

from pkgsentry.ecosystems.crates.ingest.watchlist import (
    API_BASE,
    USER_AGENT,
    _api_semaphore,
)
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import FocusList

log = get_logger("crates.focus")
ECOSYSTEM = "crates"


async def poll_focus_releases() -> int:
    """Enqueue the newest version of every crates focus package at high priority."""
    with sess.session_scope() as s:
        names = [
            r.name
            for r in s.scalars(
                select(FocusList).where(FocusList.ecosystem == ECOSYSTEM)
            ).all()
        ]
    if not names:
        return 0

    count = 0
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, timeout=30.0) as client:
        for name in names:
            async with _api_semaphore:
                try:
                    resp = await client.get(f"{API_BASE}/crates/{name}")
                    resp.raise_for_status()
                except Exception:
                    continue
                await asyncio.sleep(1.0)
            newest = (resp.json().get("crate") or {}).get("newest_version")
            if newest:
                with sess.session_scope() as s:
                    try:
                        enqueue(s, ecosystem=ECOSYSTEM, name=name, version=newest, priority="high")
                        count += 1
                    except Exception:
                        pass  # duplicate
    if count:
        log.info("focus_poll", enqueued=count, candidates=len(names))
    return count
