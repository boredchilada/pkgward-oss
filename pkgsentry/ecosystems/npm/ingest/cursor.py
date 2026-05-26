# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm registry discovery via the CouchDB ``_changes`` replication feed.

``https://replicate.npmjs.com/_changes?since={seq}&limit=N`` streams a row per
package change carrying ``seq`` + package ``id`` (name) — but **not** the
version. So, unlike the PyPI/gomod feeds, we gate on the name first and only
then resolve ``dist-tags.latest`` (one registry call per gated package) to get
a concrete version for proper queue dedup.

The ``seq`` is stored in ``ScanCursor.last_serial`` and treated as an opaque,
forward-only token (npm's historical non-monotonic reset is behind us; we only
ever poll forward from the last seq we saw).
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from sqlalchemy import func, select

from pkgsentry.focus import focus_exclusive, gate_decision, load_focus_names, on_focus
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Package, ScanCursor, ScanQueue
from pkgsentry.util.user_agent import user_agent
from pkgsentry.ecosystems.npm.ingest.watchlist import is_watchlist

log = get_logger("npm.cursor")

ECOSYSTEM = "npm"
USER_AGENT = user_agent()
REPLICATE_BASE = "https://replicate.npmjs.com"
REGISTRY_BASE = "https://registry.npmjs.org"
DEFAULT_LIMIT = 1000
# Bound work per 60s poll; catch-up spreads across successive polls.
MAX_PAGES_PER_POLL = 5
_resolve_limiter = asyncio.Semaphore(8)


def _seq_to_int(seq) -> int:
    """Coerce a CouchDB seq to int. Handles ``N`` and composite ``N-hash``."""
    if isinstance(seq, int):
        return seq
    s = str(seq)
    head = s.split("-", 1)[0]
    try:
        return int(head)
    except ValueError:
        return 0


def get_last_seq() -> Optional[int]:
    """Return the stored seq cursor, or None when unset (needs bootstrap)."""
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        return row.last_serial if row is not None else None


def set_last_seq(seq: int) -> None:
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        if row is None:
            s.add(ScanCursor(ecosystem=ECOSYSTEM, last_serial=seq))
        else:
            row.last_serial = seq


async def _current_update_seq(client: httpx.AsyncClient) -> int:
    """Fetch the registry's current ``update_seq`` to bootstrap the cursor."""
    resp = await client.get(f"{REPLICATE_BASE}/", timeout=30.0)
    resp.raise_for_status()
    return _seq_to_int(resp.json().get("update_seq", 0))


async def _fetch_changes(client: httpx.AsyncClient, since: int, limit: int = DEFAULT_LIMIT) -> dict:
    params = {"since": str(since), "limit": str(limit)}
    try:
        resp = await client.get(f"{REPLICATE_BASE}/_changes", params=params, timeout=60.0)
        resp.raise_for_status()
    except Exception as e:
        log.warning("changes_fetch_failed", since=since, error=str(e))
        return {}
    try:
        return resp.json()
    except ValueError:
        log.warning("changes_parse_failed", since=since)
        return {}


async def _resolve_latest(client: httpx.AsyncClient, name: str) -> Optional[str]:
    """Resolve a package's current latest version via /{pkg}/latest."""
    from pkgsentry.ecosystems.npm.fetch.download import _encode_name, get_with_retry
    async with _resolve_limiter:
        try:
            resp = await get_with_retry(client, f"{REGISTRY_BASE}/{_encode_name(name)}/latest", timeout=20.0)
            if resp.status_code != 200:
                return None
            v = resp.json().get("version")
            return str(v) if v else None
        except Exception:
            return None


def _gate_page(results: list[dict], gated: dict[str, str], exclusive: bool) -> tuple[int, int]:
    """Apply ingest gates to one page of change rows, merging into ``gated``.

    ``gated`` maps name -> priority (deduped within the poll). Brand-new probes
    dedup against Package + ScanQueue (case-insensitive) and the in-flight
    ``gated`` set. Returns (newly_gated, skipped)."""
    newly = 0
    skipped = 0
    with sess.session_scope() as s:
        focus_names = load_focus_names(s, ECOSYSTEM)
        for row in results:
            name = row.get("id", "")
            if not name or name.startswith("_design/") or row.get("deleted"):
                continue
            if name in gated:
                continue
            on_foc = on_focus(name, focus_names, ECOSYSTEM)
            if exclusive:
                if on_foc:
                    gated[name] = "high"
                    newly += 1
                else:
                    skipped += 1
                continue
            on_wl = is_watchlist(s, name) is not None
            brand_new = False
            if not on_foc and not on_wl:
                name_l = name.lower()
                known = (
                    s.scalars(
                        select(Package.id).where(
                            Package.ecosystem == ECOSYSTEM,
                            func.lower(Package.name) == name_l,
                        ).limit(1)
                    ).first() is not None
                    or s.scalars(
                        select(ScanQueue.id).where(
                            ScanQueue.ecosystem == ECOSYSTEM,
                            func.lower(ScanQueue.name) == name_l,
                        ).limit(1)
                    ).first() is not None
                )
                brand_new = not known
            pri = gate_decision(
                on_focus=on_foc, on_watchlist=on_wl,
                brand_new=brand_new, exclusive=exclusive,
            )
            if pri is None:
                skipped += 1
                continue
            gated[name] = pri
            newly += 1
    return newly, skipped


async def poll_changes_once() -> int:
    """Poll the npm changes feed, resolve versions for gated packages, enqueue.

    Returns the count enqueued."""
    exclusive = focus_exclusive()

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        cursor = get_last_seq()
        if cursor is None:
            try:
                cursor = await _current_update_seq(client)
            except Exception as e:
                log.warning("bootstrap_failed", error=str(e))
                return 0
            set_last_seq(cursor)
            log.info("cursor_bootstrapped", since=cursor)
            return 0

        gated: dict[str, str] = {}
        total_skipped = 0
        since = cursor
        max_seq = cursor
        pages = 0

        while pages < MAX_PAGES_PER_POLL:
            page = await _fetch_changes(client, since)
            results = page.get("results") or []
            if not results:
                break
            last_seq = _seq_to_int(page.get("last_seq", since))
            if last_seq > max_seq:
                max_seq = last_seq
            _, skipped = _gate_page(results, gated, exclusive)
            total_skipped += skipped
            pages += 1
            since = last_seq
            if len(results) < DEFAULT_LIMIT:
                break

        # Resolve concrete versions for gated packages concurrently.
        names = list(gated.keys())
        resolved: list[tuple[str, str]] = []
        if names:
            async def _one(n: str):
                v = await _resolve_latest(client, n)
                if v:
                    resolved.append((n, v))
            await asyncio.gather(*[_one(n) for n in names])

    enq = 0
    if resolved:
        with sess.session_scope() as s:
            for name, version in resolved:
                row = enqueue(s, ecosystem=ECOSYSTEM, name=name,
                              version=version, priority=gated[name])
                if row is not None and row.status == "pending":
                    enq += 1

    if max_seq > cursor:
        set_last_seq(max_seq)

    if enq or total_skipped:
        log.info("changes_poll", enqueued=enq, gated=len(gated),
                 unresolved=len(gated) - len(resolved), skipped=total_skipped,
                 new_seq=max_seq, exclusive=exclusive)
    return enq


def pull_since_beginning(days: int) -> int:
    """Backfill is not supported for npm.

    The CouchDB ``_changes`` feed is keyed by an opaque seq, not a timestamp, so
    a ``days`` window has no mapping. Discovery starts from the current seq at
    first boot; there is no time-addressable history to replay.
    """
    log.info("backfill_unsupported", ecosystem=ECOSYSTEM, days=days)
    return 0
