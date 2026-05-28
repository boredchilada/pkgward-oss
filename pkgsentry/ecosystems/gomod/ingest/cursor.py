# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select, func

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Package, ScanCursor, ScanQueue
from pkgsentry.util.user_agent import user_agent
from pkgsentry.ecosystems.gomod.ingest.watchlist import is_watchlist

log = get_logger("gomod.cursor")

ECOSYSTEM = "gomod"
INDEX_URL = "https://index.golang.org/index"
USER_AGENT = user_agent()
DEFAULT_LIMIT = 2000

# Go pseudo-versions in all three forms end in <14-digit UTC timestamp>-<12-char
# commit hash> (optionally +incompatible): v0.0.0-…, vX.Y.Z-0.…, vX.Y.Z-pre.0.….
# The old `^v0\.0\.0-…$` anchor only caught the first form, so pseudo-versions of
# repos with a prior tag (most popular modules) leaked past the skip gate.
_PSEUDO_RE = re.compile(r"\d{14}-[0-9a-f]{12}(\+incompatible)?$")


def _is_pseudo_version(version: str) -> bool:
    return bool(_PSEUDO_RE.search(version))


def _ts_to_cursor(iso: str) -> int:
    """RFC3339 timestamp → epoch microseconds (int)."""
    ts = iso.rstrip("Z")
    if "+" not in ts and "-" not in ts[11:]:
        ts += "+00:00"
    dt = datetime.fromisoformat(ts)
    return int(dt.timestamp() * 1_000_000)


def _cursor_to_since(cursor: int) -> str:
    """Epoch microseconds → RFC3339 string for the ?since= parameter."""
    dt = datetime.fromtimestamp(cursor / 1_000_000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_last_cursor() -> int:
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        if row is None:
            now_us = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
            row = ScanCursor(ecosystem=ECOSYSTEM, last_serial=now_us)
            s.add(row)
            s.flush()
            log.info("cursor_bootstrapped", since=_cursor_to_since(now_us))
        return row.last_serial


def set_last_cursor(cursor: int) -> None:
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        if row is None:
            row = ScanCursor(ecosystem=ECOSYSTEM, last_serial=cursor)
            s.add(row)
        else:
            row.last_serial = cursor


def _parse_ndjson(text: str) -> list[dict]:
    """Parse newline-delimited JSON from index.golang.org."""
    import json
    entries = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("ndjson_parse_error", line=line[:200])
    return entries


async def _fetch_page(since: str, limit: int = DEFAULT_LIMIT) -> list[dict]:
    """Fetch one page from the Go module index."""
    params = {"since": since, "limit": str(limit)}
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await client.get(INDEX_URL, params=params, timeout=30.0)
            resp.raise_for_status()
    except Exception as e:
        log.warning("index_fetch_failed", error=str(e))
        return []
    return _parse_ndjson(resp.text)


async def poll_index_once() -> int:
    """Poll the Go module index, enqueue watchlist + brand-new modules only.

    Gate logic (mirrors PyPI cursor):
    - On watchlist → enqueue at high priority
    - Not on watchlist, not in Package table → brand-new, enqueue at normal
    - Everything else → skip
    """
    scan_pseudo = os.environ.get("GOMOD_SCAN_PSEUDO", "0") == "1"
    cursor = get_last_cursor()
    since = _cursor_to_since(cursor)

    total_enqueued = 0
    total_enqueued_new = 0
    total_skipped = 0
    skipped_gate = 0
    max_cursor = cursor
    from pkgsentry.focus import load_focus_names, on_focus, focus_exclusive
    exclusive = focus_exclusive()

    while True:
        entries = await _fetch_page(since)
        if not entries:
            break

        with sess.session_scope() as s:
            focus_names = load_focus_names(s, ECOSYSTEM)  # preloaded once per page
            for entry in entries:
                path = entry.get("Path", "")
                version = entry.get("Version", "")
                timestamp = entry.get("Timestamp", "")
                if not path or not version or not timestamp:
                    continue

                entry_cursor = _ts_to_cursor(timestamp)
                if entry_cursor > max_cursor:
                    max_cursor = entry_cursor

                if not scan_pseudo and _is_pseudo_version(version):
                    total_skipped += 1
                    continue

                on_foc = on_focus(path, focus_names, ECOSYSTEM)

                if exclusive:
                    # Only focus modules; skip watchlist + the expensive
                    # brand-new probe entirely.
                    if not on_foc:
                        skipped_gate += 1
                        continue
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=path,
                                  version=version, priority="high")
                    if row is not None:
                        total_enqueued += 1
                    continue

                on_watchlist = is_watchlist(s, path) is not None

                if on_foc or on_watchlist:
                    # Focus or watchlist: enqueue every version (supply-chain monitoring).
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=path,
                                  version=version, priority="high")
                    if row is not None:
                        total_enqueued += 1
                else:
                    # Brand-new gate: enqueue only the first version we ever see
                    # for this module path. Dedupe against BOTH Package (post-scan
                    # marker) and ScanQueue (any status). Comparison is
                    # case-insensitive: GitHub paths are case-insensitive at the
                    # platform level even though the Go proxy preserves casing
                    # via !x encoding, so different casings represent the same
                    # repo and would otherwise look like distinct brand-new modules.
                    path_l = path.lower()
                    already_known = (
                        s.scalars(
                            select(Package).where(
                                Package.ecosystem == ECOSYSTEM,
                                func.lower(Package.name) == path_l,
                            )
                        ).first()
                        is not None
                        or s.scalars(
                            select(ScanQueue.id).where(
                                ScanQueue.ecosystem == ECOSYSTEM,
                                func.lower(ScanQueue.name) == path_l,
                            ).limit(1)
                        ).first()
                        is not None
                    )
                    if already_known:
                        skipped_gate += 1
                        continue
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=path,
                                  version=version, priority="normal")
                    if row is not None:
                        total_enqueued += 1
                        total_enqueued_new += 1

        if len(entries) < DEFAULT_LIMIT:
            break
        since = _cursor_to_since(max_cursor)

    if max_cursor > cursor:
        set_last_cursor(max_cursor)

    if total_enqueued or total_skipped or skipped_gate:
        log.info(
            "index_poll",
            enqueued=total_enqueued,
            enqueued_new=total_enqueued_new,
            skipped_pseudo=total_skipped,
            skipped_gate=skipped_gate,
            new_cursor=_cursor_to_since(max_cursor),
        )
    return total_enqueued


def pull_since_beginning(days: int) -> int:
    """Backfill: page through the index starting from `now - days`."""
    import asyncio
    from datetime import timedelta

    start = datetime.now(timezone.utc) - timedelta(days=days)
    start_cursor = int(start.timestamp() * 1_000_000)
    since = _cursor_to_since(start_cursor)
    scan_pseudo = os.environ.get("GOMOD_SCAN_PSEUDO", "0") == "1"

    total = 0
    max_cursor = start_cursor

    async def _drain():
        nonlocal total, max_cursor, since
        while True:
            entries = await _fetch_page(since)
            if not entries:
                break
            with sess.session_scope() as s:
                for entry in entries:
                    path = entry.get("Path", "")
                    version = entry.get("Version", "")
                    timestamp = entry.get("Timestamp", "")
                    if not path or not version or not timestamp:
                        continue
                    entry_cursor = _ts_to_cursor(timestamp)
                    if entry_cursor > max_cursor:
                        max_cursor = entry_cursor
                    if not scan_pseudo and _is_pseudo_version(version):
                        continue
                    on_watchlist = is_watchlist(s, path) is not None
                    if on_watchlist:
                        if enqueue(s, ecosystem=ECOSYSTEM, name=path,
                                   version=version, priority="high") is not None:
                            total += 1
                    else:
                        path_l = path.lower()
                        already_known = (
                            s.scalars(
                                select(Package).where(
                                    Package.ecosystem == ECOSYSTEM,
                                    func.lower(Package.name) == path_l,
                                )
                            ).first()
                            is not None
                            or s.scalars(
                                select(ScanQueue.id).where(
                                    ScanQueue.ecosystem == ECOSYSTEM,
                                    func.lower(ScanQueue.name) == path_l,
                                ).limit(1)
                            ).first()
                            is not None
                        )
                        if already_known:
                            continue
                        if enqueue(s, ecosystem=ECOSYSTEM, name=path,
                                   version=version, priority="normal") is not None:
                            total += 1
            if len(entries) < DEFAULT_LIMIT:
                break
            since = _cursor_to_since(max_cursor)

    asyncio.run(_drain())

    if max_cursor > start_cursor:
        set_last_cursor(max_cursor)
    log.info("backfill_done", enqueued=total, days=days)
    return total
