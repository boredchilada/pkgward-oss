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
import os
from collections import defaultdict
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
from pkgsentry import scope_watchlist

log = get_logger("npm.cursor")

ECOSYSTEM = "npm"
USER_AGENT = user_agent()
REPLICATE_BASE = "https://replicate.npmjs.com"
REGISTRY_BASE = "https://registry.npmjs.org"
DEFAULT_LIMIT = 1000
# Bound work per 60s poll; catch-up spreads across successive polls.
MAX_PAGES_PER_POLL = 5
_resolve_limiter = asyncio.Semaphore(8)

# A gated brand-new package whose version we can't resolve this poll (transient
# 429/5xx/timeout) must NOT be left behind the forward-only cursor — it would
# never re-appear in the feed and would be silently un-scanned. We hold the
# cursor just before such a package's seq so the next poll re-fetches and
# retries it. A genuinely-deleted package (permanent 404) would otherwise wedge
# the cursor forever, so each name is retried at most NPM_RESOLVE_MAX_ATTEMPTS
# times (in-process counter, resets on restart — mirrors watchlist_auto) and
# then given up with a warning (a visible event instead of a silent drop).
NPM_RESOLVE_MAX_ATTEMPTS = int(os.environ.get("NPM_RESOLVE_MAX_ATTEMPTS", "5"))
_resolve_attempts: dict[str, int] = defaultdict(int)
_RESOLVE_ATTEMPTS_CAP = 50_000


def _reset_resolve_attempts_for_tests() -> None:
    _resolve_attempts.clear()


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


# Install-time lifecycle hooks: the on-`npm install` code-execution surface and
# the trigger for credential-stealer campaigns (e.g. the oob.moika.tech 99.99.99
# dependency-confusion campaign, May 2026). A brand-new package declaring one of
# these is scanned at high priority so it doesn't sit days deep in the npm
# backlog while a live campaign exfiltrates secrets.
_INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def _has_install_hook(scripts) -> bool:
    return isinstance(scripts, dict) and any(h in scripts for h in _INSTALL_HOOKS)


def _is_suspicious_version(version: str) -> bool:
    """Dependency-confusion version-inflation tell. Attackers publish absurdly
    high / patterned versions to win semver resolution against an internal
    package (observed: 99.99.99, 9.9.9, 9.9.10, 10.10.10, 11.11.11). This is a
    *secondary* priority booster — the install hook is the primary signal — so a
    looser match is fine: a false promote only scans a benign package sooner."""
    core = version.strip().lstrip("v").split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return False
    nums = [int(p) for p in parts]
    if all(set(p) == {"9"} for p in parts):       # 9.9.9, 99.99.99
        return True
    if len(set(nums)) == 1 and nums[0] >= 9:      # 10.10.10, 11.11.11
        return True
    if nums[0] >= 99:                             # absurd major inflation
        return True
    return False


async def _resolve_latest(client: httpx.AsyncClient, name: str) -> Optional[tuple[str, bool]]:
    """Resolve a package's latest version via /{pkg}/latest, returning
    ``(version, has_install_hook)``. The same manifest carries ``scripts``, so
    detecting an install hook here is free (no extra request). None on failure."""
    from pkgsentry.ecosystems.npm.fetch.download import _encode_name, get_with_retry
    async with _resolve_limiter:
        try:
            resp = await get_with_retry(client, f"{REGISTRY_BASE}/{_encode_name(name)}/latest", timeout=20.0)
            if resp.status_code != 200:
                return None
            data = resp.json()
            v = data.get("version")
            return (str(v), _has_install_hook(data.get("scripts"))) if v else None
        except Exception:
            return None


def _gate_page(
    results: list[dict], gated: dict[str, str], exclusive: bool,
    gated_seq: Optional[dict[str, int]] = None,
) -> tuple[int, int]:
    """Apply ingest gates to one page of change rows, merging into ``gated``.

    ``gated`` maps name -> priority (deduped within the poll). Brand-new probes
    dedup against Package + ScanQueue (case-insensitive) and the in-flight
    ``gated`` set. ``gated_seq`` (when provided) records the change-feed ``seq``
    of the row where each name was first gated, so the caller can hold the
    cursor before any name it later fails to resolve. Returns
    (newly_gated, skipped)."""
    newly = 0
    skipped = 0
    with sess.session_scope() as s:
        focus_names = load_focus_names(s, ECOSYSTEM)
        watch_scopes = scope_watchlist.load_scopes(s, ECOSYSTEM)
        for row in results:
            name = row.get("id", "")
            if not name or name.startswith("_design/") or row.get("deleted"):
                continue
            if name in gated:
                continue
            row_seq = _seq_to_int(row.get("seq", 0))
            on_foc = on_focus(name, focus_names, ECOSYSTEM)
            if exclusive:
                if on_foc:
                    gated[name] = "high"
                    if gated_seq is not None:
                        gated_seq[name] = row_seq
                    newly += 1
                else:
                    skipped += 1
                continue
            on_wl = (
                is_watchlist(s, name) is not None
                or scope_watchlist.is_scope_watchlisted(
                    s, ECOSYSTEM, name, scopes=watch_scopes
                )
            )
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
            if gated_seq is not None:
                gated_seq[name] = row_seq
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
        gated_seq: dict[str, int] = {}
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
            _, skipped = _gate_page(results, gated, exclusive, gated_seq)
            total_skipped += skipped
            pages += 1
            since = last_seq
            if len(results) < DEFAULT_LIMIT:
                break

        # Resolve concrete versions for gated packages concurrently. The
        # manifest also tells us whether the package runs install-time code,
        # used below to prioritize the on-install attack surface.
        names = list(gated.keys())
        resolved: list[tuple[str, str, bool]] = []
        if names:
            async def _one(n: str):
                info = await _resolve_latest(client, n)
                if info:
                    resolved.append((n, info[0], info[1]))
            await asyncio.gather(*[_one(n) for n in names])

    enq = 0
    promoted = 0
    if resolved:
        with sess.session_scope() as s:
            for name, version, has_hook in resolved:
                priority = gated[name]
                # Pull brand-new packages that can execute install-time code, or
                # carry a dependency-confusion version tell, to the front of the
                # queue — otherwise they sit days deep in the npm backlog while a
                # live campaign runs. Never downgrades watchlist/focus (already high).
                if priority == "normal" and (has_hook or _is_suspicious_version(version)):
                    priority = "high"
                    promoted += 1
                row = enqueue(s, ecosystem=ECOSYSTEM, name=name,
                              version=version, priority=priority)
                if row is not None and row.status == "pending":
                    enq += 1

    # Cursor advance with holdback: a gated name we couldn't resolve this poll
    # is a brand-new package we'd lose forever if the forward-only cursor moved
    # past it. Cap each name at NPM_RESOLVE_MAX_ATTEMPTS retries (then give up,
    # logged) so a permanently-deleted package can't wedge the feed.
    resolved_names = {r[0] for r in resolved}
    unresolved = [n for n in names if n not in resolved_names]
    blocker_seqs: list[int] = []
    given_up: list[str] = []
    for n in unresolved:
        _resolve_attempts[n] += 1
        if _resolve_attempts[n] >= NPM_RESOLVE_MAX_ATTEMPTS:
            given_up.append(n)
        elif n in gated_seq:
            blocker_seqs.append(gated_seq[n])
    for n in list(resolved_names) + given_up:
        _resolve_attempts.pop(n, None)
    # Defense-in-depth: the counter self-drains (held names reappear and get
    # popped), but a name that vanishes mid-retry strands its entry. Hard-cap so
    # it can't grow without bound over a long uptime — drop anything not actively
    # gated this poll (re-resolving a stale name later is harmless).
    if len(_resolve_attempts) > _RESOLVE_ATTEMPTS_CAP:
        for n in [k for k in _resolve_attempts if k not in gated_seq]:
            _resolve_attempts.pop(n, None)
    if given_up:
        log.warning("npm_resolve_gave_up", names=given_up[:25],
                    count=len(given_up), max_attempts=NPM_RESOLVE_MAX_ATTEMPTS)

    # Advance only up to (but not past) the earliest still-unresolved package.
    safe_seq = min(min(blocker_seqs) - 1, max_seq) if blocker_seqs else max_seq
    if safe_seq > cursor:
        set_last_seq(safe_seq)

    if enq or total_skipped or blocker_seqs or given_up:
        log.info("changes_poll", enqueued=enq, gated=len(gated),
                 promoted_high=promoted,
                 unresolved=len(unresolved), held=len(blocker_seqs),
                 gave_up=len(given_up), skipped=total_skipped,
                 new_seq=(safe_seq if safe_seq > cursor else cursor),
                 exclusive=exclusive)
    return enq


def pull_since_beginning(days: int) -> int:
    """Backfill is not supported for npm.

    The CouchDB ``_changes`` feed is keyed by an opaque seq, not a timestamp, so
    a ``days`` window has no mapping. Discovery starts from the current seq at
    first boot; there is no time-addressable history to replay.
    """
    log.info("backfill_unsupported", ecosystem=ECOSYSTEM, days=days)
    return 0
