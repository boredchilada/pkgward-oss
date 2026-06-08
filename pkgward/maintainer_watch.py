# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded force-scan watch on a caught maintainer's clean sibling packages.

The one-shot maintainer pivot (``maintainer_pivot.py``) force-scans a convicted
account's catalog at the moment of conviction — but a sibling that is still CLEAN
then, and only gets poisoned a release or two later, slips right back into the
"established-package update → skipped at ingest" blind spot (the exact hole behind
the 2026-06-07 incident). This module closes that temporal gap: each clean sibling
is watched so its next few releases are force-scanned at high priority.

FORCE-SCAN ONLY — never a known-bad mark. A watched package is merely *looked at*
(``watchlist_rank`` stays ``None`` in scoring, so the malicious threshold is not
lowered and the watch can't manufacture an FP). The worst case of a false-positive
pivot reaching here is a few wasted scans on an innocent author's next releases,
then the entry self-expires.

Bounded two ways, so the table can't grow without limit:
  * **release count** — ``PKGWARD_MAINTAINER_WATCH_RELEASES`` (default 3): once
    that many DISTINCT versions of the package have been scanned since ``added_at``,
    the watch is exhausted. Derived from scan history, not a mutable counter — no
    decrement hook on the hot path, no double-count race.
  * **safety TTL** — ``PKGWARD_MAINTAINER_WATCH_TTL_DAYS`` (default 180): a
    package that simply never releases again still falls off the table.

The ingest-gate check is cheap set membership (``load_watch_names`` once per poll,
mirroring ``scope_watchlist``); the count/TTL bound is verified only for an actual
match (rare) so an exhausted entry never force-scans even between janitor runs.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pkgward.logging_setup import get_logger
from pkgward.store.models import MaintainerWatch, Package, Scan, Version

log = get_logger("maintainer_watch")

SUPPORTED = ("pypi", "npm")


def is_enabled() -> bool:
    return os.environ.get("PKGWARD_MAINTAINER_WATCH", "1").lower() not in (
        "0", "false", "off", "no",
    )


def _releases() -> int:
    return int(os.environ.get("PKGWARD_MAINTAINER_WATCH_RELEASES", "3"))


def _ttl_days() -> int:
    return int(os.environ.get("PKGWARD_MAINTAINER_WATCH_TTL_DAYS", "180"))


def _max_per_eco() -> int:
    return int(os.environ.get("PKGWARD_MAINTAINER_WATCH_MAX_PER_ECO", "10000"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    """SQLite returns naive datetimes (Postgres returns tz-aware); normalize to UTC
    so TTL comparisons don't raise on a naive/aware mismatch."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _scans_since(session: Session, ecosystem: str, name: str, since: datetime) -> int:
    """Distinct versions of (ecosystem, name) scanned since *since*."""
    return session.scalar(
        select(func.count(func.distinct(Version.version)))
        .select_from(Scan)
        .join(Version, Scan.version_id == Version.id)
        .join(Package, Version.package_id == Package.id)
        .where(
            Package.ecosystem == ecosystem,
            func.lower(Package.name) == name.lower(),
            Scan.finished_at >= since,
        )
    ) or 0


def add_watch(
    session: Session, ecosystem: str, name: str, *, maintainer: Optional[str] = None,
) -> str:
    """Register or refresh a bounded watch. Returns 'added' | 'refreshed' |
    'unsupported'. Refreshing resets ``added_at`` so a re-caught maintainer's window
    restarts. Race-safe (savepoint-scoped insert)."""
    if ecosystem not in SUPPORTED:
        return "unsupported"
    existing = session.scalar(
        select(MaintainerWatch).where(
            MaintainerWatch.ecosystem == ecosystem,
            func.lower(MaintainerWatch.name) == name.lower(),
        )
    )
    if existing is not None:
        existing.added_at = _now()
        if maintainer:
            existing.maintainer = maintainer
        session.flush()
        return "refreshed"
    try:
        with session.begin_nested():
            session.add(MaintainerWatch(
                ecosystem=ecosystem, name=name, maintainer=maintainer, added_at=_now(),
            ))
            session.flush()
    except IntegrityError:
        return "refreshed"
    return "added"


def load_watch_names(session: Session, ecosystem: str) -> set[str]:
    """All watched names for an ecosystem (lowercased). Load once per poll batch."""
    rows = session.scalars(
        select(MaintainerWatch.name).where(MaintainerWatch.ecosystem == ecosystem)
    ).all()
    return {r.lower() for r in rows}


def is_maintainer_watched(
    session: Session, ecosystem: str, name: str, *, names: Optional[set[str]] = None,
) -> bool:
    """True if (ecosystem, name) is under an ACTIVE bounded watch. Pass a pre-loaded
    *names* set in a loop to keep the common (not-watched) case a cheap membership
    test; the count/TTL bound is checked only on a match."""
    if not is_enabled() or ecosystem not in SUPPORTED or not name:
        return False
    if names is None:
        names = load_watch_names(session, ecosystem)
    if name.lower() not in names:
        return False
    w = session.scalar(
        select(MaintainerWatch).where(
            MaintainerWatch.ecosystem == ecosystem,
            func.lower(MaintainerWatch.name) == name.lower(),
        )
    )
    if w is None:
        return False
    ttl = _ttl_days()
    if ttl > 0 and _aware(w.added_at) < _now() - timedelta(days=ttl):
        return False
    rel = _releases()
    if rel > 0 and _scans_since(session, ecosystem, name, w.added_at) >= rel:
        return False
    return True


def prune(session: Session) -> int:
    """Remove exhausted (>= N releases scanned since added_at), expired (past TTL),
    and over-cap entries. Returns the count removed."""
    removed = 0
    ttl = _ttl_days()
    rel = _releases()
    cutoff = _now() - timedelta(days=ttl) if ttl > 0 else None
    for w in session.scalars(select(MaintainerWatch)).all():
        expired = cutoff is not None and _aware(w.added_at) < cutoff
        exhausted = rel > 0 and _scans_since(session, w.ecosystem, w.name, w.added_at) >= rel
        if expired or exhausted:
            session.delete(w)
            removed += 1
    cap = _max_per_eco()
    if cap > 0:
        for eco in SUPPORTED:
            ids = session.execute(
                select(MaintainerWatch.id).where(MaintainerWatch.ecosystem == eco)
                .order_by(MaintainerWatch.added_at.asc())
            ).all()
            excess = len(ids) - cap
            if excess > 0:
                session.execute(delete(MaintainerWatch).where(
                    MaintainerWatch.id.in_([r[0] for r in ids[:excess]])))
                removed += excess
    if removed:
        session.flush()
        log.info("maintainer_watch_pruned", n=removed)
    return removed


def remove_watch(session: Session, ecosystem: str, name: str) -> int:
    """FP exit ramp / CLI: drop a single watch. Returns rows deleted."""
    res = session.execute(
        delete(MaintainerWatch).where(
            MaintainerWatch.ecosystem == ecosystem,
            func.lower(MaintainerWatch.name) == name.lower(),
        )
    )
    return int(res.rowcount or 0)


def list_watches(
    session: Session, ecosystem: Optional[str] = None,
) -> list[tuple[str, str, Optional[str], datetime]]:
    """List active watches: ``[(ecosystem, name, maintainer, added_at), …]``."""
    q = select(MaintainerWatch.ecosystem, MaintainerWatch.name,
               MaintainerWatch.maintainer, MaintainerWatch.added_at)
    if ecosystem:
        q = q.where(MaintainerWatch.ecosystem == ecosystem)
    q = q.order_by(MaintainerWatch.added_at.desc())
    return [(r[0], r[1], r[2], r[3]) for r in session.execute(q).all()]
