# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pkgsentry.store.models import ScanQueue

_PRIORITY_ORDER = {"high": 0, "normal": 1, "low": 2}

MAX_AUTO_ATTEMPTS = 3
STALE_CLAIM_TIMEOUT_SECONDS = 900

# Backlog-weighted ecosystem selection. Reserved fraction is split equally
# among non-empty ecosystems (the floor — guarantees no ecosystem starves);
# the remainder is allocated proportionally to backlog size; any one ecosystem
# is capped at max-share to prevent a 10x surge from fully dominating.
SCHED_RESERVED_FRACTION = float(os.environ.get("SCHED_RESERVED_FRACTION", "0.4"))
SCHED_MAX_ECO_SHARE = float(os.environ.get("SCHED_MAX_ECO_SHARE", "0.7"))


def _eco_weights(ecosystems: list[str], counts: dict[str, int]) -> list[float]:
    """Weight = floor + proportional-demand, clamped to max-share."""
    n = len(ecosystems)
    if n <= 1:
        return [1.0] * n
    reserved = max(0.0, min(SCHED_RESERVED_FRACTION, 1.0))
    max_share = max(reserved / n, min(SCHED_MAX_ECO_SHARE, 1.0))
    total = sum(counts.get(e, 0) for e in ecosystems) or 1
    base = reserved / n
    return [
        min(base + (1.0 - reserved) * counts.get(e, 0) / total, max_share)
        for e in ecosystems
    ]


def _weighted_order(ecosystems: list[str], weights: list[float]) -> list[str]:
    """Weighted sample without replacement → an ordered try-list.
    The first pick is biased by weight; if its row's claim CAS races, the
    iterator falls back to subsequent picks. N≤4 so the loop is trivial."""
    remaining = list(zip(ecosystems, weights))
    out: list[str] = []
    while remaining:
        ecos, ws = zip(*remaining)
        # All-zero weights → uniform fallback.
        pick = random.choices(ecos, weights=ws if any(ws) else None, k=1)[0]
        out.append(pick)
        remaining = [(e, w) for e, w in remaining if e != pick]
    return out


def enqueue(
    session: Session,
    *,
    ecosystem: str,
    name: str,
    version: str,
    priority: str = "normal",
    allow_rescan: bool = False,
) -> Optional[ScanQueue]:
    """Enqueue a (ecosystem, name, version) for scanning.

    Default (``allow_rescan=False``) is used by automated ingest jobs (feeds,
    cursor, watchlist). It dedups against ANY existing row for the same
    (eco, name, version), with one exception: a failed row whose
    ``attempts < MAX_AUTO_ATTEMPTS`` is promoted back to ``pending`` so it
    will be retried. Failed rows at/above the cap are treated as permanently
    failed and skipped (returns the existing failed row).

    ``allow_rescan=True`` is used by the CLI ``rescan`` command. It resets
    a done/failed row back to pending so the user can re-scan.
    """
    existing = session.scalars(
        select(ScanQueue).where(
            ScanQueue.ecosystem == ecosystem,
            ScanQueue.name == name,
            ScanQueue.version == version,
        )
    ).first()

    if existing is not None:
        if allow_rescan:
            if existing.status in ("pending", "claimed"):
                if _PRIORITY_ORDER.get(priority, 1) < _PRIORITY_ORDER.get(existing.priority, 1):
                    existing.priority = priority
                    session.flush()
                return existing
            # Reset done/failed row for rescan.
            existing.status = "pending"
            existing.priority = priority
            existing.last_error = None
            existing.claim_token = None
            existing.claimed_at = None
            existing.finished_at = None
            session.flush()
            return existing
        else:
            if existing.status in ("pending", "claimed", "done"):
                if existing.status not in ("done",) and _PRIORITY_ORDER.get(priority, 1) < _PRIORITY_ORDER.get(existing.priority, 1):
                    existing.priority = priority
                    session.flush()
                return existing
            if existing.status == "failed":
                if existing.attempts >= MAX_AUTO_ATTEMPTS:
                    return existing
                existing.status = "pending"
                existing.last_error = None
                existing.claim_token = None
                existing.claimed_at = None
                existing.finished_at = None
                if _PRIORITY_ORDER.get(priority, 1) < _PRIORITY_ORDER.get(existing.priority, 1):
                    existing.priority = priority
                session.flush()
                return existing

    row = ScanQueue(
        ecosystem=ecosystem,
        name=name,
        version=version,
        priority=priority,
        status="pending",
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        return None
    return row


def claim_next(session: Session) -> Optional[tuple[ScanQueue, str]]:
    """Claim the highest-priority pending item, fair across ecosystems.

    Within each priority tier the ecosystem is chosen by **backlog-weighted**
    sampling with a reserved floor: SCHED_RESERVED_FRACTION of attention is
    split equally so no ecosystem starves; the remainder is allocated
    proportionally to backlog size (so a backlogged ecosystem like npm draws
    its fair share of capacity), capped at SCHED_MAX_ECO_SHARE so a surge in
    one ecosystem can't fully dominate. Uniform-random was the previous
    behavior — it gave every ecosystem 1/N regardless of backlog, throttling
    the heavy one to its slice (npm: 79% of backlog → 25% of claims).
    """
    token = uuid.uuid4().hex
    for prio in ("high", "normal", "low"):
        # Pending count per ecosystem at this priority.
        rows = session.execute(
            select(ScanQueue.ecosystem, func.count())
            .where(ScanQueue.status == "pending", ScanQueue.priority == prio)
            .group_by(ScanQueue.ecosystem)
        ).all()
        if not rows:
            continue
        ecosystems = [r[0] for r in rows]
        counts = {r[0]: int(r[1]) for r in rows}
        weights = _eco_weights(ecosystems, counts)
        for eco in _weighted_order(ecosystems, weights):
            row = session.scalars(
                select(ScanQueue)
                .where(
                    ScanQueue.status == "pending",
                    ScanQueue.priority == prio,
                    ScanQueue.ecosystem == eco,
                )
                .order_by(ScanQueue.enqueued_at.asc())
                .limit(1)
            ).first()
            if row is not None:
                result = session.execute(
                    update(ScanQueue)
                    .where(ScanQueue.id == row.id, ScanQueue.status == "pending")
                    .values(
                        status="claimed",
                        claim_token=token,
                        claimed_at=datetime.now(timezone.utc),
                        attempts=ScanQueue.attempts + 1,
                    )
                )
                if result.rowcount == 1:
                    session.flush()
                    session.refresh(row)
                    return row, token
                session.expire(row)
    return None


def mark_done(session: Session, row: ScanQueue, token: Optional[str] = None) -> bool:
    """Mark a queue item as done. If token is provided, verify claim ownership."""
    if token is not None and row.claim_token != token:
        return False
    row.status = "done"
    row.finished_at = datetime.now(timezone.utc)
    session.flush()
    return True


def mark_failed(session: Session, row: ScanQueue, error: str, token: Optional[str] = None) -> bool:
    """Mark a queue item as failed. If token is provided, verify claim ownership."""
    if token is not None and row.claim_token != token:
        return False
    row.status = "failed"
    row.last_error = error
    row.finished_at = datetime.now(timezone.utc)
    session.flush()
    return True


def sweep_stale_claims(session: Session, *, now: Optional[datetime] = None) -> int:
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(seconds=STALE_CLAIM_TIMEOUT_SECONDS)
    rows = session.scalars(
        select(ScanQueue).where(
            ScanQueue.status == "claimed",
            ScanQueue.claimed_at.is_not(None),
            ScanQueue.claimed_at < cutoff,
        )
    ).all()
    touched = 0
    for row in rows:
        if row.attempts >= MAX_AUTO_ATTEMPTS:
            row.status = "failed"
            row.last_error = "claim_timeout"
            row.finished_at = current
        else:
            row.status = "pending"
            row.claimed_at = None
            row.claim_token = None
        touched += 1
    if touched:
        session.flush()
    return touched
