# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from pkgsentry.logging_setup import get_logger
from pkgsentry.store.models import ScanQueue

log = get_logger("queue")

_PRIORITY_ORDER = {"high": 0, "normal": 1, "low": 2}

MAX_AUTO_ATTEMPTS = 3
# How many times claim_next re-tries the same ecosystem when it loses the claim
# CAS to another worker, before moving on. Bounds the work per claim while still
# letting workers drain a hot backlog under contention instead of idling.
_CLAIM_CAS_RETRIES = 5

# Terminal (done/failed) rows are kept this many days, then pruned. Without this,
# scan_queue grows unbounded across "all new packages" on four ecosystems — the
# per-claim pending-count aggregate and the unique-index dedup on every ingest
# INSERT both degrade as dead rows accumulate. Retention must exceed any window
# in which a (eco,name,version) could realistically reappear in a feed and want
# re-dedup; 14 days is comfortably past that.
QUEUE_RETENTION_DAYS = int(os.environ.get("PKGSENTRY_QUEUE_RETENTION_DAYS", "14"))
# Must be comfortably LARGER than workers.PROCESS_TIMEOUT_SECONDS (900). If they
# are equal, a package still legitimately processing at the timeout boundary can
# be reclaimed by the stale-claim sweeper at the same instant the worker's own
# timeout fires — two writers racing the same row, and a re-claim re-scans the
# package (wasted work + duplicate detonation enqueue). 2x leaves clear daylight.
STALE_CLAIM_TIMEOUT_SECONDS = 1800

# Concurrent ingest pollers (pypi/npm/gomod/crates feeds + watchlist refresh) all
# INSERT into ScanQueue and can deadlock on the unique index. Postgres aborts one
# txn as the victim; begin_nested()'s ROLLBACK TO SAVEPOINT recovers it, so a
# bounded retry usually wins on the next attempt. After this many retries we skip
# the item (it is re-listed on the next poll) rather than crash the poll cycle.
ENQUEUE_DEADLOCK_RETRIES = int(os.environ.get("PKGSENTRY_ENQUEUE_DEADLOCK_RETRIES", "3"))


def _is_deadlock(exc: Exception) -> bool:
    return "deadlock detected" in str(getattr(exc, "orig", None) or exc).lower()


def _is_lock_timeout(exc: Exception) -> bool:
    """statement_timeout / lock_timeout: a transient under-load condition, not a
    fatal DB error. Postgres surfaces these as OperationalError too, so without
    this they'd hit the bare `raise` and crash the whole poll cycle — the same
    failure the deadlock retry was added to prevent, just a different subclass."""
    s = str(getattr(exc, "orig", None) or exc).lower()
    return (
        "canceling statement due to" in s
        or "lock timeout" in s
        or "could not obtain lock" in s
    )

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

    for attempt in range(ENQUEUE_DEADLOCK_RETRIES + 1):
        # Fresh row each attempt: a savepoint rollback expunges the prior one.
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
            return row
        except IntegrityError:
            # A concurrent insert of the same (eco, name, version) won the race.
            return None
        except OperationalError as e:
            # Deadlock victim on the ScanQueue unique index. The savepoint rolled
            # back, so retry; a concurrent poller has committed by now and we
            # either succeed or hit the IntegrityError path above.
            if _is_deadlock(e) and attempt < ENQUEUE_DEADLOCK_RETRIES:
                time.sleep(0.05 * (attempt + 1))
                continue
            if _is_deadlock(e) or _is_lock_timeout(e):
                log.warning("enqueue_lock_giveup",
                            ecosystem=ecosystem, name=name, version=version,
                            reason="deadlock" if _is_deadlock(e) else "lock_timeout")
                return None
            raise
    return None


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
            # Retry the SAME ecosystem on a CAS race: the row we lost is now
            # 'claimed', so the next select returns the next-oldest pending row.
            # Without this, N workers colliding on the head of a big backlog (the
            # npm case) all fall through to idle even though hundreds of claimable
            # rows remain — the scheduler under-drains exactly under load.
            for _ in range(_CLAIM_CAS_RETRIES):
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
                if row is None:
                    break  # this ecosystem drained — move to the next
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
                session.expire(row)  # lost the race; try the next-oldest here
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
    # Error text can embed package-controlled bytes (an archive member name in an
    # exception message, etc.). Postgres TEXT rejects NUL (0x00), so an unstripped
    # NUL here would raise inside the failure handler itself and leave the row
    # stuck 'claimed' until the stale sweep. Strip defensively.
    row.last_error = error.replace("\x00", "") if error else error
    row.finished_at = datetime.now(timezone.utc)
    session.flush()
    return True


def prune_terminal(
    session: Session, *, older_than_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> int:
    """Delete done/failed rows older than the retention window. Returns the count."""
    days = older_than_days if older_than_days is not None else QUEUE_RETENTION_DAYS
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=days)
    result = session.execute(
        delete(ScanQueue).where(
            ScanQueue.status.in_(("done", "failed")),
            ScanQueue.finished_at.is_not(None),
            ScanQueue.finished_at < cutoff,
        )
    )
    return result.rowcount or 0


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
