# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pkgsentry.store.models import DetonationQueue

_PRIORITY_ORDER = {"high": 0, "normal": 1, "low": 2}

MAX_AUTO_ATTEMPTS = 3
STALE_CLAIM_TIMEOUT_SECONDS = 900

CLEAN_TTL_HOURS = 24
CLEAN_BACKLOG_CAP = 50000


def enqueue(
    session: Session,
    *,
    scan_id: int,
    version_id: int,
    ecosystem: str,
    name: str,
    version: str,
    archive_kind: str,
    priority: str = "low",
    static_verdict: str = "clean",
) -> Optional[DetonationQueue]:
    """Enqueue a detonation job for a finished scan. Deduped per scan_id."""
    row = DetonationQueue(
        scan_id=scan_id,
        version_id=version_id,
        ecosystem=ecosystem,
        name=name,
        version=version,
        archive_kind=archive_kind,
        priority=priority,
        static_verdict=static_verdict,
        status="pending",
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        return None
    return row


def claim_next(session: Session) -> Optional[tuple[DetonationQueue, str]]:
    """Claim the highest-priority pending job, fair across ecosystems.

    high/normal tiers are FIFO (oldest first). The best-effort ``low`` tier is
    newest-first, so the capacity-starved tail that ``expire_stale_clean`` drops
    is the oldest clean jobs (least worth detonating late).
    """
    token = uuid.uuid4().hex
    for prio in ("high", "normal", "low"):
        ecosystems = [
            r[0] for r in session.execute(
                select(DetonationQueue.ecosystem)
                .where(DetonationQueue.status == "pending", DetonationQueue.priority == prio)
                .group_by(DetonationQueue.ecosystem)
            ).all()
        ]
        if not ecosystems:
            continue
        random.shuffle(ecosystems)
        order = (
            DetonationQueue.enqueued_at.desc() if prio == "low"
            else DetonationQueue.enqueued_at.asc()
        )
        for eco in ecosystems:
            row = session.scalars(
                select(DetonationQueue)
                .where(
                    DetonationQueue.status == "pending",
                    DetonationQueue.priority == prio,
                    DetonationQueue.ecosystem == eco,
                )
                .order_by(order)
                .limit(1)
            ).first()
            if row is not None:
                result = session.execute(
                    update(DetonationQueue)
                    .where(DetonationQueue.id == row.id, DetonationQueue.status == "pending")
                    .values(
                        status="claimed",
                        claim_token=token,
                        claimed_at=datetime.now(timezone.utc),
                        attempts=DetonationQueue.attempts + 1,
                    )
                )
                if result.rowcount == 1:
                    session.flush()
                    session.refresh(row)
                    return row, token
                session.expire(row)
    return None


def mark_done(session: Session, row: DetonationQueue, token: Optional[str] = None) -> bool:
    if token is not None and row.claim_token != token:
        return False
    row.status = "done"
    row.finished_at = datetime.now(timezone.utc)
    session.flush()
    return True


def mark_failed(session: Session, row: DetonationQueue, error: str, token: Optional[str] = None) -> bool:
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
        select(DetonationQueue).where(
            DetonationQueue.status == "claimed",
            DetonationQueue.claimed_at.is_not(None),
            DetonationQueue.claimed_at < cutoff,
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


def expire_stale_clean(
    session: Session,
    *,
    now: Optional[datetime] = None,
    ttl_hours: int = CLEAN_TTL_HOURS,
    cap: int = CLEAN_BACKLOG_CAP,
) -> int:
    """Bound the best-effort ``low`` (clean) backlog.

    Expires pending ``low`` jobs older than ``ttl_hours``, then expires the
    oldest beyond ``cap``. ``high``/``normal`` jobs are never expired.
    """
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(hours=ttl_hours)
    expired = 0

    res = session.execute(
        update(DetonationQueue)
        .where(
            DetonationQueue.status == "pending",
            DetonationQueue.priority == "low",
            DetonationQueue.enqueued_at < cutoff,
        )
        .values(status="expired", finished_at=current)
    )
    expired += res.rowcount or 0

    remaining = session.scalar(
        select(func.count())
        .select_from(DetonationQueue)
        .where(DetonationQueue.status == "pending", DetonationQueue.priority == "low")
    ) or 0
    if remaining > cap:
        ids = [
            r[0] for r in session.execute(
                select(DetonationQueue.id)
                .where(DetonationQueue.status == "pending", DetonationQueue.priority == "low")
                .order_by(DetonationQueue.enqueued_at.asc())
                .limit(remaining - cap)
            ).all()
        ]
        if ids:
            res2 = session.execute(
                update(DetonationQueue)
                .where(DetonationQueue.id.in_(ids))
                .values(status="expired", finished_at=current)
            )
            expired += res2.rowcount or 0

    if expired:
        session.flush()
    return expired
