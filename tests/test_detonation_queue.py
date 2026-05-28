# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from pkgsentry.detonation_queue import (
    MAX_AUTO_ATTEMPTS,
    STALE_CLAIM_TIMEOUT_SECONDS,
    claim_next,
    enqueue,
    expire_stale_clean,
    mark_done,
    mark_failed,
    sweep_stale_claims,
)
from pkgsentry.store.models import DetonationQueue


def _enq(s, scan_id, *, priority="low", eco="npm", static="clean"):
    return enqueue(
        s, scan_id=scan_id, version_id=scan_id, ecosystem=eco,
        name=f"p{scan_id}", version="1.0", archive_kind="npm_tarball",
        priority=priority, static_verdict=static,
    )


def test_enqueue_dedupes_per_scan(db_session):
    _enq(db_session, 1)
    assert _enq(db_session, 1) is None
    rows = db_session.scalars(select(DetonationQueue)).all()
    assert len(rows) == 1


def test_claim_high_before_low(db_session):
    _enq(db_session, 1, priority="low")
    _enq(db_session, 2, priority="high")
    first, _ = claim_next(db_session)
    assert first.priority == "high"
    second, _ = claim_next(db_session)
    assert second.priority == "low"
    assert claim_next(db_session) is None


def test_low_tier_newest_first(db_session):
    older = _enq(db_session, 1, priority="low")
    newer = _enq(db_session, 2, priority="low")
    now = datetime.now(timezone.utc)
    older.enqueued_at = now - timedelta(hours=2)
    newer.enqueued_at = now - timedelta(minutes=5)
    db_session.flush()
    first, _ = claim_next(db_session)
    assert first.scan_id == newer.scan_id  # newest clean job drained first


def test_high_tier_oldest_first(db_session):
    older = _enq(db_session, 1, priority="high")
    newer = _enq(db_session, 2, priority="high")
    now = datetime.now(timezone.utc)
    older.enqueued_at = now - timedelta(hours=2)
    newer.enqueued_at = now - timedelta(minutes=5)
    db_session.flush()
    first, _ = claim_next(db_session)
    assert first.scan_id == older.scan_id  # flagged/watchlist is FIFO


def test_mark_done_token_guard(db_session):
    _enq(db_session, 1)
    row, token = claim_next(db_session)
    assert mark_done(db_session, row, token="wrong") is False
    assert mark_done(db_session, row, token=token) is True
    assert row.status == "done"


def test_mark_failed(db_session):
    _enq(db_session, 1)
    row, token = claim_next(db_session)
    assert mark_failed(db_session, row, "boom", token=token) is True
    assert row.status == "failed" and row.last_error == "boom"


def test_sweep_stale_claims_requeues(db_session):
    _enq(db_session, 1)
    row, _ = claim_next(db_session)
    row.claimed_at = datetime.now(timezone.utc) - timedelta(seconds=STALE_CLAIM_TIMEOUT_SECONDS + 60)
    db_session.flush()
    n = sweep_stale_claims(db_session)
    assert n == 1
    assert row.status == "pending" and row.claim_token is None


def test_sweep_stale_claims_fails_after_max_attempts(db_session):
    _enq(db_session, 1)
    row, _ = claim_next(db_session)
    row.attempts = MAX_AUTO_ATTEMPTS
    row.claimed_at = datetime.now(timezone.utc) - timedelta(seconds=STALE_CLAIM_TIMEOUT_SECONDS + 60)
    db_session.flush()
    sweep_stale_claims(db_session)
    assert row.status == "failed"


def test_expire_stale_clean_ttl_expires_low_never_high(db_session):
    old_low = _enq(db_session, 1, priority="low")
    old_high = _enq(db_session, 2, priority="high")
    fresh_low = _enq(db_session, 3, priority="low")
    stale = datetime.now(timezone.utc) - timedelta(hours=48)
    old_low.enqueued_at = stale
    old_high.enqueued_at = stale
    db_session.flush()

    n = expire_stale_clean(db_session, ttl_hours=24, cap=10000)
    assert n == 1
    assert old_low.status == "expired"
    assert old_high.status == "pending"   # flagged jobs are never expired
    assert fresh_low.status == "pending"


def test_expire_stale_clean_cap_expires_oldest(db_session):
    now = datetime.now(timezone.utc)
    for i in range(5):
        row = _enq(db_session, i + 1, priority="low")
        row.enqueued_at = now - timedelta(minutes=(5 - i))  # scan_id 1 oldest
    db_session.flush()

    n = expire_stale_clean(db_session, ttl_hours=999, cap=2)
    assert n == 3  # 5 pending low, cap 2 -> expire 3 oldest
    surviving = db_session.scalars(
        select(DetonationQueue).where(DetonationQueue.status == "pending")
    ).all()
    assert {r.scan_id for r in surviving} == {4, 5}  # the two newest survive
