# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from pkgsentry.queue import (
    MAX_AUTO_ATTEMPTS,
    STALE_CLAIM_TIMEOUT_SECONDS,
    _eco_weights,
    _weighted_order,
    claim_next,
    enqueue,
    mark_done,
    mark_failed,
    sweep_stale_claims,
)
from pkgsentry.store.models import ScanQueue


def test_enqueue_dedupes_pending(db_session):
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0", priority="normal")
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0", priority="normal")
    rows = db_session.scalars(select(ScanQueue)).all()
    assert len(rows) == 1


def test_claim_next_drains_high_before_normal(db_session):
    enqueue(db_session, ecosystem="pypi", name="n1", version="1", priority="normal")
    enqueue(db_session, ecosystem="pypi", name="h1", version="1", priority="high")
    enqueue(db_session, ecosystem="pypi", name="l1", version="1", priority="low")
    enqueue(db_session, ecosystem="pypi", name="h2", version="1", priority="high")

    result = claim_next(db_session)
    assert result is not None
    first, _ = result
    assert first.name in {"h1", "h2"}

    result = claim_next(db_session)
    assert result is not None
    second, _ = result
    assert second.name in {"h1", "h2"} and second.name != first.name

    result = claim_next(db_session)
    assert result is not None
    third, _ = result
    assert third.priority == "normal"

    result = claim_next(db_session)
    assert result is not None
    fourth, _ = result
    assert fourth.priority == "low"

    assert claim_next(db_session) is None


def test_mark_done_and_failed(db_session):
    enqueue(db_session, ecosystem="pypi", name="a", version="1", priority="normal")
    result = claim_next(db_session)
    assert result is not None
    row, token = result
    mark_done(db_session, row, token=token)
    assert row.status == "done"

    enqueue(db_session, ecosystem="pypi", name="b", version="1", priority="normal")
    result2 = claim_next(db_session)
    assert result2 is not None
    row2, token2 = result2
    mark_failed(db_session, row2, "boom", token=token2)
    assert row2.status == "failed"
    assert row2.last_error == "boom"


def test_enqueue_skips_done_by_default(db_session):
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0")
    result = claim_next(db_session)
    assert result is not None
    row, token = result
    mark_done(db_session, row, token=token)
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0")
    rows = db_session.scalars(select(ScanQueue)).all()
    assert len(rows) == 1
    assert rows[0].status == "done"


def test_enqueue_allows_rescan_explicit(db_session):
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0")
    result = claim_next(db_session)
    assert result is not None
    row, token = result
    mark_done(db_session, row, token=token)
    # Rescan resets the existing row back to pending (single row, not a new one).
    enqueue(db_session, ecosystem="pypi", name="a", version="1.0", allow_rescan=True)
    rows = db_session.scalars(select(ScanQueue)).all()
    assert len(rows) == 1
    assert rows[0].status == "pending"


def test_enqueue_promotes_failed_under_max_attempts(db_session):
    row = ScanQueue(
        ecosystem="pypi", name="a", version="1.0", priority="normal",
        status="failed", attempts=1, last_error="boom",
        claimed_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db_session.add(row)
    db_session.flush()

    enqueue(db_session, ecosystem="pypi", name="a", version="1.0")
    rows = db_session.scalars(select(ScanQueue)).all()
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert rows[0].last_error is None
    assert rows[0].claimed_at is None


def test_enqueue_skips_permanently_failed(db_session):
    row = ScanQueue(
        ecosystem="pypi", name="a", version="1.0", priority="normal",
        status="failed", attempts=MAX_AUTO_ATTEMPTS, last_error="boom",
    )
    db_session.add(row)
    db_session.flush()

    enqueue(db_session, ecosystem="pypi", name="a", version="1.0")
    rows = db_session.scalars(select(ScanQueue)).all()
    assert len(rows) == 1
    assert rows[0].status == "failed"


def test_sweep_stale_claim_retries_under_max(db_session):
    now = datetime.now(timezone.utc)
    claimed_at = now - timedelta(minutes=20)
    row = ScanQueue(
        ecosystem="pypi", name="a", version="1.0", priority="normal",
        status="claimed", attempts=1, claimed_at=claimed_at,
    )
    db_session.add(row)
    db_session.flush()

    touched = sweep_stale_claims(db_session, now=now)
    assert touched == 1
    db_session.refresh(row)
    assert row.status == "pending"
    assert row.claimed_at is None


def test_sweep_stale_claim_fails_at_max(db_session):
    now = datetime.now(timezone.utc)
    claimed_at = now - timedelta(minutes=20)
    row = ScanQueue(
        ecosystem="pypi", name="a", version="1.0", priority="normal",
        status="claimed", attempts=MAX_AUTO_ATTEMPTS, claimed_at=claimed_at,
    )
    db_session.add(row)
    db_session.flush()

    touched = sweep_stale_claims(db_session, now=now)
    assert touched == 1
    db_session.refresh(row)
    assert row.status == "failed"
    assert row.last_error == "claim_timeout"


def test_sweep_does_not_touch_fresh_claims(db_session):
    now = datetime.now(timezone.utc)
    fresh_claimed = now - timedelta(seconds=30)
    row = ScanQueue(
        ecosystem="pypi", name="a", version="1.0", priority="normal",
        status="claimed", attempts=1, claimed_at=fresh_claimed,
    )
    db_session.add(row)
    db_session.flush()

    touched = sweep_stale_claims(db_session, now=now)
    assert touched == 0
    db_session.refresh(row)
    assert row.status == "claimed"
    assert row.claimed_at == fresh_claimed or row.claimed_at is not None


# --- Weighted ecosystem selection (Lever 1: backlog-proportional with floor) --


def test_eco_weights_equal_when_counts_equal():
    """Equal backlog → equal weight (matches old uniform fairness)."""
    ws = _eco_weights(["a", "b", "c", "d"], {"a": 10, "b": 10, "c": 10, "d": 10})
    assert all(abs(w - ws[0]) < 1e-9 for w in ws)


def test_eco_weights_floor_preserved_under_skew():
    """A 100:1 backlog skew must not let the small ecosystem drop below the floor."""
    ws = _eco_weights(["big", "small1", "small2", "small3"],
                      {"big": 1000, "small1": 1, "small2": 1, "small3": 1})
    # default reserved=0.4, n=4 → floor = 0.1 each (before demand share)
    assert all(w >= 0.1 - 1e-9 for w in ws[1:])
    # And the big one is clamped at max-share (0.7), not the raw 0.99…
    assert ws[0] <= 0.7 + 1e-9


def test_eco_weights_single_ecosystem():
    assert _eco_weights(["only"], {"only": 999}) == [1.0]


def test_weighted_order_yields_each_exactly_once():
    out = _weighted_order(["a", "b", "c", "d"], [0.5, 0.2, 0.2, 0.1])
    assert sorted(out) == ["a", "b", "c", "d"]


def test_claim_next_backlog_dominates_but_floor_protects(db_session):
    """Heavy npm backlog (~100:1) should get the majority of claims, but the
    tiny pypi backlog must still be served (no starvation)."""
    for i in range(100):
        enqueue(db_session, ecosystem="npm", name=f"n{i}", version="1", priority="normal")
    enqueue(db_session, ecosystem="pypi", name="p0", version="1", priority="normal")

    counts = {"npm": 0, "pypi": 0}
    for i in range(80):
        r = claim_next(db_session)
        if r is None:
            break
        row, _ = r
        counts[row.ecosystem] += 1
        # Re-enqueue to keep the skew constant (so the test measures the
        # selection bias, not the queue draining).
        enqueue(
            db_session, ecosystem=row.ecosystem,
            name=f"refill_{row.ecosystem}_{i}", version="1", priority="normal",
        )

    total = counts["npm"] + counts["pypi"]
    assert total >= 60
    # npm dominates (well above the old uniform 50% with N=2 ecosystems).
    assert counts["npm"] / total > 0.55, counts
    # pypi still served — the floor protects it from full starvation.
    assert counts["pypi"] >= 5, counts
