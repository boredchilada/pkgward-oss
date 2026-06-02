# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from pkgsentry.queue import (
    MAX_AUTO_ATTEMPTS,
    STALE_CLAIM_TIMEOUT_SECONDS,
    _eco_weights,
    _is_lock_timeout,
    _weighted_order,
    claim_next,
    enqueue,
    mark_done,
    mark_failed,
    prune_terminal,
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


def test_mark_failed_strips_nul_from_error(db_session):
    # Package-controlled bytes can carry a NUL into an exception message; Postgres
    # TEXT rejects NUL, which would crash the failure handler and wedge the row.
    enqueue(db_session, ecosystem="pypi", name="nul", version="1", priority="normal")
    result = claim_next(db_session)
    assert result is not None
    row, token = result
    mark_failed(db_session, row, "bad\x00bytes\x00here", token=token)
    assert row.status == "failed"
    assert "\x00" not in (row.last_error or "")
    assert row.last_error == "badbyteshere"


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
    claimed_at = now - timedelta(seconds=STALE_CLAIM_TIMEOUT_SECONDS + 60)
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
    claimed_at = now - timedelta(seconds=STALE_CLAIM_TIMEOUT_SECONDS + 60)
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


# ── deadlock-retry on concurrent ScanQueue inserts (0.5.2) ──────────
# Postgres can pick our INSERT as a deadlock victim when concurrent pollers
# contend on the unique index. enqueue() must retry (savepoint recovers) and,
# if it can't win, skip the item rather than crash the whole poll cycle.
import pytest
from sqlalchemy.exc import OperationalError

import pkgsentry.queue as q


def _op_err(msg: str) -> OperationalError:
    return OperationalError("INSERT INTO scan_queue ...", {}, Exception(msg))


def test_is_deadlock_detects_message():
    assert q._is_deadlock(_op_err("deadlock detected")) is True
    assert q._is_deadlock(_op_err("statement timeout")) is False


def _flush_raising_on_insert(db_session, exc_factory, *, fail_times=None):
    """Return a flush() replacement that raises (from exc_factory) only when a
    ScanQueue INSERT is actually pending — i.e. at enqueue's begin_nested flush,
    not the earlier dedup SELECT's autoflush. ``fail_times=None`` = always fail
    on insert; an int caps how many insert-flushes raise before succeeding."""
    real_flush = db_session.flush
    state = {"n": 0}

    def flush(*a, **k):
        pending_insert = any(isinstance(o, ScanQueue) for o in db_session.new)
        if pending_insert and (fail_times is None or state["n"] < fail_times):
            state["n"] += 1
            raise exc_factory()
        return real_flush(*a, **k)

    return flush, state


def test_enqueue_retries_then_succeeds_on_deadlock(db_session, monkeypatch):
    monkeypatch.setattr(q.time, "sleep", lambda *_: None)
    flush, state = _flush_raising_on_insert(
        db_session, lambda: _op_err("deadlock detected"), fail_times=1)
    monkeypatch.setattr(db_session, "flush", flush)
    row = q.enqueue(db_session, ecosystem="pypi", name="dl", version="1.0")
    assert row is not None
    assert state["n"] == 1  # first insert deadlocked, retry succeeded


def test_enqueue_gives_up_after_retries_without_crashing(db_session, monkeypatch):
    monkeypatch.setattr(q, "ENQUEUE_DEADLOCK_RETRIES", 2)
    monkeypatch.setattr(q.time, "sleep", lambda *_: None)
    flush, state = _flush_raising_on_insert(
        db_session, lambda: _op_err("deadlock detected"))
    monkeypatch.setattr(db_session, "flush", flush)
    # Must NOT raise — the poll cycle keeps going, item skipped (re-listed next poll).
    row = q.enqueue(db_session, ecosystem="pypi", name="dl2", version="1.0")
    assert row is None
    assert state["n"] == 3  # initial + 2 retries


def test_enqueue_reraises_non_deadlock_operational_error(db_session, monkeypatch):
    monkeypatch.setattr(q.time, "sleep", lambda *_: None)
    flush, _ = _flush_raising_on_insert(
        db_session, lambda: _op_err("connection reset by peer"))
    monkeypatch.setattr(db_session, "flush", flush)
    with pytest.raises(OperationalError):
        q.enqueue(db_session, ecosystem="pypi", name="dl3", version="1.0")


def test_prune_terminal_deletes_old_keeps_recent(db_session):
    now = datetime.now(timezone.utc)
    old_done = ScanQueue(ecosystem="pypi", name="old", version="1", priority="normal",
                         status="done", finished_at=now - timedelta(days=30))
    old_failed = ScanQueue(ecosystem="pypi", name="oldf", version="1", priority="normal",
                           status="failed", finished_at=now - timedelta(days=30))
    recent_done = ScanQueue(ecosystem="pypi", name="recent", version="1", priority="normal",
                            status="done", finished_at=now - timedelta(days=1))
    pending = ScanQueue(ecosystem="pypi", name="pend", version="1", priority="normal",
                        status="pending")
    db_session.add_all([old_done, old_failed, recent_done, pending])
    db_session.flush()

    deleted = prune_terminal(db_session, older_than_days=14, now=now)
    assert deleted == 2
    remaining = {r.name for r in db_session.scalars(select(ScanQueue)).all()}
    assert remaining == {"recent", "pend"}  # recent done + pending survive


def test_is_lock_timeout_matches_statement_timeout():
    class _Op(Exception):
        pass
    assert _is_lock_timeout(_Op("canceling statement due to statement timeout"))
    assert _is_lock_timeout(_Op("canceling statement due to lock timeout"))
    assert not _is_lock_timeout(_Op("deadlock detected"))
    assert not _is_lock_timeout(_Op("some other error"))
