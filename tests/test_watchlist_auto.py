# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the auto-watchlist gate.

Trigger: double-confirmed malicious (rules + LLM both). Auto-added rows carry
sentinel rank AUTO_MALICIOUS_RANK and are distinguished from popularity entries.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from pkgsentry import watchlist_auto
from pkgsentry.store.models import Watchlist
from pkgsentry.watchlist_auto import (
    AUTO_MALICIOUS_RANK,
    add_confirmed_malicious,
    is_watchlist_auto_only,
    list_auto_entries,
    prune_expired,
    prune_over_cap,
    remove_auto_entry,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    watchlist_auto._reset_rate_for_tests()
    monkeypatch.setenv("WATCHLIST_AUTO_MALICIOUS", "1")
    monkeypatch.delenv("WATCHLIST_AUTO_BLOCKLIST", raising=False)


def test_add_inserts_at_sentinel_rank(db_session):
    res = add_confirmed_malicious(db_session, "npm", "forge-jsxy", scan_id=1)
    assert res == "added"
    row = db_session.scalar(select(Watchlist).where(Watchlist.name == "forge-jsxy"))
    assert row is not None
    assert row.rank == AUTO_MALICIOUS_RANK


def test_re_add_refreshes_ttl(db_session):
    add_confirmed_malicious(db_session, "npm", "forge-jsxy")
    row = db_session.scalar(select(Watchlist).where(Watchlist.name == "forge-jsxy"))
    old = row.refreshed_at
    # Backdate so the refresh is observable.
    row.refreshed_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.flush()
    res = add_confirmed_malicious(db_session, "npm", "forge-jsxy")
    assert res == "refreshed"
    db_session.refresh(row)
    assert row.refreshed_at > old - timedelta(seconds=1)


def test_already_popularity_is_noop(db_session):
    # Pre-existing popularity row at rank 5 — must NOT be downgraded.
    db_session.add(Watchlist(ecosystem="npm", name="react", rank=5))
    db_session.flush()
    res = add_confirmed_malicious(db_session, "npm", "react")
    assert res == "already_popularity"
    row = db_session.scalar(select(Watchlist).where(Watchlist.name == "react"))
    assert row.rank == 5  # untouched


def test_blocklist_skips_add(db_session, monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_BLOCKLIST", "npm:bc-pkg,pypi:other")
    res = add_confirmed_malicious(db_session, "npm", "bc-pkg")
    assert res == "blocklisted"
    assert db_session.scalar(select(Watchlist).where(Watchlist.name == "bc-pkg")) is None


def test_disabled_returns_none(db_session, monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_MALICIOUS", "0")
    res = add_confirmed_malicious(db_session, "npm", "x")
    assert res is None
    assert db_session.scalar(select(Watchlist).where(Watchlist.name == "x")) is None


def test_rate_limit(db_session, monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_MAX_ADDS_PER_HOUR", "3")
    for i in range(3):
        assert add_confirmed_malicious(db_session, "npm", f"p{i}") == "added"
    assert add_confirmed_malicious(db_session, "npm", "p3") == "rate_limited"


def test_is_watchlist_auto_only(db_session):
    db_session.add(Watchlist(ecosystem="npm", name="react", rank=5))
    add_confirmed_malicious(db_session, "npm", "forge-jsxy")
    assert is_watchlist_auto_only(db_session, "npm", "forge-jsxy") is True
    assert is_watchlist_auto_only(db_session, "npm", "react") is False
    assert is_watchlist_auto_only(db_session, "npm", "never-seen") is False


def test_prune_expired_only_auto(db_session, monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_TTL_DAYS", "30")
    # Popularity entry, old refreshed_at — must NOT be pruned by this janitor.
    pop = Watchlist(
        ecosystem="npm", name="react", rank=5,
        refreshed_at=datetime.now(timezone.utc) - timedelta(days=365),
    )
    db_session.add(pop)
    # Auto-added entry past TTL.
    db_session.add(Watchlist(
        ecosystem="npm", name="forge-jsxy", rank=AUTO_MALICIOUS_RANK,
        refreshed_at=datetime.now(timezone.utc) - timedelta(days=60),
    ))
    # Auto-added entry within TTL.
    db_session.add(Watchlist(
        ecosystem="npm", name="recent-bad", rank=AUTO_MALICIOUS_RANK,
        refreshed_at=datetime.now(timezone.utc) - timedelta(days=1),
    ))
    db_session.flush()
    n = prune_expired(db_session)
    assert n == 1
    names = {r.name for r in db_session.scalars(select(Watchlist))}
    assert "forge-jsxy" not in names
    assert "react" in names  # popularity untouched
    assert "recent-bad" in names


def test_prune_over_cap_evicts_oldest(db_session, monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_MAX_PER_ECO", "2")
    base = datetime.now(timezone.utc)
    for i, name in enumerate(("a", "b", "c", "d")):
        db_session.add(Watchlist(
            ecosystem="npm", name=name, rank=AUTO_MALICIOUS_RANK,
            refreshed_at=base - timedelta(hours=i),  # 'a' newest, 'd' oldest
        ))
    db_session.flush()
    n = prune_over_cap(db_session)
    assert n == 2  # 4 - 2 cap = 2 evicted
    kept = {r.name for r in db_session.scalars(select(Watchlist))}
    assert kept == {"a", "b"}  # oldest two ('c','d') evicted


def test_remove_auto_entry_only_touches_auto_rank(db_session):
    db_session.add(Watchlist(ecosystem="npm", name="react", rank=5))
    add_confirmed_malicious(db_session, "npm", "forge-jsxy")
    db_session.flush()
    assert remove_auto_entry(db_session, "npm", "forge-jsxy") is True
    # Try to remove the popularity row via the auto path — should be no-op.
    assert remove_auto_entry(db_session, "npm", "react") is False
    names = {r.name for r in db_session.scalars(select(Watchlist))}
    assert names == {"react"}


def test_list_auto_entries(db_session):
    db_session.add(Watchlist(ecosystem="npm", name="react", rank=5))
    add_confirmed_malicious(db_session, "npm", "x")
    add_confirmed_malicious(db_session, "pypi", "y")
    db_session.flush()
    entries = list_auto_entries(db_session)
    assert {(e, n) for e, n, _ in entries} == {("npm", "x"), ("pypi", "y")}
    # ecosystem filter
    only_npm = list_auto_entries(db_session, ecosystem="npm")
    assert {n for _, n, _ in only_npm} == {"x"}
