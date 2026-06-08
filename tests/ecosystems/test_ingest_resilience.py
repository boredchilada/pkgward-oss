# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ingest silent-drop hardening (maintenance pass 2026-05-30):
gomod cursor holdback + same-timestamp hang-guard, crates reconciliation backstop."""
from __future__ import annotations

from sqlalchemy import select

from pkgward.store import session as sess
from pkgward.store.models import ScanQueue


def _init_db(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'ing.db'}")
    sess.reset_engine()
    sess.init_db()


def _entry(path, version, ts):
    return {"Path": path, "Version": version, "Timestamp": ts}


async def test_gomod_cursor_held_before_failed_brandnew_enqueue(tmp_path, monkeypatch):
    _init_db(tmp_path, monkeypatch)
    from pkgward.ecosystems.gomod.ingest import cursor as gc

    base = gc._ts_to_cursor("2026-05-01T00:00:00.000000Z")
    gc.set_last_cursor(base)

    t1 = "2026-05-02T00:00:00.000000Z"
    t2 = "2026-05-02T00:00:01.000000Z"   # the entry whose enqueue is blocked
    t3 = "2026-05-02T00:00:02.000000Z"
    pages = [[_entry("good/a", "v1.0.0", t1),
              _entry("blocked/b", "v1.0.0", t2),
              _entry("good/c", "v1.0.0", t3)], []]

    async def _fake_fetch(since, limit=gc.DEFAULT_LIMIT):
        return pages.pop(0) if pages else []
    monkeypatch.setattr(gc, "_fetch_page", _fake_fetch)

    real_enqueue = gc.enqueue

    def _enqueue(s, **kw):
        if kw.get("name") == "blocked/b":
            return None  # simulate a deadlock give-up / race (couldn't insert)
        return real_enqueue(s, **kw)
    monkeypatch.setattr(gc, "enqueue", _enqueue)

    await gc.poll_index_once()

    # Cursor held just before the blocked entry, NOT advanced past it to t3.
    assert gc.get_last_cursor() == gc._ts_to_cursor(t2) - 1
    with sess.session_scope() as s:
        names = set(s.scalars(
            select(ScanQueue.name).where(ScanQueue.ecosystem == "gomod")).all())
    assert "good/a" in names and "good/c" in names
    assert "blocked/b" not in names


async def test_gomod_poll_terminates_on_same_timestamp_full_page(tmp_path, monkeypatch):
    _init_db(tmp_path, monkeypatch)
    from pkgward.ecosystems.gomod.ingest import cursor as gc

    gc.set_last_cursor(gc._ts_to_cursor("2026-05-01T00:00:00.000000Z"))
    ts = "2026-05-02T00:00:00.000000Z"
    full = [_entry(f"mod/{i}", "v1.0.0", ts) for i in range(gc.DEFAULT_LIMIT)]
    pages = [full, []]   # one FULL page all at one timestamp, then empty

    async def _fake_fetch(since, limit=gc.DEFAULT_LIMIT):
        return pages.pop(0) if pages else []
    monkeypatch.setattr(gc, "_fetch_page", _fake_fetch)

    # Must return (not loop forever); the +1us bump steps past the stalled page.
    await gc.poll_index_once()
    assert gc.get_last_cursor() >= gc._ts_to_cursor(ts)


async def test_crates_reconcile_enqueues_missed_brandnew(tmp_path, monkeypatch):
    _init_db(tmp_path, monkeypatch)
    from pkgward.ecosystems.crates.ingest import feeds

    async def _fake_new(pages):
        return [("alpha", "1.0.0"), ("beta", "2.1.0")]
    monkeypatch.setattr(feeds, "_fetch_new_crates", _fake_new)

    n = await feeds.reconcile_new_crates()
    assert n == 2
    with sess.session_scope() as s:
        names = set(s.scalars(
            select(ScanQueue.name).where(ScanQueue.ecosystem == "crates")).all())
    assert names == {"alpha", "beta"}

    # Idempotent: the second run dedups against the now-queued names.
    assert await feeds.reconcile_new_crates() == 0
