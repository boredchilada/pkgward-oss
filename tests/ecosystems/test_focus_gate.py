# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focus-list interaction with the per-ecosystem ingest gates."""
import pytest
from sqlalchemy import select
from unittest.mock import AsyncMock

from pkgsentry import focus
from pkgsentry.focus import FocusEntry
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Watchlist


def _fresh(tmp_path, monkeypatch, name):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/name}")
    monkeypatch.delenv("PKGSENTRY_FOCUS_EXCLUSIVE", raising=False)
    sess.reset_engine()
    sess.init_db()


def _queue(eco="pypi"):
    with sess.session_scope() as s:
        return {r.name: r.priority for r in s.scalars(select(ScanQueue).where(ScanQueue.ecosystem == eco)).all()}


PKG_XML = b"""<?xml version="1.0"?><rss version="2.0"><channel>
 <item><title>focuspkg 1.0.0</title><link>https://pypi.org/project/focuspkg/1.0.0/</link></item>
 <item><title>wlpkg 2.0.0</title><link>https://pypi.org/project/wlpkg/2.0.0/</link></item>
 <item><title>randompkg 3.0.0</title><link>https://pypi.org/project/randompkg/3.0.0/</link></item>
</channel></rss>"""
EMPTY_XML = b"""<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>"""


@pytest.mark.asyncio
async def test_pypi_feeds_additive_enqueues_focus_only_name(httpx_mock, tmp_path, monkeypatch):
    from pkgsentry.ecosystems.pypi.ingest import feeds
    _fresh(tmp_path, monkeypatch, "a.db")
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="wlpkg", rank=1))
        focus.upsert_focus(s, "pypi", [FocusEntry("focuspkg")])
    httpx_mock.add_response(url=feeds.UPDATES_URL, content=PKG_XML)
    httpx_mock.add_response(url=feeds.PACKAGES_URL, content=EMPTY_XML)  # nothing brand-new

    await feeds.poll_feeds_once()
    q = _queue()
    assert q.get("focuspkg") == "high"   # focus-only name still enqueued
    assert q.get("wlpkg") == "high"      # watchlist still works (additive)
    assert "randompkg" not in q          # neither focus nor watchlist nor brand-new


@pytest.mark.asyncio
async def test_pypi_feeds_exclusive_skips_watchlist(httpx_mock, tmp_path, monkeypatch):
    from pkgsentry.ecosystems.pypi.ingest import feeds
    _fresh(tmp_path, monkeypatch, "e.db")
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="wlpkg", rank=1))
        focus.upsert_focus(s, "pypi", [FocusEntry("focuspkg")])
    httpx_mock.add_response(url=feeds.UPDATES_URL, content=PKG_XML)
    httpx_mock.add_response(url=feeds.PACKAGES_URL, content=EMPTY_XML)

    await feeds.poll_feeds_once()
    q = _queue()
    assert q == {"focuspkg": "high"}     # ONLY focus; watchlist skipped


@pytest.mark.asyncio
async def test_crates_feeds_exclusive(tmp_path, monkeypatch):
    from pkgsentry.ecosystems.crates.ingest import feeds
    _fresh(tmp_path, monkeypatch, "c.db")
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="crates", name="serde", rank=1))
        focus.upsert_focus(s, "crates", [FocusEntry("mycrate")])
    # _fetch_rss called twice: new_items, then update_items.
    monkeypatch.setattr(feeds, "_fetch_rss", AsyncMock(side_effect=[
        [("mycrate", "0.1.0"), ("randomcrate", "9.9.9")],  # new
        [("serde", "1.0.0")],                               # updates (watchlist)
    ]))
    await feeds.poll_feeds_once()
    q = _queue("crates")
    assert q == {"mycrate": "high"}      # serde (watchlist) + randomcrate skipped


@pytest.mark.asyncio
async def test_gomod_cursor_exclusive_case_insensitive(tmp_path, monkeypatch):
    from pkgsentry.ecosystems.gomod.ingest import cursor
    _fresh(tmp_path, monkeypatch, "g.db")
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    with sess.session_scope() as s:
        # focus stored with different casing than the index entry
        focus.upsert_focus(s, "gomod", [FocusEntry("github.com/Foo/Bar")])
    entries = [
        {"Path": "github.com/foo/bar", "Version": "v1.2.3", "Timestamp": "2026-01-01T00:00:00Z"},
        {"Path": "github.com/other/mod", "Version": "v0.1.0", "Timestamp": "2026-01-01T00:00:01Z"},
    ]
    monkeypatch.setattr(cursor, "_fetch_page", AsyncMock(side_effect=[entries, []]))
    await cursor.poll_index_once()
    q = _queue("gomod")
    assert q == {"github.com/foo/bar": "high"}  # case-insensitive focus match; other skipped
