# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import pytest

from pkgsentry.ecosystems.pypi.ingest import watchlist as wl
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Watchlist
from sqlalchemy import select


SAMPLE_TOP = {
    "rows": [
        {"project": "boto3", "download_count": 900_000_000},
        {"project": "requests", "download_count": 500_000_000},
        {"project": "urllib3", "download_count": 400_000_000},
    ]
}


@pytest.mark.asyncio
async def test_refresh_writes_watchlist(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'w.db'}")
    sess.reset_engine()
    sess.init_db()
    httpx_mock.add_response(url=wl.TOP_URL, json=SAMPLE_TOP)
    n = await wl.refresh_watchlist(top_n=3)
    assert n == 3
    with sess.session_scope() as s:
        rows = s.scalars(select(Watchlist).order_by(Watchlist.rank)).all()
        assert [r.name for r in rows] == ["boto3", "requests", "urllib3"]
        assert rows[0].rank == 1


def test_is_watchlist_lookup(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'w2.db'}")
    sess.reset_engine()
    sess.init_db()
    from datetime import datetime, timezone
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="requests", rank=2, downloads_last_30d=1, refreshed_at=datetime.now(timezone.utc)))
    with sess.session_scope() as s:
        assert wl.is_watchlist(s, "requests") == 2
        assert wl.is_watchlist(s, "absent") is None


@pytest.mark.asyncio
async def test_poll_watchlist_releases_enqueues_high(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'w3.db'}")
    sess.reset_engine()
    sess.init_db()
    from datetime import datetime, timezone
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="requests", rank=1, downloads_last_30d=1, refreshed_at=datetime.now(timezone.utc)))
    httpx_mock.add_response(
        url="https://pypi.org/pypi/requests/json",
        json={"info": {"version": "2.32.1"}, "releases": {"2.32.1": [{}]}},
    )
    n = await wl.poll_watchlist_releases(limit=1)
    assert n >= 1
    with sess.session_scope() as s:
        row = s.scalars(select(ScanQueue).where(ScanQueue.name == "requests")).one()
        assert row.priority == "high"
        assert row.version == "2.32.1"
