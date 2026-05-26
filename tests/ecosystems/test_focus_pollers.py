# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from sqlalchemy import select

from pkgsentry import focus
from pkgsentry.focus import FocusEntry
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue


def _fresh_db(tmp_path, monkeypatch, name):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/name}")
    sess.reset_engine()
    sess.init_db()


@pytest.mark.asyncio
async def test_pypi_poll_focus_releases(httpx_mock, tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch, "pf.db")
    with sess.session_scope() as s:
        focus.upsert_focus(s, "pypi", [FocusEntry("requests"), FocusEntry("flask")])
    httpx_mock.add_response(url="https://pypi.org/pypi/requests/json", json={"info": {"version": "2.31.0"}})
    httpx_mock.add_response(url="https://pypi.org/pypi/flask/json", json={"info": {"version": "3.0.0"}})

    from pkgsentry.ecosystems.pypi.ingest import focus as pf
    n = await pf.poll_focus_releases()
    assert n == 2
    with sess.session_scope() as s:
        rows = {r.name: (r.version, r.priority) for r in s.scalars(select(ScanQueue)).all()}
    assert rows == {"requests": ("2.31.0", "high"), "flask": ("3.0.0", "high")}


@pytest.mark.asyncio
async def test_crates_poll_focus_releases(httpx_mock, tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch, "cf.db")
    with sess.session_scope() as s:
        focus.upsert_focus(s, "crates", [FocusEntry("serde")])
    httpx_mock.add_response(
        url="https://crates.io/api/v1/crates/serde",
        json={"crate": {"newest_version": "1.0.219"}},
    )
    from pkgsentry.ecosystems.crates.ingest import focus as cf
    n = await cf.poll_focus_releases()
    assert n == 1
    with sess.session_scope() as s:
        row = s.scalars(select(ScanQueue)).one()
    assert (row.name, row.version, row.priority) == ("serde", "1.0.219", "high")


@pytest.mark.asyncio
async def test_gomod_poll_focus_releases(httpx_mock, tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch, "gf.db")
    with sess.session_scope() as s:
        focus.upsert_focus(s, "gomod", [FocusEntry("golang.org/x/crypto")])
    httpx_mock.add_response(
        url="https://proxy.golang.org/golang.org/x/crypto/@latest",
        json={"Version": "v0.21.0"},
    )
    from pkgsentry.ecosystems.gomod.ingest import focus as gf
    n = await gf.poll_focus_releases()
    assert n == 1
    with sess.session_scope() as s:
        row = s.scalars(select(ScanQueue)).one()
    assert (row.name, row.version, row.priority) == ("golang.org/x/crypto", "v0.21.0", "high")


@pytest.mark.asyncio
async def test_poll_focus_empty_is_noop(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch, "ef.db")
    from pkgsentry.ecosystems.pypi.ingest import focus as pf
    assert await pf.poll_focus_releases() == 0
