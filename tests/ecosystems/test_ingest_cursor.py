# SPDX-License-Identifier: AGPL-3.0-or-later
from unittest.mock import patch

from pkgsentry.ecosystems.pypi.ingest import cursor as cur
from pkgsentry.store.models import ScanCursor, ScanQueue, Watchlist
from pkgsentry.store import session as sess


def test_get_and_set_serial(tmp_path, monkeypatch):
    """First get bootstraps the cursor to PyPI's current serial; subsequent
    set/get round-trips correctly. We mock _fetch_current_serial so the test
    is hermetic (no network) and asserts a known initial value."""
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'c.db'}")
    monkeypatch.setattr(cur, "_fetch_current_serial", lambda client: 999)
    sess.reset_engine()
    sess.init_db()
    assert cur.get_last_serial() == 999  # bootstrapped at PyPI's "now"
    cur.set_last_serial(1042)
    assert cur.get_last_serial() == 1042


def test_get_last_serial_falls_back_to_zero_when_xmlrpc_fails(tmp_path, monkeypatch):
    """If PyPI's XMLRPC endpoint is unreachable on first run, bootstrap
    falls back to 0 (and the next successful pull_since will advance it)."""
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'cf.db'}")
    monkeypatch.setattr(cur, "_fetch_current_serial", lambda client: None)
    sess.reset_engine()
    sess.init_db()
    assert cur.get_last_serial() == 0


def test_pull_since_enqueues_new_items(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'c2.db'}")
    # Bootstrap below pretends PyPI is at serial 0 so the fake events advance it.
    monkeypatch.setattr(cur, "_fetch_current_serial", lambda client: 0)
    sess.reset_engine()
    sess.init_db()

    # Pre-populate watchlist so cursor's watchlist-only filter passes
    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="foo", rank=1))
        s.add(Watchlist(ecosystem="pypi", name="bar", rank=2))

    # changelog_since_serial returns tuples
    # (name, version, timestamp, action, serial)
    fake = [
        ("foo", "1.0", 123, "create", 100),
        ("bar", "2.0", 124, "new release", 101),
        ("baz", None, 125, "remove", 102),  # skip: no version
    ]

    class FakeClient:
        def changelog_since_serial(self, serial):
            return fake
        def changelog_last_serial(self):
            return 0

    with patch.object(cur, "_xmlrpc_client", return_value=FakeClient()):
        n = cur.pull_since()
    assert n == 2
    with sess.session_scope() as s:
        from sqlalchemy import select
        names = {r.name for r in s.scalars(select(ScanQueue)).all()}
        assert names == {"foo", "bar"}
    assert cur.get_last_serial() == 102
