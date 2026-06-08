# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import pytest

from pkgward.ecosystems.npm.ingest import cursor as npm_cursor
from pkgward.ecosystems.npm.ingest.cursor import _seq_to_int
from pkgward.store import session as sess
from pkgward.store.models import ScanCursor, ScanQueue


def test_seq_to_int_plain():
    assert _seq_to_int(12345) == 12345


def test_seq_to_int_string():
    assert _seq_to_int("67890") == 67890


def test_seq_to_int_composite():
    # CouchDB composite seq "N-<b64hash>" — take the leading integer.
    assert _seq_to_int("4521-g1AAAABXeJ") == 4521


def test_seq_to_int_garbage():
    assert _seq_to_int("not-a-number") == 0
    assert _seq_to_int("") == 0


# ── cursor advance / resolution-holdback integration tests ──────────
#
# The npm cursor gates on package NAME from the _changes feed, then resolves
# dist-tags.latest separately. A transient resolve failure must not let the
# forward-only cursor advance past the unresolved brand-new package (it would
# never re-appear in the feed → silently never scanned).


def _changes_page(rows: list[tuple[int, str]]) -> dict:
    """Build a _changes response from (seq, name) tuples."""
    results = [{"seq": seq, "id": name, "changes": [{"rev": "1-x"}]} for seq, name in rows]
    last = rows[-1][0] if rows else 0
    return {"results": results, "last_seq": last}


@pytest.fixture()
def _npm_db(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'npm.db'}")
    monkeypatch.delenv("PKGWARD_FOCUS_EXCLUSIVE", raising=False)
    sess.reset_engine()
    sess.init_db()
    npm_cursor._reset_resolve_attempts_for_tests()
    # Seed the cursor so poll_changes_once does an incremental poll (not bootstrap).
    with sess.session_scope() as s:
        s.add(ScanCursor(ecosystem="npm", last_serial=100))
    yield
    sess.reset_engine()


@pytest.mark.asyncio
async def test_resolve_failure_holds_cursor_before_unresolved(_npm_db, monkeypatch):
    """A brand-new package whose version won't resolve holds the cursor just
    before its seq, so the next poll re-fetches it instead of losing it."""
    page = _changes_page([(101, "alpha-new"), (102, "beta-new"), (103, "gamma-new")])

    async def fake_fetch(client, since, limit=npm_cursor.DEFAULT_LIMIT):
        return page if since == 100 else {"results": [], "last_seq": since}

    async def fake_resolve(client, name):
        # beta-new (seq 102) fails to resolve; the others succeed.
        return None if name == "beta-new" else ("1.0.0", False)

    monkeypatch.setattr(npm_cursor, "_fetch_changes", fake_fetch)
    monkeypatch.setattr(npm_cursor, "_resolve_latest", fake_resolve)

    enq = await npm_cursor.poll_changes_once()

    assert enq == 2  # alpha + gamma enqueued
    # Cursor held at 101 (== 102 - 1), NOT advanced to 103.
    assert npm_cursor.get_last_seq() == 101
    with sess.session_scope() as s:
        names = {r.name for r in s.query(ScanQueue).all()}
    assert names == {"alpha-new", "gamma-new"}
    assert "beta-new" not in names  # not lost — will be retried next poll


@pytest.mark.asyncio
async def test_all_resolved_advances_cursor_fully(_npm_db, monkeypatch):
    page = _changes_page([(101, "a-pkg"), (102, "b-pkg")])

    async def fake_fetch(client, since, limit=npm_cursor.DEFAULT_LIMIT):
        return page if since == 100 else {"results": [], "last_seq": since}

    async def fake_resolve(client, name):
        return ("2.3.4", False)

    monkeypatch.setattr(npm_cursor, "_fetch_changes", fake_fetch)
    monkeypatch.setattr(npm_cursor, "_resolve_latest", fake_resolve)

    enq = await npm_cursor.poll_changes_once()

    assert enq == 2
    assert npm_cursor.get_last_seq() == 102  # advanced fully


@pytest.mark.asyncio
async def test_persistent_failure_gives_up_after_max_attempts(_npm_db, monkeypatch):
    """A package that never resolves (e.g. permanent 404) must not wedge the
    cursor forever — after NPM_RESOLVE_MAX_ATTEMPTS it is given up and the
    cursor advances past it."""
    monkeypatch.setattr(npm_cursor, "NPM_RESOLVE_MAX_ATTEMPTS", 3)
    page = _changes_page([(101, "dead-pkg")])

    async def fake_fetch(client, since, limit=npm_cursor.DEFAULT_LIMIT):
        return page if since == 100 else {"results": [], "last_seq": since}

    async def fake_resolve(client, name):
        return None  # always fails

    monkeypatch.setattr(npm_cursor, "_fetch_changes", fake_fetch)
    monkeypatch.setattr(npm_cursor, "_resolve_latest", fake_resolve)

    # First two polls hold the cursor at 100 (before seq 101).
    await npm_cursor.poll_changes_once()
    assert npm_cursor.get_last_seq() == 100
    await npm_cursor.poll_changes_once()
    assert npm_cursor.get_last_seq() == 100
    # Third poll hits the attempt cap → gives up → advances past it.
    await npm_cursor.poll_changes_once()
    assert npm_cursor.get_last_seq() == 101


# ── dependency-confusion / install-attack priority promotion (0.5.2) ──
# Brand-new npm packages that run install-time code, or carry a dep-confusion
# version tell (99.99.99 / 9.9.9 / 10.10.10 ...), jump to high priority so they
# don't sit days deep in the npm backlog while a live campaign runs.


@pytest.mark.parametrize("v,expected", [
    ("99.99.99", True), ("9.9.9", True), ("10.10.10", True), ("11.11.11", True),
    ("999.999.999", True), ("100.0.0", True),
    ("9.9.10", False), ("1.2.3", False), ("2.0.0", False), ("1.1.1", False),
    ("0.0.1", False), ("v3.4.5", False), ("1.0.0-beta", False),
])
def test_is_suspicious_version(v, expected):
    assert npm_cursor._is_suspicious_version(v) is expected


def test_has_install_hook():
    assert npm_cursor._has_install_hook({"postinstall": "node x.js"}) is True
    assert npm_cursor._has_install_hook({"preinstall": "x"}) is True
    assert npm_cursor._has_install_hook({"test": "jest", "build": "tsc"}) is False
    assert npm_cursor._has_install_hook(None) is False


@pytest.mark.asyncio
async def test_brandnew_install_hook_or_susp_version_promoted_to_high(_npm_db, monkeypatch):
    page = _changes_page([(101, "hooky"), (102, "depconf"), (103, "plain")])

    async def fake_fetch(client, since, limit=npm_cursor.DEFAULT_LIMIT):
        return page if since == 100 else {"results": [], "last_seq": since}

    async def fake_resolve(client, name):
        if name == "hooky":
            return ("1.0.0", True)            # install hook -> high
        if name == "depconf":
            return ("99.99.99", False)        # dep-confusion version -> high
        return ("1.2.3", False)               # plain brand-new -> stays normal

    monkeypatch.setattr(npm_cursor, "_fetch_changes", fake_fetch)
    monkeypatch.setattr(npm_cursor, "_resolve_latest", fake_resolve)

    await npm_cursor.poll_changes_once()

    with sess.session_scope() as s:
        pri = {r.name: r.priority for r in s.query(ScanQueue).all()}
    assert pri == {"hooky": "high", "depconf": "high", "plain": "normal"}
