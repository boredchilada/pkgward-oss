# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for PyPI brand-new package detection.

Both cursor.py and feeds.py had bugs that caused enqueued_new=0 for all
brand-new PyPI packages — the create-action tracking happened after the
version-skip filter (cursor.py), and packages.xml titles were rejected
by PkgVersion validation (feeds.py).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pkgsentry.ecosystems.pypi.ingest.feeds import (
    parse_feed,
    parse_new_package_names,
)


# -------- feeds.py: parse_new_package_names --------

def test_parse_new_package_names_real_format():
    """packages.xml entries: '<name> added to PyPI'."""
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss><channel>
      <title>PyPI newest packages</title>
      <item><title>pandas-sns-2-part4 added to PyPI</title></item>
      <item><title>pymysqlo-db added to PyPI</title></item>
      <item><title>crewai-playwright-export added to PyPI</title></item>
    </channel></rss>"""
    names = parse_new_package_names(xml)
    assert names == [
        "pandas-sns-2-part4",
        "pymysqlo-db",
        "crewai-playwright-export",
    ]


def test_parse_new_package_names_skips_channel_title():
    xml = b"""<rss><channel>
      <title>PyPI newest packages</title>
      <item><title>foo-bar added to PyPI</title></item>
    </channel></rss>"""
    names = parse_new_package_names(xml)
    assert names == ["foo-bar"]


def test_parse_new_package_names_skips_unrelated_titles():
    """Titles without ' added to PyPI' suffix are ignored."""
    xml = b"""<rss><channel>
      <item><title>foo 1.2.3</title></item>
      <item><title>realnew added to PyPI</title></item>
    </channel></rss>"""
    names = parse_new_package_names(xml)
    assert names == ["realnew"]


def test_parse_feed_still_handles_updates_format():
    """Regression: updates.xml '<name> <version>' format still works."""
    xml = b"""<rss><channel>
      <title>PyPI recent updates</title>
      <item><title>requests 2.31.0</title></item>
      <item><title>numpy 1.26.4</title></item>
    </channel></rss>"""
    pairs = parse_feed(xml)
    assert pairs == [("requests", "2.31.0"), ("numpy", "1.26.4")]


def test_parse_feed_rejects_packages_xml_titles():
    """parse_feed must NOT extract from packages.xml — 'PyPI' is not a version."""
    xml = b"""<rss><channel>
      <item><title>foo added to PyPI</title></item>
    </channel></rss>"""
    pairs = parse_feed(xml)
    assert pairs == []


# -------- cursor.py: brand-new ordering --------

def test_cursor_brand_new_create_tracked_before_version_check(sqlite_engine, monkeypatch):
    """A 'create' event (version=None) must populate _created_in_batch
    so the subsequent 'new release X' event for the same package is
    recognized as brand-new."""
    from pkgsentry.ecosystems.pypi.ingest import cursor
    from pkgsentry.store import session as sess
    from pkgsentry.store.models import ScanQueue, ScanCursor

    # Wire test DB
    monkeypatch.setattr(sess, "_engine", sqlite_engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=sqlite_engine, expire_on_commit=False, future=True)
    monkeypatch.setattr(sess, "_SessionLocal", SessionLocal)

    # Bootstrap cursor at serial 0
    with sess.session_scope() as s:
        s.add(ScanCursor(ecosystem="pypi", last_serial=0))

    # Mock the XML-RPC client to return create + new release for a brand-new package
    mock_client = MagicMock()
    mock_client.changelog_since_serial.return_value = [
        # (name, version, ts, action, serial)
        ("brand-new-lure", None, 1700000000, "create", 1),
        ("brand-new-lure", "0.1.0", 1700000001, "new release 0.1.0", 2),
    ]
    monkeypatch.setattr(cursor, "_xmlrpc_client", lambda: mock_client)

    enqueued = cursor.pull_since()
    assert enqueued == 1

    # Verify it was enqueued with priority=normal (brand-new path)
    with sess.session_scope() as s:
        rows = s.query(ScanQueue).filter_by(ecosystem="pypi", name="brand-new-lure").all()
        assert len(rows) == 1
        assert rows[0].version == "0.1.0"
        assert rows[0].priority == "normal"


def test_cursor_create_alone_does_not_enqueue(sqlite_engine, monkeypatch):
    """A 'create' event with no subsequent release should NOT enqueue
    (we have no version to scan yet)."""
    from pkgsentry.ecosystems.pypi.ingest import cursor
    from pkgsentry.store import session as sess
    from pkgsentry.store.models import ScanQueue, ScanCursor

    monkeypatch.setattr(sess, "_engine", sqlite_engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=sqlite_engine, expire_on_commit=False, future=True)
    monkeypatch.setattr(sess, "_SessionLocal", SessionLocal)

    with sess.session_scope() as s:
        s.add(ScanCursor(ecosystem="pypi", last_serial=0))

    mock_client = MagicMock()
    mock_client.changelog_since_serial.return_value = [
        ("created-no-release", None, 1700000000, "create", 1),
    ]
    monkeypatch.setattr(cursor, "_xmlrpc_client", lambda: mock_client)

    enqueued = cursor.pull_since()
    assert enqueued == 0
    with sess.session_scope() as s:
        rows = s.query(ScanQueue).filter_by(ecosystem="pypi").all()
        assert len(rows) == 0


def test_cursor_non_watchlist_version_update_skipped(sqlite_engine, monkeypatch):
    """Existing non-watchlist package publishing a new version (no preceding
    create in same batch) should be skipped — that's the gate."""
    from pkgsentry.ecosystems.pypi.ingest import cursor
    from pkgsentry.store import session as sess
    from pkgsentry.store.models import ScanQueue, ScanCursor

    monkeypatch.setattr(sess, "_engine", sqlite_engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=sqlite_engine, expire_on_commit=False, future=True)
    monkeypatch.setattr(sess, "_SessionLocal", SessionLocal)

    with sess.session_scope() as s:
        s.add(ScanCursor(ecosystem="pypi", last_serial=0))

    mock_client = MagicMock()
    mock_client.changelog_since_serial.return_value = [
        ("some-existing-pkg", "2.0.0", 1700000000, "new release 2.0.0", 1),
    ]
    monkeypatch.setattr(cursor, "_xmlrpc_client", lambda: mock_client)

    enqueued = cursor.pull_since()
    assert enqueued == 0
