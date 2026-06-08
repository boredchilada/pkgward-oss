# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded force-scan watch on a caught maintainer's clean siblings.

Closes the temporal hole in the one-shot pivot: a sibling that is clean at sweep
time but poisoned a release or two later. Force-scan only (never known-bad),
bounded by a release count (derived from scan history) + a safety TTL.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from pkgward import maintainer_watch as mw
from pkgward.store import session as sess
from pkgward.store.models import MaintainerWatch, Package, Scan, Version


@pytest.fixture()
def watch_db(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("PKGWARD_MAINTAINER_WATCH"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'w.db'}")
    sess.reset_engine()
    sess.init_db()
    yield
    sess.reset_engine()


def _seed_scan(ecosystem, name, version, *, days_ago=0):
    with sess.session_scope() as s:
        pkg = s.scalar(select(Package).where(
            Package.ecosystem == ecosystem, Package.name == name))
        if pkg is None:
            pkg = Package(ecosystem=ecosystem, name=name)
            s.add(pkg); s.flush()
        ver = Version(ecosystem=ecosystem, package_id=pkg.id, version=version)
        s.add(ver); s.flush()
        s.add(Scan(version_id=ver.id, verdict="clean",
                   finished_at=datetime.now(timezone.utc) - timedelta(days=days_ago)))


def test_add_and_is_watched(watch_db):
    with sess.session_scope() as s:
        assert mw.add_watch(s, "pypi", "ufish", maintainer="alice") == "added"
        assert mw.add_watch(s, "pypi", "ufish", maintainer="alice") == "refreshed"
        assert mw.is_maintainer_watched(s, "pypi", "ufish")
        assert mw.is_maintainer_watched(s, "pypi", "UFISH")  # case-insensitive
        assert not mw.is_maintainer_watched(s, "pypi", "unrelated")


def test_unsupported_ecosystem(watch_db):
    with sess.session_scope() as s:
        assert mw.add_watch(s, "gomod", "x") == "unsupported"
        assert not mw.is_maintainer_watched(s, "gomod", "x")


def test_exhausted_after_n_releases(watch_db, monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_WATCH_RELEASES", "3")
    with sess.session_scope() as s:
        mw.add_watch(s, "pypi", "spateo-release", maintainer="alice")
    # Two releases scanned since watch began → still active (2 < 3).
    _seed_scan("pypi", "spateo-release", "1.0.1")
    _seed_scan("pypi", "spateo-release", "1.0.2")
    with sess.session_scope() as s:
        assert mw.is_maintainer_watched(s, "pypi", "spateo-release")
    # Third release scanned → exhausted, and the janitor prunes it.
    _seed_scan("pypi", "spateo-release", "1.0.3")
    with sess.session_scope() as s:
        assert not mw.is_maintainer_watched(s, "pypi", "spateo-release")
        assert mw.prune(s) == 1
        assert s.scalar(select(func.count()).select_from(MaintainerWatch)) == 0


def test_ttl_backstop_prunes_dormant(watch_db, monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_WATCH_TTL_DAYS", "180")
    with sess.session_scope() as s:
        mw.add_watch(s, "npm", "dormant-pkg", maintainer="bob")
        # Backdate it past the TTL — a package that never releases again.
        row = s.scalar(select(MaintainerWatch))
        row.added_at = datetime.now(timezone.utc) - timedelta(days=200)
        s.flush()
        assert not mw.is_maintainer_watched(s, "npm", "dormant-pkg")
        assert mw.prune(s) == 1


def test_remove_watch_exit_ramp(watch_db):
    with sess.session_scope() as s:
        mw.add_watch(s, "pypi", "fp-pkg")
        assert mw.remove_watch(s, "pypi", "fp-pkg") == 1
        assert not mw.is_maintainer_watched(s, "pypi", "fp-pkg")


def test_disabled(watch_db, monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_WATCH", "0")
    with sess.session_scope() as s:
        mw.add_watch(s, "pypi", "x")
        assert not mw.is_maintainer_watched(s, "pypi", "x")
