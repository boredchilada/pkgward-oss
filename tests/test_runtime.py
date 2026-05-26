# SPDX-License-Identifier: AGPL-3.0-or-later
import io
import contextlib

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from pkgsentry.store import session as sess
from pkgsentry.store.models import (
    Finding,
    Package,
    Scan,
    ScanQueue,
    Version,
)


def test_enqueue_one(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'r.db'}")
    sess.reset_engine()
    sess.init_db()
    from pkgsentry.runtime import enqueue_one
    enqueue_one(ecosystem="pypi", name="x", version="1", priority="high")
    with sess.session_scope() as s:
        row = s.scalars(select(ScanQueue)).one()
        assert row.priority == "high"


def test_show_findings_prints_results(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'r2.db'}")
    sess.reset_engine()
    sess.init_db()
    with sess.session_scope() as s:
        pkg = Package(ecosystem="pypi", name="bad"); s.add(pkg); s.flush()
        ver = Version(ecosystem="pypi", package_id=pkg.id, version="1.0"); s.add(ver); s.flush()
        scan = Scan(version_id=ver.id, verdict="malicious", score=99); s.add(scan); s.flush()
        s.add(Finding(scan_id=scan.id, rule_id="installer.urlopen_exec_chain",
                      category="installer", severity="critical", confidence="high",
                      file="setup.py", line=3, evidence="chain"))
    from pkgsentry.runtime import show_findings
    show_findings(ecosystem="pypi", name="bad", version="1.0")
    out = capsys.readouterr().out
    assert "malicious" in out
    assert "installer.urlopen_exec_chain" in out


def test_backfill_days_uses_cursor(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'r3.db'}")
    sess.reset_engine()
    sess.init_db()
    from pkgsentry.runtime import backfill_days
    called = {}
    def fake_pull(max_items=None):
        called["pulled"] = True
        return 0
    monkeypatch.setattr("pkgsentry.ecosystems.pypi.ingest.cursor.pull_since", fake_pull)
    backfill_days(days=1)
    assert called.get("pulled") is True
