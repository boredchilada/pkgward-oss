# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone

from sqlalchemy import select

from pkgsentry.store.models import (
    Finding,
    Package,
    Scan,
    ScanCursor,
    ScanQueue,
    Version,
    Watchlist,
    RuleHit,
)


def test_package_unique_per_ecosystem(db_session):
    a = Package(ecosystem="pypi", name="requests")
    b = Package(ecosystem="cratesio", name="requests")
    db_session.add_all([a, b])
    db_session.commit()
    rows = db_session.scalars(select(Package)).all()
    assert {r.ecosystem for r in rows} == {"pypi", "cratesio"}


def test_scan_queue_has_priority_and_ecosystem(db_session):
    q = ScanQueue(ecosystem="pypi", name="requests", version="2.32.1", priority="high")
    db_session.add(q)
    db_session.commit()
    row = db_session.scalars(select(ScanQueue)).one()
    assert row.priority == "high"
    assert row.ecosystem == "pypi"
    assert row.claimed_at is None
    assert row.status == "pending"


def test_scan_cursor_keyed_by_ecosystem(db_session):
    c = ScanCursor(ecosystem="pypi", last_serial=12345)
    db_session.add(c)
    db_session.commit()
    row = db_session.get(ScanCursor, "pypi")
    assert row.last_serial == 12345


def test_watchlist_carries_ecosystem(db_session):
    w = Watchlist(
        ecosystem="pypi",
        name="requests",
        rank=1,
        downloads_last_30d=500_000_000,
        refreshed_at=datetime.now(timezone.utc),
    )
    db_session.add(w)
    db_session.commit()
    row = db_session.scalars(select(Watchlist)).one()
    assert row.rank == 1


def test_finding_belongs_to_scan(db_session):
    pkg = Package(ecosystem="pypi", name="foo")
    db_session.add(pkg)
    db_session.flush()
    ver = Version(ecosystem="pypi", package_id=pkg.id, version="0.1.0")
    db_session.add(ver)
    db_session.flush()
    scan = Scan(version_id=ver.id, verdict="clean", score=0)
    db_session.add(scan)
    db_session.flush()
    f = Finding(
        scan_id=scan.id,
        rule_id="installer.urlopen_exec_chain",
        category="installer",
        severity="critical",
        confidence="high",
        file="setup.py",
        line=12,
        evidence="urlopen(...).read() -> exec(...)",
    )
    db_session.add(f)
    db_session.commit()
    assert db_session.scalars(select(Finding)).one().severity == "critical"


def test_rulehit_counter(db_session):
    rh = RuleHit(rule_id="installer.urlopen_exec_chain", count=3)
    db_session.add(rh)
    db_session.commit()
    assert db_session.get(RuleHit, "installer.urlopen_exec_chain").count == 3


def test_detonation_model(db_session):
    """Detonation row links to scan with phase and trace metadata."""
    from pkgsentry.store.models import Detonation

    pkg = Package(ecosystem="pypi", name="evil-pkg")
    db_session.add(pkg)
    db_session.flush()

    ver = Version(ecosystem="pypi", package_id=pkg.id, version="1.0.0")
    db_session.add(ver)
    db_session.flush()

    scan = Scan(version_id=ver.id, verdict="suspicious", score=35)
    db_session.add(scan)
    db_session.flush()

    det = Detonation(
        scan_id=scan.id,
        ecosystem="pypi",
        sandbox_id="det-abc123",
        status="completed",
        install_exit_code=0,
        install_duration_ms=4200,
        install_timed_out=False,
        import_exit_code=0,
        import_duration_ms=1100,
        import_timed_out=False,
        total_trace_events=1247,
        filtered_trace_events=3,
    )
    db_session.add(det)
    db_session.flush()

    assert det.id is not None
    assert det.scan_id == scan.id
    assert det.status == "completed"
    assert det.install_duration_ms == 4200


def test_trace_event_model(db_session):
    """TraceEvent rows link to detonation with structured detail."""
    from pkgsentry.store.models import Detonation, TraceEvent

    pkg = Package(ecosystem="pypi", name="evil-pkg")
    db_session.add(pkg)
    db_session.flush()

    ver = Version(ecosystem="pypi", package_id=pkg.id, version="1.0.0")
    db_session.add(ver)
    db_session.flush()

    scan = Scan(version_id=ver.id, verdict="malicious", score=85)
    db_session.add(scan)
    db_session.flush()

    det = Detonation(
        scan_id=scan.id, ecosystem="pypi",
        sandbox_id="det-abc123", status="completed",
    )
    db_session.add(det)
    db_session.flush()

    evt = TraceEvent(
        detonation_id=det.id,
        phase="install",
        category="network",
        operation="connect",
        detail={"addr": "45.33.32.156", "port": 443, "family": "AF_INET"},
        matched_rule="dyn_install_exfil",
    )
    db_session.add(evt)
    db_session.flush()

    assert evt.id is not None
    assert evt.detonation_id == det.id
    assert evt.detail["addr"] == "45.33.32.156"
    assert evt.matched_rule == "dyn_install_exfil"
