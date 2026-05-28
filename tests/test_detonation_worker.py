# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from pkgsentry.detonate.client import DetonationResult, PhaseResult
from pkgsentry.store import session as sess
from pkgsentry.store.models import (
    DetonationQueue,
    Detonation,
    Finding as FindingRow,
    Package,
    Scan,
    TraceEvent,
    Version,
)


def _malicious_result() -> DetonationResult:
    return DetonationResult(
        detonation_id="det-test",
        status="completed",
        install_phase=PhaseResult(exit_code=0, duration_ms=120, timed_out=False),
        import_phase=PhaseResult(exit_code=0, duration_ms=40, timed_out=False),
        findings_json=[{
            "rule_id": "dyn_install_exfil", "category": "dynamic",
            "severity": "critical", "confidence": "high",
            "evidence": "connect(AF_INET, 45.33.32.156:443)",
        }],
        trace_events_json=[{
            "phase": "install", "category": "network", "operation": "connect",
            "pid": 99, "binary": "/usr/bin/node", "detail": {"addr": "45.33.32.156:443"},
            "matched_rule": "dyn_install_exfil",
        }],
        total_trace_events=1,
        filtered_trace_events=1,
    )


def _seed_scan(*, static_verdict: str) -> tuple[int, int]:
    """Create package/version/scan (+ one static finding) and a pending detonation
    job. Returns (scan_id, detq_id)."""
    with sess.session_scope() as s:
        pkg = Package(ecosystem="npm", name="evilpkg")
        s.add(pkg)
        s.flush()
        ver = Version(ecosystem="npm", package_id=pkg.id, version="1.0.0")
        s.add(ver)
        s.flush()
        scan = Scan(version_id=ver.id, verdict=static_verdict, score=0)
        s.add(scan)
        s.flush()
        s.add(FindingRow(
            scan_id=scan.id, rule_id="iocs.url_suspicious", category="iocs",
            severity="low", confidence="low", file="index.js", line=1, evidence="http://x",
        ))
        detq = DetonationQueue(
            scan_id=scan.id, version_id=ver.id, ecosystem="npm", name="evilpkg",
            version="1.0.0", archive_kind="npm_tarball", priority="low",
            status="pending", static_verdict=static_verdict,
        )
        s.add(detq)
        s.flush()
        return scan.id, detq.id


def _patch_boundaries(monkeypatch, tmp_path, *, alert_mock):
    arc_path = tmp_path / "dl" / "evilpkg-1.0.0.tgz"
    arc_path.parent.mkdir(parents=True, exist_ok=True)
    arc_path.write_bytes(b"x")
    arc = SimpleNamespace(kind="npm_tarball", path=arc_path)

    fake_adapter = SimpleNamespace(fetch=AsyncMock(return_value=[arc]))
    monkeypatch.setattr("pkgsentry.detonation_worker.adapter_registry", {"npm": fake_adapter})

    fake_client = SimpleNamespace(detonate=AsyncMock(return_value=_malicious_result()))
    monkeypatch.setattr("pkgsentry.detonation_worker.get_detonation_client", lambda: fake_client)

    monkeypatch.setattr("pkgsentry.detonation_worker.discord_notify.is_enabled", lambda: True)
    monkeypatch.setattr("pkgsentry.detonation_worker.discord_notify.send_dynamic_alert", alert_mock)


@pytest.mark.asyncio
async def test_worker_flips_verdict_and_alerts_once(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'d.db'}")
    sess.reset_engine()
    sess.init_db()
    scan_id, detq_id = _seed_scan(static_verdict="clean")

    alert = MagicMock(return_value=True)
    _patch_boundaries(monkeypatch, tmp_path, alert_mock=alert)

    from pkgsentry import detonation_worker as dw
    job = {
        "id": detq_id, "token": None, "scan_id": scan_id, "version_id": 1,
        "ecosystem": "npm", "name": "evilpkg", "version": "1.0.0",
        "archive_kind": "npm_tarball", "static_verdict": "clean",
    }
    # claim it so mark_done's token check (None) passes
    with sess.session_scope() as s:
        s.get(DetonationQueue, detq_id).status = "claimed"

    await dw._process_detonation(job)

    with sess.session_scope() as s:
        scan = s.get(Scan, scan_id)
        assert scan.verdict == "malicious"            # detonation flipped it
        detq = s.get(DetonationQueue, detq_id)
        assert detq.status == "done"
        dets = s.query(Detonation).filter_by(scan_id=scan_id).all()
        assert len(dets) == 1
        traces = s.query(TraceEvent).all()
        assert len(traces) == 1
        dyn = s.query(FindingRow).filter_by(scan_id=scan_id, rule_id="dyn_install_exfil").all()
        assert len(dyn) == 1

    alert.assert_called_once()
    assert alert.call_args.kwargs["new_verdict"] == "malicious"
    assert alert.call_args.kwargs["static_verdict"] == "clean"


@pytest.mark.asyncio
async def test_worker_no_double_alert_when_static_already_malicious(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'d.db'}")
    sess.reset_engine()
    sess.init_db()
    scan_id, detq_id = _seed_scan(static_verdict="malicious")

    alert = MagicMock(return_value=True)
    _patch_boundaries(monkeypatch, tmp_path, alert_mock=alert)

    from pkgsentry import detonation_worker as dw
    job = {
        "id": detq_id, "token": None, "scan_id": scan_id, "version_id": 1,
        "ecosystem": "npm", "name": "evilpkg", "version": "1.0.0",
        "archive_kind": "npm_tarball", "static_verdict": "malicious",
    }
    with sess.session_scope() as s:
        s.get(DetonationQueue, detq_id).status = "claimed"

    await dw._process_detonation(job)

    with sess.session_scope() as s:
        assert s.get(DetonationQueue, detq_id).status == "done"
        # detonation still persisted, just no second alert
        assert s.query(Detonation).filter_by(scan_id=scan_id).count() == 1

    alert.assert_not_called()  # static path already alerted on malicious


@pytest.mark.asyncio
async def test_worker_fast_fails_yanked_package(tmp_path, monkeypatch):
    from pkgsentry.adapter import NoFilesError

    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'d.db'}")
    sess.reset_engine()
    sess.init_db()
    scan_id, detq_id = _seed_scan(static_verdict="clean")

    fake_adapter = SimpleNamespace(fetch=AsyncMock(side_effect=NoFilesError("gone")))
    monkeypatch.setattr("pkgsentry.detonation_worker.adapter_registry", {"npm": fake_adapter})

    from pkgsentry import detonation_worker as dw
    job = {
        "id": detq_id, "token": None, "scan_id": scan_id, "version_id": 1,
        "ecosystem": "npm", "name": "evilpkg", "version": "1.0.0",
        "archive_kind": "npm_tarball", "static_verdict": "clean",
    }
    with sess.session_scope() as s:
        s.get(DetonationQueue, detq_id).status = "claimed"

    await dw._process_detonation(job)

    with sess.session_scope() as s:
        detq = s.get(DetonationQueue, detq_id)
        assert detq.status == "failed"          # permanent: not requeued
        assert s.query(Detonation).filter_by(scan_id=scan_id).count() == 0


@pytest.mark.asyncio
async def test_worker_timeout_requeues_without_partial_row(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'d.db'}")
    sess.reset_engine()
    sess.init_db()
    scan_id, detq_id = _seed_scan(static_verdict="clean")

    arc_path = tmp_path / "dl" / "evilpkg-1.0.0.tgz"
    arc_path.parent.mkdir(parents=True, exist_ok=True)
    arc_path.write_bytes(b"x")
    arc = SimpleNamespace(kind="npm_tarball", path=arc_path)
    fake_adapter = SimpleNamespace(fetch=AsyncMock(return_value=[arc]))
    monkeypatch.setattr("pkgsentry.detonation_worker.adapter_registry", {"npm": fake_adapter})

    async def _hang(**_):
        import asyncio
        await asyncio.sleep(10)

    fake_client = SimpleNamespace(detonate=_hang)
    monkeypatch.setattr("pkgsentry.detonation_worker.get_detonation_client", lambda: fake_client)
    monkeypatch.setattr("pkgsentry.detonation_worker.DETONATION_PROCESS_TIMEOUT", 0.05)

    from pkgsentry import detonation_worker as dw
    job = {
        "id": detq_id, "token": None, "scan_id": scan_id, "version_id": 1,
        "ecosystem": "npm", "name": "evilpkg", "version": "1.0.0",
        "archive_kind": "npm_tarball", "static_verdict": "clean",
    }
    with sess.session_scope() as s:
        s.get(DetonationQueue, detq_id).status = "claimed"

    await dw._process_detonation(job)

    with sess.session_scope() as s:
        detq = s.get(DetonationQueue, detq_id)
        assert detq.status == "pending"          # requeued for retry
        assert s.query(Detonation).filter_by(scan_id=scan_id).count() == 0
