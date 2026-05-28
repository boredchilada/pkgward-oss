# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy import select

from pkgsentry import detonation_queue
from pkgsentry.adapter import Finding, NoFilesError, adapter_registry
from pkgsentry.detect.score import _is_shadow_finding, score_and_verdict
from pkgsentry.detonate.client import get_client as get_detonation_client
from pkgsentry.logging_setup import get_logger
from pkgsentry.notify import discord as discord_notify
from pkgsentry.pipeline import (
    _bump_rulehits_deferred,
    _is_watchlist,
    _persist_findings,
)
from pkgsentry.store import session as sess
from pkgsentry.store.models import (
    Detonation,
    DetonationQueue,
    Finding as FindingRow,
    Scan,
    TraceEvent,
)

log = get_logger("detonation_worker")

# fetch (network) + detonate (≤180s client timeout) + persist
DETONATION_PROCESS_TIMEOUT = 300


def _mark_failed(job: dict, reason: str) -> None:
    with sess.session_scope() as s:
        q = s.get(DetonationQueue, job["id"])
        if q is not None:
            detonation_queue.mark_failed(s, q, reason[:4000], token=job["token"])


def _requeue_or_fail(job: dict, reason: str) -> None:
    """Transient failure: return the job to pending (retry) until MAX_AUTO_ATTEMPTS."""
    with sess.session_scope() as s:
        q = s.get(DetonationQueue, job["id"])
        if q is None or q.status != "claimed" or q.claim_token != job["token"]:
            return
        if q.attempts >= detonation_queue.MAX_AUTO_ATTEMPTS:
            q.status = "failed"
            q.last_error = reason[:4000]
            q.finished_at = datetime.now(timezone.utc)
        else:
            q.status = "pending"
            q.claim_token = None
            q.claimed_at = None
        s.flush()


def _finalize_detonation(job: dict, det_result) -> Optional[dict]:
    """Persist the detonation + trace events, re-score with dynamic findings, mark
    the job done. Returns an alert payload if the verdict flipped to malicious."""
    alert: Optional[dict] = None
    dyn_for_bump: list[Finding] = []
    with sess.session_scope() as s:
        q = s.get(DetonationQueue, job["id"])
        scan = s.get(Scan, job["scan_id"])
        if scan is None:
            if q is not None:
                detonation_queue.mark_done(s, q, token=job["token"])
            return None

        det_row = Detonation(
            scan_id=scan.id,
            ecosystem=job["ecosystem"],
            sandbox_id=det_result.detonation_id,
            status=det_result.status,
            install_exit_code=det_result.install_phase.exit_code if det_result.install_phase else None,
            install_duration_ms=det_result.install_phase.duration_ms if det_result.install_phase else None,
            install_timed_out=det_result.install_phase.timed_out if det_result.install_phase else False,
            import_exit_code=det_result.import_phase.exit_code if det_result.import_phase else None,
            import_duration_ms=det_result.import_phase.duration_ms if det_result.import_phase else None,
            import_timed_out=det_result.import_phase.timed_out if det_result.import_phase else False,
            total_trace_events=det_result.total_trace_events,
            filtered_trace_events=det_result.filtered_trace_events,
            finished_at=datetime.now(timezone.utc),
        )
        s.add(det_row)
        s.flush()

        for evt in det_result.trace_events_json:
            s.add(TraceEvent(
                detonation_id=det_row.id,
                phase=evt.get("phase", "install"),
                category=evt.get("category", "unknown"),
                operation=evt.get("operation", "unknown"),
                pid=evt.get("pid"),
                binary=evt.get("binary"),
                detail=evt.get("detail") or {},
                matched_rule=evt.get("matched_rule"),
            ))

        dyn_findings = det_result.to_findings()
        new_verdict, new_score = scan.verdict, scan.score
        if dyn_findings:
            static_rows = s.scalars(
                select(FindingRow).where(FindingRow.scan_id == scan.id)
            ).all()
            static_findings = [
                Finding(rule_id=r.rule_id, category=r.category, severity=r.severity,
                        confidence=r.confidence, file=r.file, line=r.line, evidence=r.evidence)
                for r in static_rows
            ]
            all_findings = static_findings + dyn_findings
            _persist_findings(s, scan, dyn_findings)
            rank = _is_watchlist(s, job["name"], job["ecosystem"])
            res = score_and_verdict(all_findings, watchlist_rank=rank)
            scan.verdict = res.verdict
            scan.score = res.score
            scan.alert_tag = res.alert_tag
            new_verdict, new_score = res.verdict, res.score
            dyn_for_bump = dyn_findings

            if new_verdict == "malicious" and job["static_verdict"] != "malicious":
                non_shadow = [f for f in all_findings if not _is_shadow_finding(f)]
                alert = {
                    "pkg_name": job["name"],
                    "pkg_version": job["version"],
                    "ecosystem": job["ecosystem"],
                    "static_verdict": job["static_verdict"],
                    "new_verdict": new_verdict,
                    "new_score": new_score,
                    "n_findings": len(non_shadow),
                    "findings": non_shadow,
                }

        log.info(
            "detonation_done",
            status=det_result.status,
            trace_events=det_result.total_trace_events,
            dyn_findings=len(dyn_findings),
            new_verdict=new_verdict,
            flipped=alert is not None,
        )
        if q is not None:
            detonation_queue.mark_done(s, q, token=job["token"])

    if dyn_for_bump:
        _bump_rulehits_deferred(dyn_for_bump)
    return alert


async def _fetch_and_detonate(adapter, job: dict, archives_out: list):
    """Re-fetch the archive and run the sandbox (the network-bound, timed part).

    Appends to *archives_out* so the caller can clean up even on cancellation."""
    fetched = await adapter.fetch(job["name"], job["version"])
    archives_out.extend(
        list(getattr(fetched, "archives", None) or (fetched if isinstance(fetched, list) else []))
    )
    if not archives_out:
        raise NoFilesError("no_archives")
    arc = next((a for a in archives_out if a.kind == job["archive_kind"]), archives_out[0])
    log.info("detonation_start", archive=arc.kind, name=job["name"], version=job["version"])
    return await get_detonation_client().detonate(
        ecosystem=job["ecosystem"],
        name=job["name"],
        version=job["version"],
        archive_path=str(arc.path),
        archive_kind=arc.kind,
    )


async def _process_detonation(job: dict) -> None:
    adapter = adapter_registry.get(job["ecosystem"])
    if adapter is None:
        _mark_failed(job, f"no adapter for {job['ecosystem']}")
        return

    archives: list = []
    try:
        try:
            det_result = await asyncio.wait_for(
                _fetch_and_detonate(adapter, job, archives),
                timeout=DETONATION_PROCESS_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.warning("det_worker_timeout", name=job["name"], version=job["version"])
            _requeue_or_fail(job, f"timeout_after_{DETONATION_PROCESS_TIMEOUT}s")
            return
        except NoFilesError as e:
            _mark_failed(job, f"no_files: {e}")
            return
        except Exception as e:
            _requeue_or_fail(job, f"fetch_failed: {e}")
            return
        if det_result is None:
            _requeue_or_fail(job, "detonation_unavailable")
            return

        alert = await asyncio.to_thread(_finalize_detonation, job, det_result)
        if alert is not None and discord_notify.is_enabled():
            await asyncio.to_thread(discord_notify.send_dynamic_alert, **alert)
    finally:
        for a in archives:
            try:
                shutil.rmtree(Path(a.path).parent, ignore_errors=True)
            except Exception:
                pass


async def _detonation_loop(worker_id: int, stop_event: asyncio.Event, poll_interval: float) -> None:
    log.info("det_worker_start", worker=worker_id)
    while not stop_event.is_set():
        job: Optional[dict] = None
        with sess.session_scope() as s:
            claimed = detonation_queue.claim_next(s)
            if claimed is not None:
                row, token = claimed
                job = {
                    "id": row.id,
                    "token": token,
                    "scan_id": row.scan_id,
                    "version_id": row.version_id,
                    "ecosystem": row.ecosystem,
                    "name": row.name,
                    "version": row.version,
                    "archive_kind": row.archive_kind,
                    "static_verdict": row.static_verdict,
                }

        if job is None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll_interval)
            except asyncio.TimeoutError:
                pass
            continue

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(dw=worker_id)
        try:
            await _process_detonation(job)
        except Exception as e:
            log.exception("det_worker_error", name=job["name"], error=str(e))
            _requeue_or_fail(job, str(e)[:4000])
        finally:
            structlog.contextvars.clear_contextvars()
    log.info("det_worker_stop", worker=worker_id)


async def run_detonation_pool(
    num_workers: int = 6,
    stop_event: Optional[asyncio.Event] = None,
    poll_interval: float = 1.0,
) -> None:
    stop_event = stop_event or asyncio.Event()
    tasks = [
        asyncio.create_task(_detonation_loop(i, stop_event, poll_interval))
        for i in range(num_workers)
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
