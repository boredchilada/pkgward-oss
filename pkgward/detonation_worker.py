# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import hashlib
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy import select

from pkgward import detonation_queue, detonation_staging, vault
from pkgward.adapter import ArchivePath, Finding, NoFilesError, adapter_registry
from pkgward.detect.score import _is_shadow_finding, score_and_verdict
from pkgward.detonate.client import get_client as get_detonation_client
from pkgward.logging_setup import get_logger
from pkgward.notify import discord as discord_notify
from pkgward.pipeline import _strip_nul
from pkgward.pipeline import (
    _bump_rulehits_deferred,
    _is_watchlist,
    _persist_findings,
)
from pkgward.store import session as sess
from pkgward.store.models import (
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
        # Count a real detonation FAILURE (not a claim) against the retry budget,
        # so claim races / stale-sweeps from worker deaths don't burn it.
        q.attempts += 1
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
        if q is None or q.status != "claimed" or q.claim_token != job["token"]:
            # A stale-claim sweep reassigned this job to another worker while this
            # detonation ran. Bail before writing a duplicate Detonation row,
            # re-scoring, or firing a second flip-alert.
            return None
        scan = s.get(Scan, job["scan_id"])
        if scan is None:
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
            # binary + detail are package-controlled (traced exec paths/argv, syscall
            # args). A single NUL byte in either fails the JSONB/TEXT write and would
            # roll back the whole finalize txn — silently dropping the dynamic verdict
            # + flip-alert. Strip NUL like the static-scan persistence path does.
            s.add(TraceEvent(
                detonation_id=det_row.id,
                phase=evt.get("phase", "install"),
                category=evt.get("category", "unknown"),
                operation=evt.get("operation", "unknown"),
                pid=evt.get("pid"),
                binary=_strip_nul(evt.get("binary")),
                detail=_strip_nul(evt.get("detail") or {}),
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
            # Vendor self-download recognition: if the static scan found a checksum-
            # verified prebuilt-binary download from host H (the legit native-wrapper
            # pattern), an install-time connect to H is that same self-download, not
            # exfil — drop the dyn_install_exfil so it doesn't chain to malicious.
            vhosts = _verified_download_hosts(static_findings)
            if vhosts:
                dyn_findings = [f for f in dyn_findings if not _is_self_download_exfil(f, vhosts)]
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
                from pkgward.enrich import publisher as _publisher
                alert = {
                    "pkg_name": job["name"],
                    "pkg_version": job["version"],
                    "ecosystem": job["ecosystem"],
                    "static_verdict": job["static_verdict"],
                    "new_verdict": new_verdict,
                    "new_score": new_score,
                    "n_findings": len(non_shadow),
                    "findings": non_shadow,
                    "publisher": _publisher.from_scan(scan.id),
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


_EXFIL_HOST_RE = re.compile(r"phase:\s*([A-Za-z0-9.\-]+)")


def _registrable(host: str) -> str:
    p = host.lower().strip(". ").split(".")
    return ".".join(p[-2:]) if len(p) >= 2 else host.lower()


def _verified_download_hosts(findings: list) -> set:
    """Registrable domains a package downloads a CHECKSUM-VERIFIED prebuilt binary
    from (the legit native-wrapper pattern). installer.npm_install_remote_binary_drop
    records these as 'hosts: <h>, ...' only when checksum verification was present."""
    out: set = set()
    for f in findings:
        ev = f.evidence or ""
        if (f.rule_id == "installer.npm_install_remote_binary_drop"
                and "checksum-verified" in ev and "hosts:" in ev):
            for h in ev.split("hosts:", 1)[1].split(","):
                h = h.strip()
                if h:
                    out.add(_registrable(h))
    return out


def _is_self_download_exfil(f, vhosts: set) -> bool:
    """A dyn_install_exfil whose connect host is a verified self-download host — the
    legit binary fetch, not exfil; drop it so it doesn't chain to malicious."""
    if f.rule_id != "dyn_install_exfil":
        return False
    m = _EXFIL_HOST_RE.search(f.evidence or "")
    return bool(m) and _registrable(m.group(1)) in vhosts


def _stage_from_vault(job: dict) -> Optional[ArchivePath]:
    """Stage the exact scanned bytes from the vault as an archive for detonation.

    Returns an ArchivePath under the host-shared staging dir (/tmp/pkgward, the only
    dir bind-mounted into both the scanner container and the detonation service host so
    the svc can read the archive bytes), or None if the
    package isn't vaulted. This is preferred over re-fetching: a malicious version is
    often yanked from the registry before async detonation runs, so a re-fetch gets a
    takedown placeholder instead of the payload we actually scanned."""
    res = vault.read_archive(job["ecosystem"], job["name"], job["version"])
    if res is None:
        return None
    data, inner = res
    # Stage through the shared helper so the dir/file carry the cross-uid bind-mount
    # permissions the rootless detonation service needs (see detonation_staging).
    dest = detonation_staging.stage_bytes(data, inner, prefix="vault-")
    return ArchivePath(path=dest, kind=job["archive_kind"], sha256=hashlib.sha256(data).hexdigest())


async def _fetch_and_detonate(adapter, job: dict, archives_out: list):
    """Detonate the package. Prefer the frozen vault copy of the exact scanned bytes;
    fall back to a re-fetch only when the package isn't vaulted.

    Appends to *archives_out* so the caller can clean up even on cancellation."""
    arc = await asyncio.to_thread(_stage_from_vault, job)
    if arc is not None:
        archives_out.append(arc)
        log.info("detonation_archive_source", source="vault", name=job["name"], version=job["version"])
    else:
        fetched = await adapter.fetch(job["name"], job["version"])
        archives_out.extend(
            list(getattr(fetched, "archives", None) or (fetched if isinstance(fetched, list) else []))
        )
        if not archives_out:
            raise NoFilesError("no_archives")
        arc = next((a for a in archives_out if a.kind == job["archive_kind"]), archives_out[0])
        log.info("detonation_archive_source", source="refetch", name=job["name"], version=job["version"])
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
        await asyncio.to_thread(_mark_failed, job, f"no adapter for {job['ecosystem']}")
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
            await asyncio.to_thread(_requeue_or_fail, job, f"timeout_after_{DETONATION_PROCESS_TIMEOUT}s")
            return
        except NoFilesError as e:
            # Archive unavailability is frequently transient (registry yanked the
            # file, mirror lag, a delete-then-restore) — retry within the bounded
            # budget rather than permanently failing a malicious-at-scan package.
            await asyncio.to_thread(_requeue_or_fail, job, f"no_files: {e}")
            return
        except Exception as e:
            await asyncio.to_thread(_requeue_or_fail, job, f"fetch_failed: {e}")
            return
        if det_result is None:
            await asyncio.to_thread(_requeue_or_fail, job, "detonation_unavailable")
            return
        if det_result.status == "error":
            # The service returns HTTP 200 with status="error" on a sandbox/setup/
            # install failure (including the empty-archive case). Finalizing it would
            # persist an empty detonation and mark the job done — silently discarding
            # any behaviour-only malicious verdict. Requeue within the bounded budget
            # instead of treating an errored detonation as a clean one.
            await asyncio.to_thread(_requeue_or_fail, job, "detonation_service_error")
            return

        alert = await asyncio.to_thread(_finalize_detonation, job, det_result)
        if alert is not None and discord_notify.is_enabled():
            try:
                from pkgward.enrich import downloads as _downloads
                alert["downloads_weekly"] = await asyncio.to_thread(
                    _downloads.enrich, job["ecosystem"], job["name"])
            except Exception:
                pass
            await asyncio.to_thread(discord_notify.send_dynamic_alert, **alert)
    finally:
        def _cleanup() -> None:
            for a in archives:
                try:
                    shutil.rmtree(Path(a.path).parent, ignore_errors=True)
                except Exception:
                    pass
        await asyncio.to_thread(_cleanup)


def _claim_job() -> Optional[dict]:
    with sess.session_scope() as s:
        claimed = detonation_queue.claim_next(s)
        if claimed is None:
            return None
        row, token = claimed
        return {
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


async def _detonation_loop(worker_id: int, stop_event: asyncio.Event, poll_interval: float) -> None:
    log.info("det_worker_start", worker=worker_id)
    while not stop_event.is_set():
        # to_thread: a sync claim on a remote-DB node blocks the event loop
        # for ~wire-RTT per query (see workers._worker_loop).
        job: Optional[dict] = await asyncio.to_thread(_claim_job)

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
            await asyncio.to_thread(_requeue_or_fail, job, str(e)[:4000])
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
