# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import os
import signal
import time
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from pkgsentry import intel
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Finding, Package, Scan, Version

# Force PyPI adapter registration on import.
import pkgsentry.ecosystems  # noqa: F401  -- triggers auto-registration

log = get_logger("runtime")


def sync_focus_file(focus_file: str) -> None:
    """Authoritatively sync a combined focus file into FocusList and enqueue any
    pinned versions. Used by `run -f <file>` (focused mode). Logs and returns on
    a missing/malformed file rather than crashing the scanner."""
    from pathlib import Path
    from pkgsentry import focus as focus_mod
    try:
        text = Path(focus_file).read_text(encoding="utf-8")
    except FileNotFoundError:
        log.error("focus_file_missing", path=focus_file)
        return
    try:
        with sess.session_scope() as s:
            sections = focus_mod.apply_focus_file(s, text)
            pinned = 0
            for eco, entries in sections.items():
                for e in entries:
                    if e.pinned_version and enqueue(
                        s, ecosystem=eco, name=e.name,
                        version=e.pinned_version, priority="high",
                    ):
                        pinned += 1
        log.info(
            "focus_file_loaded",
            path=focus_file,
            ecosystems={k: len(v) for k, v in sections.items()},
            pinned_enqueued=pinned,
        )
    except Exception as e:
        log.error("focus_file_load_failed", path=focus_file, error=str(e))


def enqueue_one(ecosystem: str, name: str, version: str, priority: str = "normal") -> None:
    with sess.session_scope() as s:
        enqueue(
            s, ecosystem=ecosystem, name=name, version=version,
            priority=priority, allow_rescan=True,
        )


def backfill_days(days: int = 1, ecosystem: str = "pypi") -> None:
    from pkgsentry.adapter import adapter_registry
    sess.init_db()
    adapter = adapter_registry.get(ecosystem)
    if adapter is None:
        log.error("backfill_no_adapter", ecosystem=ecosystem)
        return
    total = adapter.backfill(days)
    log.info("backfill_done", ecosystem=ecosystem, enqueued=total)


def show_findings(ecosystem: str, name: str, version: str) -> None:
    with sess.session_scope() as s:
        pkg = s.scalars(select(Package).where(Package.ecosystem == ecosystem, Package.name == name)).first()
        if pkg is None:
            print(f"no package: {ecosystem}:{name}")
            return
        ver = s.scalars(select(Version).where(
            Version.ecosystem == ecosystem,
            Version.package_id == pkg.id,
            Version.version == version,
        )).first()
        if ver is None:
            print(f"no version: {ecosystem}:{name}=={version}")
            return
        scan = s.scalars(
            select(Scan).where(Scan.version_id == ver.id).order_by(Scan.started_at.desc()).limit(1)
        ).first()
        if scan is None:
            print(f"no scan yet for {name}=={version}")
            return
        print(f"=== {ecosystem}:{name}=={version} ===")
        print(f"verdict={scan.verdict} score={scan.score} alert_tag={scan.alert_tag}")
        print(f"started={scan.started_at} finished={scan.finished_at}")
        if ver.author:
            print(f"author={ver.author} email={ver.author_email or '-'}")
        if ver.summary:
            print(f"summary={ver.summary}")
        if ver.downloads_last_30d:
            print(f"downloads_last_30d={ver.downloads_last_30d}")
        if ver.requires_dist:
            head = ver.requires_dist[:5]
            tail = " ..." if len(ver.requires_dist) > 5 else ""
            print(f"requires_dist={head}{tail}")
        findings = s.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        if not findings:
            print("(no findings)")
            return
        for f in findings:
            loc = f.file + (f":{f.line}" if f.line else "")
            print(f"  [{f.severity}/{f.confidence}] {f.rule_id} {loc} :: {f.evidence}")


async def _async_run(workers: int, duration: int, focus_file: Optional[str] = None) -> None:
    from pkgsentry.adapter import adapter_registry
    from pkgsentry.workers import run_pool

    # Focused mode (`run -f <file>`): force exclusive ingest BEFORE adapters read
    # focus_exclusive() in schedule_jobs/boot, then sync the combined file.
    if focus_file:
        os.environ["PKGSENTRY_FOCUS_EXCLUSIVE"] = "1"

    sess.init_db()
    intel.load()

    if focus_file:
        sync_focus_file(focus_file)

    stop_event = asyncio.Event()

    def _request_stop(*_):
        log.info("stop_requested")
        stop_event.set()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, _request_stop)
        loop.add_signal_handler(signal.SIGTERM, _request_stop)
    except (NotImplementedError, AttributeError):
        pass

    ingest_enabled = os.environ.get("SCANNER_INGEST", "1") != "0"

    scheduler = AsyncIOScheduler()

    # Each ecosystem adapter registers its own jobs
    if ingest_enabled:
        for adapter in adapter_registry.values():
            adapter.schedule_jobs(scheduler)

    # Ecosystem-agnostic sweep jobs
    def _sweep_all():
        for adapter in adapter_registry.values():
            try:
                adapter.sweep()
            except Exception as e:
                log.warning("sweep_error", ecosystem=adapter.ecosystem_id, error=str(e))

    scheduler.add_job(_sweep_all, "interval", minutes=15, id="sweep_all")

    def _sweep_stale_job():
        from pkgsentry.queue import sweep_stale_claims
        with sess.session_scope() as s:
            n = sweep_stale_claims(s)
            if n:
                log.info("stale_claims_swept", count=n)

    scheduler.add_job(_sweep_stale_job, "interval", minutes=2, id="claim_sweep")
    scheduler.start()

    # Start workers first so the queue drains while boot polls watchlists.
    pool_task = asyncio.create_task(run_pool(num_workers=workers, stop_event=stop_event, poll_interval=1.0))

    # Boot each ecosystem (watchlist refresh + initial poll — can be slow)
    if ingest_enabled:
        for adapter in adapter_registry.values():
            try:
                await adapter.boot()
            except Exception as e:
                log.warning("boot_failed", ecosystem=adapter.ecosystem_id, error=str(e))
    else:
        log.info("ingest_disabled", reason="SCANNER_INGEST=0")

    try:
        if duration > 0:
            await asyncio.wait_for(stop_event.wait(), timeout=duration)
        else:
            await stop_event.wait()
    except (asyncio.TimeoutError, KeyboardInterrupt):
        stop_event.set()
    finally:
        scheduler.shutdown(wait=False)
        await pool_task


def run_forever(workers: int = 4, duration: int = 0, focus_file: Optional[str] = None) -> None:
    asyncio.run(_async_run(workers=workers, duration=duration, focus_file=focus_file))
