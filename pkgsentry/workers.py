# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
from typing import Optional

import structlog

from pkgsentry.logging_setup import get_logger
from pkgsentry.pipeline import process_one as _process_one
from pkgsentry.queue import claim_next, mark_failed
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue

log = get_logger("workers")

process_one = _process_one

PROCESS_TIMEOUT_SECONDS = 900  # 15 min per package — large wheels/mono-repos take time


async def _worker_loop(worker_id: int, stop_event: asyncio.Event, poll_interval: float) -> None:
    log.info("worker_start", worker=worker_id)
    while not stop_event.is_set():
        queue_id: Optional[int] = None
        claim_token: Optional[str] = None
        name: Optional[str] = None
        ecosystem: Optional[str] = None
        with sess.session_scope() as s:
            claimed = claim_next(s)
            if claimed is not None:
                queue_id = claimed[0].id
                claim_token = claimed[1]
                name = claimed[0].name
                ecosystem = claimed[0].ecosystem

        if queue_id is None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll_interval)
            except asyncio.TimeoutError:
                pass
            continue

        # Bind worker + package context to all log lines during this scan
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(w=worker_id)

        try:
            await asyncio.wait_for(
                process_one(queue_id, claim_token),
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            log.warning("worker_timeout", queue_id=queue_id,
                        ecosystem=ecosystem, name=name,
                        timeout=PROCESS_TIMEOUT_SECONDS)
            try:
                with sess.session_scope() as s:
                    row = s.get(ScanQueue, queue_id)
                    if row is not None and row.status not in ("done", "failed"):
                        mark_failed(s, row, f"timeout_after_{PROCESS_TIMEOUT_SECONDS}s",
                                    token=claim_token)
            except Exception:
                log.exception("worker_timeout_handler_error")
        except Exception as e:
            log.exception("worker_error", ecosystem=ecosystem, name=name, error=str(e))
            try:
                with sess.session_scope() as s:
                    row = s.get(ScanQueue, queue_id)
                    if row is not None and row.status not in ("done", "failed"):
                        mark_failed(s, row, str(e)[:4000], token=claim_token)
            except Exception:
                log.exception("worker_fail_handler_error")
        finally:
            structlog.contextvars.clear_contextvars()
    log.info("worker_stop", worker=worker_id)


async def run_pool(
    num_workers: int = 4,
    stop_event: Optional[asyncio.Event] = None,
    poll_interval: float = 1.0,
) -> None:
    stop_event = stop_event or asyncio.Event()
    tasks = [
        asyncio.create_task(_worker_loop(i, stop_event, poll_interval))
        for i in range(num_workers)
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
