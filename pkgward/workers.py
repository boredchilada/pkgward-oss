# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
from typing import Optional

import structlog

from pkgward.logging_setup import get_logger
from pkgward.pipeline import process_one as _process_one
from pkgward.queue import claim_next, mark_failed
from pkgward.store import session as sess
from pkgward.store.models import ScanQueue

log = get_logger("workers")

process_one = _process_one

PROCESS_TIMEOUT_SECONDS = 900  # 15 min per package — large wheels/mono-repos take time


def _claim_one() -> Optional[tuple[int, str, str, str]]:
    with sess.session_scope() as s:
        claimed = claim_next(s)
        if claimed is None:
            return None
        return claimed[0].id, claimed[1], claimed[0].name, claimed[0].ecosystem


def _fail_row(queue_id: int, error: str, token: Optional[str]) -> None:
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is not None and row.status not in ("done", "failed"):
            mark_failed(s, row, error, token=token)


async def _worker_loop(worker_id: int, stop_event: asyncio.Event, poll_interval: float) -> None:
    log.info("worker_start", worker=worker_id)
    while not stop_event.is_set():
        queue_id: Optional[int] = None
        claim_token: Optional[str] = None
        name: Optional[str] = None
        ecosystem: Optional[str] = None
        try:
            # to_thread: on a remote-DB worker each claim query costs ~wire-RTT;
            # run synchronously it freezes the event loop for every coroutine
            # (in-flight connects blow their timeouts as ConnectTimeout).
            claimed = await asyncio.to_thread(_claim_one)
            if claimed is not None:
                queue_id, claim_token, name, ecosystem = claimed
        except Exception:
            # A transient DB hiccup during claim must not kill the worker task
            # for the lifetime of the process (run_pool does not restart it) —
            # that would silently shrink capacity one worker at a time. Log and
            # treat as an empty poll; the next loop retries.
            log.exception("claim_error", worker=worker_id)
            queue_id = None

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
                await asyncio.to_thread(
                    _fail_row, queue_id,
                    f"timeout_after_{PROCESS_TIMEOUT_SECONDS}s", claim_token)
            except Exception:
                log.exception("worker_timeout_handler_error")
        except Exception as e:
            log.exception("worker_error", ecosystem=ecosystem, name=name, error=str(e))
            try:
                await asyncio.to_thread(_fail_row, queue_id, str(e)[:4000], claim_token)
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
