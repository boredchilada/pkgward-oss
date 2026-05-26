# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import pytest
from sqlalchemy import select

from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue


@pytest.mark.asyncio
async def test_pool_drains_in_priority_order(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'w.db'}")
    sess.reset_engine()
    sess.init_db()

    processed: list[str] = []

    async def fake_process(queue_id, claim_token=None):
        with sess.session_scope() as s:
            row = s.get(ScanQueue, queue_id)
            if row is not None:
                processed.append(f"{row.priority}:{row.name}")
                row.status = "done"

    from pkgsentry import workers
    monkeypatch.setattr(workers, "process_one", fake_process)

    with sess.session_scope() as s:
        for n in ("n1", "n2"):
            s.add(ScanQueue(ecosystem="pypi", name=n, version="1", priority="normal", status="pending"))
        for n in ("h1", "h2"):
            s.add(ScanQueue(ecosystem="pypi", name=n, version="1", priority="high", status="pending"))

    stop = asyncio.Event()
    task = asyncio.create_task(workers.run_pool(num_workers=2, stop_event=stop, poll_interval=0.01))
    for _ in range(200):
        await asyncio.sleep(0.02)
        with sess.session_scope() as s:
            remaining = s.scalars(select(ScanQueue).where(ScanQueue.status == "pending")).all()
            if not remaining:
                break
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)

    assert {processed[0], processed[1]} == {"high:h1", "high:h2"}
    assert set(processed[2:]) == {"normal:n1", "normal:n2"}
