# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from pkgsentry.adapter import (
    ArchivePath,
    DiscoveredItem,
    EcosystemAdapter,
    FetchResult,
    Finding,
)


class PyPIAdapter(EcosystemAdapter):
    ecosystem_id = "pypi"
    install_archive_kind = "sdist"
    strips_top_dir = True

    async def discover(self) -> AsyncIterator[DiscoveredItem]:
        from pkgsentry.ecosystems.pypi.ingest.feeds import poll_feeds_once
        for item in await poll_feeds_once():
            yield item

    async def fetch(self, name: str, version: str) -> FetchResult:
        from pkgsentry.ecosystems.pypi.fetch.download import download_all
        return await download_all(name, version)

    async def analyze_install(
        self,
        extracted_root: Path,
        changed_files: set[str] | None = None,
    ) -> list[Finding]:
        from pkgsentry.ecosystems.pypi.installer import analyze_install_scripts
        return analyze_install_scripts(extracted_root)

    def schedule_jobs(self, scheduler) -> None:
        from pkgsentry.ecosystems.pypi.ingest import cursor as cur
        from pkgsentry.ecosystems.pypi.ingest import feeds as feed_mod
        from pkgsentry.ecosystems.pypi.ingest import watchlist as wl
        from pkgsentry.ecosystems.pypi.ingest import focus as pf
        from pkgsentry.focus import focus_exclusive
        scheduler.add_job(feed_mod.poll_feeds_once, "interval", seconds=60, id="pypi_feeds")
        scheduler.add_job(cur.pull_since, "interval", seconds=120, id="pypi_cursor")
        scheduler.add_job(pf.poll_focus_releases, "interval", seconds=300, id="pypi_focus")
        if not focus_exclusive():
            scheduler.add_job(wl.refresh_watchlist, "interval", weeks=1, id="pypi_watchlist_refresh")

    async def boot(self) -> None:
        from pkgsentry.ecosystems.pypi.ingest import watchlist as wl
        from pkgsentry.ecosystems.pypi.ingest import feeds as feed_mod
        from pkgsentry.ecosystems.pypi.ingest import cursor as cur
        from pkgsentry.ecosystems.pypi.ingest import focus as pf
        from pkgsentry.focus import focus_exclusive
        from pkgsentry.logging_setup import get_logger
        from pkgsentry.store import session as sess
        from pkgsentry.store.models import FocusList, Watchlist
        from sqlalchemy import select
        import asyncio

        if not focus_exclusive():
            with sess.session_scope() as s:
                empty = s.scalars(select(Watchlist).limit(1)).first() is None
            if empty:
                await wl.refresh_watchlist()
                # First run: seed queue with latest version of every watchlist package.
                await wl.poll_watchlist_releases()
        else:
            with sess.session_scope() as s:
                has_focus = s.scalars(
                    select(FocusList).where(FocusList.ecosystem == "pypi").limit(1)
                ).first() is not None
            if not has_focus:
                get_logger("pypi.adapter").warning("focus_exclusive_empty", ecosystem="pypi")
        # Focus packages — seed latest/pinned versions (both modes).
        await pf.poll_focus_releases()
        # Incremental ingest — fast, catches recent publishes only.
        await feed_mod.poll_feeds_once()
        await asyncio.to_thread(cur.pull_since)

    def sweep(self) -> None:
        from pkgsentry.ecosystems.pypi.fetch.download import sweep_orphans
        sweep_orphans(max_age_seconds=3600.0)

    def backfill(self, days: int) -> int:
        from pkgsentry.ecosystems.pypi.ingest import cursor as cur
        max_iter = max(1, days * 24 * 60)
        total = 0
        for _ in range(max_iter):
            n = cur.pull_since(max_items=5000)
            total += n
            if n == 0:
                break
        return total
