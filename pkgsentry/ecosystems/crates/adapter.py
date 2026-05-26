# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from pkgsentry.adapter import (
    DiscoveredItem,
    EcosystemAdapter,
    FetchResult,
    Finding,
)


class CratesAdapter(EcosystemAdapter):
    ecosystem_id = "crates"
    install_archive_kind = "crate"
    strips_top_dir = True

    async def discover(self) -> AsyncIterator[DiscoveredItem]:
        from pkgsentry.ecosystems.crates.ingest.feeds import poll_feeds_once
        # discover() is for parity — real ingest is scheduler-driven
        yield  # pragma: no cover

    async def fetch(self, name: str, version: str) -> FetchResult:
        from pkgsentry.ecosystems.crates.fetch.download import download_crate
        return await download_crate(name, version)

    async def analyze_install(
        self,
        extracted_root: Path,
        changed_files: set[str] | None = None,
    ) -> list[Finding]:
        from pkgsentry.ecosystems.crates.build_rs import analyze_build_rs
        return analyze_build_rs(extracted_root)

    def schedule_jobs(self, scheduler) -> None:
        from pkgsentry.ecosystems.crates.ingest import feeds, watchlist
        from pkgsentry.ecosystems.crates.ingest import focus as cf
        from pkgsentry.focus import focus_exclusive
        scheduler.add_job(feeds.poll_feeds_once, "interval", seconds=60, id="crates_feeds")
        scheduler.add_job(cf.poll_focus_releases, "interval", seconds=300, id="crates_focus")
        if not focus_exclusive():
            scheduler.add_job(watchlist.refresh_watchlist, "interval", weeks=1, id="crates_watchlist_refresh")

    async def boot(self) -> None:
        from pkgsentry.ecosystems.crates.ingest import feeds, watchlist
        from pkgsentry.ecosystems.crates.ingest import focus as cf
        from pkgsentry.focus import focus_exclusive
        from pkgsentry.logging_setup import get_logger
        from pkgsentry.store import session as sess
        from pkgsentry.store.models import FocusList, Watchlist as WatchlistModel
        from sqlalchemy import select

        if not focus_exclusive():
            with sess.session_scope() as s:
                has_crates_wl = s.scalars(
                    select(WatchlistModel).where(WatchlistModel.ecosystem == "crates").limit(1)
                ).first() is not None
            if not has_crates_wl:
                await watchlist.refresh_watchlist()
                # First run: seed queue with latest version of every watchlist crate.
                await watchlist.poll_watchlist_releases()
            else:
                # Defensive: backfill any watchlist crate missing from scan_queue
                # (catches partial seeds from prior crashed runs, or watchlist
                # expansions like 5K → 10K).
                await watchlist.seed_missing_watchlist()
        else:
            with sess.session_scope() as s:
                has_focus = s.scalars(
                    select(FocusList).where(FocusList.ecosystem == "crates").limit(1)
                ).first() is not None
            if not has_focus:
                get_logger("crates.adapter").warning("focus_exclusive_empty", ecosystem="crates")
        # Focus packages — seed latest versions (both modes).
        await cf.poll_focus_releases()
        # Incremental ingest — fast, catches recent publishes only.
        await feeds.poll_feeds_once()

    def sweep(self) -> None:
        from pkgsentry.ecosystems.crates.fetch.download import sweep_orphans
        sweep_orphans(max_age_seconds=3600.0)

    def backfill(self, days: int) -> int:
        return 0  # crates.io has no cursor API
