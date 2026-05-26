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


class GoModAdapter(EcosystemAdapter):
    ecosystem_id = "gomod"
    install_archive_kind = "gomod_zip"
    strips_top_dir = True

    async def discover(self) -> AsyncIterator[DiscoveredItem]:
        yield  # pragma: no cover

    async def fetch(self, name: str, version: str) -> FetchResult:
        from pkgsentry.ecosystems.gomod.fetch.download import download_module
        return await download_module(name, version)

    async def analyze_install(
        self,
        extracted_root: Path,
        changed_files: set[str] | None = None,
    ) -> list[Finding]:
        from pkgsentry.ecosystems.gomod.go_directives import analyze_go_directives
        return analyze_go_directives(extracted_root, changed_files=changed_files)

    def schedule_jobs(self, scheduler) -> None:
        from pkgsentry.ecosystems.gomod.ingest import cursor, watchlist
        from pkgsentry.ecosystems.gomod.ingest import focus as gf
        from pkgsentry.focus import focus_exclusive
        scheduler.add_job(
            cursor.poll_index_once, "interval", seconds=60, id="gomod_index",
        )
        scheduler.add_job(
            gf.poll_focus_releases, "interval", seconds=300, id="gomod_focus",
        )
        if not focus_exclusive():
            scheduler.add_job(
                watchlist.refresh_watchlist, "interval", weeks=1, id="gomod_watchlist_refresh",
            )

    async def boot(self) -> None:
        from pkgsentry.ecosystems.gomod.ingest import cursor, watchlist
        from pkgsentry.ecosystems.gomod.ingest import focus as gf
        from pkgsentry.focus import focus_exclusive
        from pkgsentry.logging_setup import get_logger
        from pkgsentry.store import session as sess
        from pkgsentry.store.models import FocusList, Watchlist as WatchlistModel
        from sqlalchemy import select

        if not focus_exclusive():
            with sess.session_scope() as s:
                has_gomod_wl = s.scalars(
                    select(WatchlistModel).where(WatchlistModel.ecosystem == "gomod").limit(1)
                ).first() is not None
            if not has_gomod_wl:
                await watchlist.refresh_watchlist()
                await watchlist.seed_watchlist_queue()
            else:
                await watchlist.seed_missing_watchlist()
        else:
            with sess.session_scope() as s:
                has_focus = s.scalars(
                    select(FocusList).where(FocusList.ecosystem == "gomod").limit(1)
                ).first() is not None
            if not has_focus:
                get_logger("gomod.adapter").warning("focus_exclusive_empty", ecosystem="gomod")
        # Focus packages — seed latest versions (both modes).
        await gf.poll_focus_releases()
        await cursor.poll_index_once()

    def sweep(self) -> None:
        from pkgsentry.ecosystems.gomod.fetch.download import sweep_orphans
        sweep_orphans(max_age_seconds=3600.0)

    def backfill(self, days: int) -> int:
        from pkgsentry.ecosystems.gomod.ingest.cursor import pull_since_beginning
        return pull_since_beginning(days)
