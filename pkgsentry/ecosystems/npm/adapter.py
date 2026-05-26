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


class NpmAdapter(EcosystemAdapter):
    ecosystem_id = "npm"
    install_archive_kind = "npm_tarball"
    strips_top_dir = True

    async def discover(self) -> AsyncIterator[DiscoveredItem]:
        yield  # pragma: no cover  -- real ingest is scheduler-driven

    async def fetch(self, name: str, version: str) -> FetchResult:
        from pkgsentry.ecosystems.npm.fetch.download import download_tarball
        return await download_tarball(name, version)

    async def analyze_install(
        self,
        extracted_root: Path,
        changed_files: set[str] | None = None,
    ) -> list[Finding]:
        from pkgsentry.ecosystems.npm.installer import analyze_install_scripts
        return analyze_install_scripts(extracted_root, changed_files=changed_files)

    def schedule_jobs(self, scheduler) -> None:
        from pkgsentry.ecosystems.npm.ingest import cursor, watchlist
        from pkgsentry.ecosystems.npm.ingest import focus as nf
        from pkgsentry.focus import focus_exclusive
        scheduler.add_job(cursor.poll_changes_once, "interval", seconds=60, id="npm_changes")
        scheduler.add_job(nf.poll_focus_releases, "interval", seconds=300, id="npm_focus")
        if not focus_exclusive():
            scheduler.add_job(
                watchlist.refresh_watchlist, "interval", weeks=1, id="npm_watchlist_refresh",
            )

    async def boot(self) -> None:
        from pkgsentry.ecosystems.npm.ingest import cursor, watchlist
        from pkgsentry.ecosystems.npm.ingest import focus as nf
        from pkgsentry.focus import focus_exclusive
        from pkgsentry.logging_setup import get_logger
        from pkgsentry.store import session as sess
        from pkgsentry.store.models import FocusList, Watchlist as WatchlistModel
        from sqlalchemy import select

        if not focus_exclusive():
            with sess.session_scope() as s:
                has_npm_wl = s.scalars(
                    select(WatchlistModel).where(WatchlistModel.ecosystem == "npm").limit(1)
                ).first() is not None
            if not has_npm_wl:
                await watchlist.refresh_watchlist()
                await watchlist.poll_watchlist_releases()
            else:
                await watchlist.seed_missing_watchlist()
        else:
            with sess.session_scope() as s:
                has_focus = s.scalars(
                    select(FocusList).where(FocusList.ecosystem == "npm").limit(1)
                ).first() is not None
            if not has_focus:
                get_logger("npm.adapter").warning("focus_exclusive_empty", ecosystem="npm")
        # Focus packages — seed latest versions (both modes).
        await nf.poll_focus_releases()
        # Incremental discovery — bootstraps the seq cursor on first run.
        await cursor.poll_changes_once()

    def sweep(self) -> None:
        from pkgsentry.ecosystems.npm.fetch.download import sweep_orphans
        sweep_orphans(max_age_seconds=3600.0)

    def backfill(self, days: int) -> int:
        from pkgsentry.ecosystems.npm.ingest.cursor import pull_since_beginning
        return pull_since_beginning(days)
