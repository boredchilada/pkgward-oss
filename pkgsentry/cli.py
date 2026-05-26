# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer

from pkgsentry.logging_setup import configure_logging, get_logger
from pkgsentry.store import session as sess

app = typer.Typer(no_args_is_help=True, help="PyPI scanner — malware detection pipeline.")
log = get_logger("cli")


@app.callback()
def _root(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    configure_logging(level="DEBUG" if verbose else "INFO")


@app.command("init-db")
def init_db_cmd() -> None:
    """Create all tables."""
    sess.init_db()
    typer.echo("ok")


@app.command("run")
def run_cmd(
    workers: int = typer.Option(4, "--workers", "-w"),
    duration: int = typer.Option(0, "--duration", help="Stop after N seconds (0 = forever)."),
) -> None:
    """Start ingest + worker pool + scheduler."""
    from pkgsentry.runtime import run_forever  # late import to keep CLI fast
    run_forever(workers=workers, duration=duration)


@app.command("backfill")
def backfill_cmd(days: int = typer.Option(1, "--days")) -> None:
    """Enqueue everything from PyPI changelog over the last N days."""
    from pkgsentry.runtime import backfill_days
    backfill_days(days=days)


@app.command("rescan")
def rescan_cmd(
    package: str = typer.Option(..., "--package"),
    version: str = typer.Option(..., "--version"),
    ecosystem: str = typer.Option("pypi", "--ecosystem"),
) -> None:
    """Re-enqueue a single (ecosystem, package, version)."""
    from pkgsentry.runtime import enqueue_one
    enqueue_one(ecosystem=ecosystem, name=package, version=version, priority="high")
    typer.echo("enqueued")


@app.command("scan-watchlist")
def scan_watchlist_cmd(
    limit: int = typer.Option(0, "--limit", "-n", help="Max packages (0 = all)."),
    concurrency: int = typer.Option(20, "--concurrency", "-c"),
) -> None:
    """Enqueue all watchlist packages for scanning (first-pass baseline)."""
    import asyncio as _aio
    from pkgsentry.ecosystems.pypi.ingest import watchlist as wl
    sess.init_db()

    async def _go():
        from pkgsentry.store.models import Watchlist
        from sqlalchemy import select
        with sess.session_scope() as s:
            empty = s.scalars(select(Watchlist).limit(1)).first() is None
        if empty:
            typer.echo("watchlist empty — refreshing from PyPI...")
            await wl.refresh_watchlist()
        n = await wl.poll_watchlist_releases(
            limit=limit or None, concurrency=concurrency,
        )
        typer.echo(f"enqueued {n} packages")

    _aio.run(_go())


@app.command("show")
def show_cmd(
    package: str = typer.Option(..., "--package"),
    version: str = typer.Option(..., "--version"),
    ecosystem: str = typer.Option("pypi", "--ecosystem"),
) -> None:
    """Print latest scan + findings for a package version."""
    from pkgsentry.runtime import show_findings
    show_findings(ecosystem=ecosystem, name=package, version=version)
