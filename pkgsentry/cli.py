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
    focus: str = typer.Option(
        None, "--focus", "-f",
        help="Focused mode: load this combined focus file ([pypi]/[crates]/[gomod] "
             "sections) and scan ONLY focus packages. Omit for normal mode.",
    ),
) -> None:
    """Start ingest + worker pool + scheduler.

    With -f/--focus the scanner runs in exclusive focused mode against the given
    combined file (authoritative — the file defines the focus list). Without it,
    the usual watchlist + brand-new ingest runs.
    """
    from pkgsentry.runtime import run_forever  # late import to keep CLI fast
    run_forever(workers=workers, duration=duration, focus_file=focus)


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


focus_app = typer.Typer(
    no_args_is_help=True,
    help="Manage focus packages — a per-ecosystem personal watchlist.",
)
app.add_typer(focus_app, name="focus")

_ECOSYSTEMS = ("pypi", "crates", "gomod", "npm")


def _check_ecosystem(ecosystem: str) -> None:
    if ecosystem not in _ECOSYSTEMS:
        raise typer.BadParameter(f"ecosystem must be one of {_ECOSYSTEMS}")


@focus_app.command("load")
def focus_load_cmd(
    file: str = typer.Argument(..., help="Path to focus list file."),
    ecosystem: str = typer.Option(
        None, "--ecosystem", "-e",
        help="pypi|crates|gomod for a flat file. Omit for a combined file with "
             "[pypi]/[crates]/[gomod] sections (covers all ecosystems at once).",
    ),
    enqueue_pinned: bool = typer.Option(
        True, "--enqueue-pinned/--no-enqueue-pinned",
        help="Enqueue any pinned versions for immediate scanning.",
    ),
) -> None:
    """Load focus packages from a file.

    Flat file with -e: additive upsert for that ecosystem (one `name` or
    `name==version` per line). Combined file without -e: each `[ecosystem]`
    section authoritatively replaces that ecosystem's focus list.
    """
    from pathlib import Path
    from pkgsentry import focus
    from pkgsentry.queue import enqueue

    sess.init_db()
    text = Path(file).read_text(encoding="utf-8")

    if ecosystem:
        _check_ecosystem(ecosystem)
        sections = {ecosystem: focus.parse_focus_file(text, ecosystem)}
        authoritative = False  # flat single-ecosystem load is additive
    else:
        sections = focus.parse_combined_focus_file(text)
        if not sections:
            raise typer.BadParameter(
                "no [ecosystem] sections found — pass -e for a flat single-ecosystem file."
            )
        authoritative = True  # combined file is the source of truth

    total = 0
    enq = 0
    with sess.session_scope() as s:
        for eco, entries in sections.items():
            if authoritative:
                focus.sync_focus(s, eco, entries)
            else:
                focus.upsert_focus(s, eco, entries)
            total += len(entries)
            if enqueue_pinned:
                for e in entries:
                    if e.pinned_version and enqueue(
                        s, ecosystem=eco, name=e.name,
                        version=e.pinned_version, priority="high",
                    ):
                        enq += 1
    scope = ", ".join(sorted(sections)) if sections else "—"
    typer.echo(f"loaded {total} focus entries ({scope}) — {enq} pinned versions enqueued")


@focus_app.command("list")
def focus_list_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
) -> None:
    """List focus entries (warns if exclusive mode is on but the list is empty)."""
    from sqlalchemy import select
    from pkgsentry.store.models import FocusList
    from pkgsentry.focus import focus_exclusive

    sess.init_db()
    with sess.session_scope() as s:
        q = select(FocusList)
        if ecosystem:
            q = q.where(FocusList.ecosystem == ecosystem)
        rows = s.scalars(q.order_by(FocusList.ecosystem, FocusList.name)).all()
        for r in rows:
            typer.echo(f"{r.ecosystem}\t{r.name}\t{r.pinned_version or '-'}")
        typer.echo(f"# {len(rows)} entries")
        if focus_exclusive() and not rows:
            typer.echo(
                "WARNING: PKGSENTRY_FOCUS_EXCLUSIVE=1 but focus list is empty — the scanner will idle."
            )


@focus_app.command("clear")
def focus_clear_cmd(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e", help="Limit to one ecosystem (default: all)."),
) -> None:
    """Remove focus entries (all, or one ecosystem)."""
    from pkgsentry.focus import clear_focus

    sess.init_db()
    with sess.session_scope() as s:
        n = clear_focus(s, ecosystem)
    typer.echo(f"cleared {n} entries")
