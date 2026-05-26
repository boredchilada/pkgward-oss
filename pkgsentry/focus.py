# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focus packages — an operator-supplied per-ecosystem personal watchlist.

Shared, network-free logic (DB + env + parsing), mirroring ``queue.py``'s role.
Per-ecosystem latest-version resolution lives in each
``ecosystems/<eco>/ingest/focus.py``.

Mode is governed by ``PKGSENTRY_FOCUS_EXCLUSIVE``:
  "0" (default) — additive: focus packages are scanned at high priority in
                  addition to the watchlist + brand-new gates.
  "1"           — exclusive: only focus packages are ingested; the watchlist /
                  brand-new gates and watchlist refresh/seed jobs are skipped.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from pkgsentry.store.models import FocusList

# Ecosystems whose names match case-insensitively, matching is_watchlist().
# npm: the registry lowercases new package names (legacy mixed-case exists).
_CASE_INSENSITIVE = {"gomod", "npm"}


def focus_exclusive() -> bool:
    """True when PKGSENTRY_FOCUS_EXCLUSIVE=1 (scan only focus packages)."""
    return os.environ.get("PKGSENTRY_FOCUS_EXCLUSIVE", "0") == "1"


def _key(name: str, ecosystem: str) -> str:
    return name.lower() if ecosystem in _CASE_INSENSITIVE else name


def load_focus_names(session: Session, ecosystem: str) -> set[str]:
    """Preload the focus name set for an ecosystem (small, operator-sized).

    Call once per poll and use :func:`on_focus` for in-memory membership —
    avoids a per-item SELECT in the high-volume feeds (critical in exclusive
    mode, which gates every upload). gomod names are lowercased.
    """
    rows = session.scalars(
        select(FocusList.name).where(FocusList.ecosystem == ecosystem)
    ).all()
    return {_key(n, ecosystem) for n in rows}


def on_focus(name: str, focus_names: set[str], ecosystem: str) -> bool:
    """In-memory membership against a set from :func:`load_focus_names`."""
    return _key(name, ecosystem) in focus_names


def is_focus(session: Session, ecosystem: str, name: str) -> bool:
    """Single-item DB check (CLI / tests). gomod is case-insensitive."""
    if ecosystem in _CASE_INSENSITIVE:
        cond = func.lower(FocusList.name) == name.lower()
    else:
        cond = FocusList.name == name
    return (
        session.scalars(
            select(FocusList.id)
            .where(FocusList.ecosystem == ecosystem, cond)
            .limit(1)
        ).first()
        is not None
    )


def gate_decision(
    *,
    on_focus: bool,
    on_watchlist: bool,
    brand_new: bool,
    exclusive: bool,
) -> Optional[str]:
    """Central enqueue gate. Returns the priority, or None to skip.

    Keeps the per-consumer edits DRY: exclusive mode admits only focus packages
    (high); additive mode admits focus/watchlist (high) or brand-new (normal).
    """
    if exclusive:
        return "high" if on_focus else None
    if on_focus or on_watchlist:
        return "high"
    if brand_new:
        return "normal"
    return None


@dataclass
class FocusEntry:
    name: str
    pinned_version: Optional[str] = None


# A package name ends at the first specifier operator or whitespace.
_NAME_VERSION_SPLIT = re.compile(r"[<>=~!^,\s]")


def _floor_version(expr: str) -> Optional[str]:
    """Extract a single concrete version to scan once from a version expression
    in any common form (``==1.2.3``, ``>=1.2.3``, ``~=1.2``, ``^1.0``,
    ``>=2.0,<3.0``, ``v1.2.3``). Uses the lower bound of a range. Returns None
    when there's no usable concrete version (empty or a wildcard)."""
    expr = expr.split(",", 1)[0].strip()          # lower bound of any range
    ver = expr.strip("<>=~!^ \t")                  # drop specifier operators
    if not ver or "*" in ver:
        return None
    return ver


def parse_focus_file(text: str, ecosystem: str) -> list[FocusEntry]:
    """Parse a focus list (one entry per line; '#' comments and blanks ignored).

    Lenient — an entry is a package NAME optionally followed by a version in any
    common dependency-file form: bare ``name``, ``name==1.2.3``, ``name>=1.2.3``,
    ``name~=1.2``, ``name^1.0`` (crates), ``name v1.2.3`` (gomod). The NAME is
    what's monitored — every new release of it is scanned. Any version present is
    treated as "the version you're running" and scanned once at load (a range's
    lower bound is used). This lets operators paste requirements.txt / go.mod /
    Cargo lines directly. Names are stored verbatim (gomod matched
    case-insensitively elsewhere); nothing is rejected.
    """
    out: list[FocusEntry] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ecosystem == "gomod":
            parts = line.split(None, 1)
            name = parts[0]
            ver = _floor_version(parts[1]) if len(parts) > 1 else None
        else:
            m = _NAME_VERSION_SPLIT.search(line)
            if m:
                name = line[: m.start()].strip()
                ver = _floor_version(line[m.start():])
            else:
                name, ver = line, None
        if name:
            out.append(FocusEntry(name=name, pinned_version=ver))
    return out


def upsert_focus(session: Session, ecosystem: str, entries: list[FocusEntry]) -> int:
    """Insert/update FocusList rows for an ecosystem. Returns rows written.
    Idempotent on (ecosystem, name); updates pinned_version in place. Does not
    enqueue — the CLI enqueues pinned versions separately via queue.enqueue().
    """
    written = 0
    for e in entries:
        existing = session.scalars(
            select(FocusList).where(
                FocusList.ecosystem == ecosystem, FocusList.name == e.name
            )
        ).first()
        if existing is None:
            session.add(
                FocusList(
                    ecosystem=ecosystem,
                    name=e.name,
                    pinned_version=e.pinned_version,
                )
            )
        else:
            existing.pinned_version = e.pinned_version
        written += 1
    session.flush()
    return written


def clear_focus(session: Session, ecosystem: Optional[str] = None) -> int:
    """Delete focus entries (all, or one ecosystem). Returns rows removed."""
    stmt = delete(FocusList)
    if ecosystem:
        stmt = stmt.where(FocusList.ecosystem == ecosystem)
    return session.execute(stmt).rowcount or 0


_VALID_ECOSYSTEMS = {"pypi", "crates", "gomod", "npm"}


def parse_combined_focus_file(text: str) -> dict[str, list[FocusEntry]]:
    """Parse a single combined file with per-ecosystem sections::

        [pypi]
        requests==2.31.0
        [gomod]
        github.com/gin-gonic/gin v1.9.1

    Returns {ecosystem: entries} for every section header present (an empty
    section yields []). Lines under a header are parsed with the ecosystem's
    rules via :func:`parse_focus_file`. Raises ValueError on an unknown section
    header or content before the first header.
    """
    buckets: dict[str, list[str]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            eco = stripped[1:-1].strip().lower()
            if eco not in _VALID_ECOSYSTEMS:
                raise ValueError(
                    f"unknown ecosystem section [{eco}] — expected one of {sorted(_VALID_ECOSYSTEMS)}"
                )
            current = eco
            buckets.setdefault(current, [])
            continue
        if current is None:
            if raw.split("#", 1)[0].strip():
                raise ValueError("focus file has content before the first [ecosystem] section header")
            continue
        buckets[current].append(raw)
    return {eco: parse_focus_file("\n".join(lines), eco) for eco, lines in buckets.items()}


def sync_focus(session: Session, ecosystem: str, entries: list[FocusEntry]) -> int:
    """Authoritatively replace an ecosystem's focus entries with ``entries``
    (the file is the source of truth). Returns the new entry count."""
    clear_focus(session, ecosystem)
    return upsert_focus(session, ecosystem, entries)


def apply_focus_file(session: Session, text: str) -> dict[str, list[FocusEntry]]:
    """Sync a combined focus file: each section present replaces that
    ecosystem's focus list. Returns the parsed {ecosystem: entries} so the
    caller can enqueue pinned versions. Ecosystems with no section are left
    untouched."""
    sections = parse_combined_focus_file(text)
    for eco, entries in sections.items():
        sync_focus(session, eco, entries)
    return sections
