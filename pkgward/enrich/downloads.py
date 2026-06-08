# SPDX-License-Identifier: AGPL-3.0-or-later
"""Weekly-download enrichment for alert blast-radius triage.

Fetches an estimated weekly download count per package from each ecosystem's
public stats API and caches it on the ``Package`` row (TTL-bounded). Surfaced in
Discord alerts so an operator can tell a high-blast-radius compromise of a
popular package from a zero-install lure at a glance.

Fail-soft everywhere: any network/parse error returns ``None`` and never blocks
an alert. npm/PyPI are exact last-week counts; crates.io exposes only a ~90-day
``recent_downloads``, derived here into a weekly estimate; Go modules have no
public download stats (returns ``None``).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

import httpx

from pkgward.logging_setup import get_logger

log = get_logger("enrich.downloads")

_TIMEOUT = float(os.environ.get("PKGWARD_DOWNLOADS_TIMEOUT", "8"))
_TTL = timedelta(days=int(os.environ.get("PKGWARD_DOWNLOADS_TTL_DAYS", "7")))
_CONTACT = os.environ.get("PKGWARD_CONTACT_EMAIL", "https://github.com/pkgward")


def is_enabled() -> bool:
    return os.environ.get("PKGWARD_DOWNLOADS_ENABLED", "1") != "0"


def _ua() -> str:
    return f"pkgward-downloads (+{_CONTACT})"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get(url: str) -> httpx.Response:
    return httpx.get(url, timeout=_TIMEOUT, headers={"User-Agent": _ua()},
                     follow_redirects=True)


def _fetch_npm(name: str) -> Optional[int]:
    # api.npmjs.org/downloads/point/last-week/<pkg> — scoped names (@scope/name)
    # are passed through verbatim (the API accepts the unencoded slash). 404 means
    # the package has no download record yet -> treat as 0 (real new/lure package).
    r = _get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    d = r.json().get("downloads")
    return int(d) if d is not None else None


def _fetch_pypi(name: str) -> Optional[int]:
    # pypistats.org last-week. Normalize the project name (PEP 503: lowercase,
    # runs of [-_.] -> single '-'). 404 = no stats yet (brand-new) -> unknown(None),
    # NOT 0, so we don't imply a real zero install base we can't actually confirm.
    import re
    norm = re.sub(r"[-_.]+", "-", name.lower())
    r = _get(f"https://pypistats.org/api/packages/{quote(norm)}/recent")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    w = (r.json().get("data") or {}).get("last_week")
    return int(w) if w is not None else None


def _fetch_crates(name: str) -> Optional[int]:
    # crates.io exposes recent_downloads (~last 90 days); derive a weekly estimate.
    r = _get(f"https://crates.io/api/v1/crates/{quote(name)}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    rd = (r.json().get("crate") or {}).get("recent_downloads")
    return max(0, round(int(rd) * 7 / 90)) if rd is not None else None


_FETCHERS = {"npm": _fetch_npm, "pypi": _fetch_pypi, "crates": _fetch_crates}


def weekly_downloads(ecosystem: str, name: str) -> Optional[int]:
    """Live fetch, no cache. ``None`` on unknown ecosystem / no data / any error."""
    fn = _FETCHERS.get(ecosystem)
    if fn is None or not name:
        return None
    try:
        return fn(name)
    except Exception as e:  # network, JSON, HTTP status — all fail-soft
        log.warning("downloads_fetch_failed", ecosystem=ecosystem, name=name, error=str(e))
        return None


def enrich(ecosystem: str, name: str) -> Optional[int]:
    """Cached-or-fresh weekly download estimate, persisted on the Package row.

    Manages its own short sessions and never holds one across the network fetch.
    Fully fail-soft — returns ``None`` rather than raising into the alert path."""
    if not is_enabled() or not name:
        return None
    from sqlalchemy import select

    from pkgward.store import session as sess
    from pkgward.store.models import Package

    # Phase 1 — read cache (no network under the session).
    pkg_id: Optional[int] = None
    try:
        with sess.session_scope() as s:
            pkg = s.scalar(select(Package).where(
                Package.ecosystem == ecosystem, Package.name == name))
            if pkg is not None:
                pkg_id = pkg.id
                fetched = pkg.downloads_fetched_at
                if fetched is not None:
                    if fetched.tzinfo is None:  # sqlite returns naive datetimes
                        fetched = fetched.replace(tzinfo=timezone.utc)
                    if _utcnow() - fetched < _TTL:
                        return pkg.downloads_weekly
    except Exception:
        return None

    # Phase 2 — live fetch with NO session held.
    val = weekly_downloads(ecosystem, name)

    # Phase 3 — persist (short session) ONLY a definitive result. A None means
    # unknown/transient (a 404 with no data, a pypistats 429, a timeout); caching
    # it would pin "n/a" on the row for the whole TTL even for a popular package
    # that merely got rate-limited once. Leave the row untouched so the next alert
    # retries. A real count (including a confirmed 0) is cached.
    if pkg_id is not None and val is not None:
        try:
            with sess.session_scope() as s:
                pkg = s.get(Package, pkg_id)
                if pkg is not None:
                    pkg.downloads_weekly = val
                    pkg.downloads_fetched_at = _utcnow()
        except Exception:
            pass
    return val


def format_field(weekly: Optional[int]) -> str:
    """Human string for the alert field."""
    if weekly is None:
        return "n/a"
    if weekly <= 0:
        return "0 (no install base)"
    return f"~{weekly:,}"
