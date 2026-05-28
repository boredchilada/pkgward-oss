# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-add packages to the Watchlist on double-confirmed malicious verdicts.

Triggered from `pipeline.py` when **both** the rule verdict and the LLM
verdict are `malicious` — the strongest signal we have. Auto-added rows carry
sentinel rank ``AUTO_MALICIOUS_RANK`` so they're trivially distinguishable
from popularity-ranked entries (and the popularity refresh paths skip them
via the same rank filter — see ``ecosystems/*/ingest/watchlist.py``).

Size-control layers (all env-tunable):

* **TTL** — every re-confirmation refreshes ``refreshed_at``; entries older than
  ``WATCHLIST_AUTO_TTL_DAYS`` (default 180) are pruned by the periodic janitor.
  Live campaigns stay watchlisted; dead ones fall off.
* **Per-ecosystem hard cap** — ``WATCHLIST_AUTO_MAX_PER_ECO`` (default 5000);
  janitor evicts oldest by ``refreshed_at`` when over.
* **Add-rate ceiling** — ``WATCHLIST_AUTO_MAX_ADDS_PER_HOUR`` (default 100,
  per ecosystem, in-process). Defense-in-depth against an FP surge.

FP exit ramps:

* Sentinel rank means ``SELECT … WHERE rank = 9999999`` lists every auto-added
  row.
* ``WATCHLIST_AUTO_BLOCKLIST`` env (``"npm:bad-name,pypi:other"``) — names that
  are *never* auto-added, even on double-confirm. (v2 plan: move to an
  intel-pack TOML so operators ship a private blocklist via overlay.)
* ``pkgsentry watchlist auto remove/purge/list`` CLI for ad-hoc trimming.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pkgsentry.logging_setup import get_logger
from pkgsentry.store.models import Watchlist

log = get_logger("watchlist.auto")

# Sentinel rank — well above any plausible popularity rank (top-N watchlists
# cap at ~10K). Used as the discriminator everywhere: refresh paths skip rows
# at this rank, prune queries scope to this rank, audits filter on it.
AUTO_MALICIOUS_RANK = 9_999_999


def _ttl_days() -> int:
    return int(os.environ.get("WATCHLIST_AUTO_TTL_DAYS", "180"))


def _max_per_eco() -> int:
    return int(os.environ.get("WATCHLIST_AUTO_MAX_PER_ECO", "5000"))


def _max_adds_per_hour() -> int:
    return int(os.environ.get("WATCHLIST_AUTO_MAX_ADDS_PER_HOUR", "100"))


def is_enabled() -> bool:
    return os.environ.get("WATCHLIST_AUTO_MALICIOUS", "1").lower() not in (
        "0", "false", "off", "no",
    )


def _blocklist() -> dict[str, set[str]]:
    """Parse ``WATCHLIST_AUTO_BLOCKLIST=npm:foo,pypi:bar`` into
    ``{ecosystem: {lowercased_names}}``. Empty when unset."""
    raw = os.environ.get("WATCHLIST_AUTO_BLOCKLIST", "").strip()
    if not raw:
        return {}
    out: dict[str, set[str]] = defaultdict(set)
    for token in raw.split(","):
        token = token.strip()
        if ":" not in token:
            continue
        eco, name = token.split(":", 1)
        out[eco.strip()].add(name.strip().lower())
    return dict(out)


# Per-ecosystem in-process rate limiter — resets on scanner restart. The TTL +
# cap layers are the durable controls; this is the surge guard.
_rate_lock = threading.Lock()
_recent_adds: dict[str, deque[float]] = defaultdict(deque)


def _rate_limited(ecosystem: str) -> bool:
    cap = _max_adds_per_hour()
    if cap <= 0:
        return False
    now = time.monotonic()
    cutoff = now - 3600
    with _rate_lock:
        dq = _recent_adds[ecosystem]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= cap:
            return True
        dq.append(now)
    return False


def _reset_rate_for_tests() -> None:
    with _rate_lock:
        _recent_adds.clear()


def add_confirmed_malicious(
    session: Session, ecosystem: str, name: str,
    *, scan_id: Optional[int] = None,
) -> Optional[str]:
    """Add or refresh ``(ecosystem, name)`` on the Watchlist. Returns a status
    string suitable for logging:

      - ``"added"`` — newly inserted at the sentinel rank.
      - ``"refreshed"`` — existing auto-malicious row's TTL refreshed.
      - ``"already_popularity"`` — already on the popularity watchlist; no-op
        (do not downgrade its real rank).
      - ``"blocklisted"`` — name on the blocklist; skip.
      - ``"rate_limited"`` — add-rate ceiling hit this hour; skip.
      - ``None`` — feature disabled (``WATCHLIST_AUTO_MALICIOUS=0``).

    Idempotent and race-safe — another worker inserting first → ``"refreshed"``
    on the next call.
    """
    if not is_enabled():
        return None
    if name.lower() in _blocklist().get(ecosystem, set()):
        log.info("watchlist_auto_blocklisted", ecosystem=ecosystem, name=name, scan_id=scan_id)
        return "blocklisted"
    try:
        existing = session.scalar(
            select(Watchlist).where(
                Watchlist.ecosystem == ecosystem,
                func.lower(Watchlist.name) == name.lower(),
            )
        )
        if existing is not None:
            if existing.rank == AUTO_MALICIOUS_RANK:
                existing.refreshed_at = datetime.now(timezone.utc)
                session.flush()
                log.info("watchlist_auto_refreshed",
                         ecosystem=ecosystem, name=name, scan_id=scan_id)
                return "refreshed"
            # Already on the popularity watchlist — leave the real rank alone.
            return "already_popularity"
        if _rate_limited(ecosystem):
            log.warning("watchlist_auto_rate_limited",
                        ecosystem=ecosystem, name=name,
                        cap_per_hour=_max_adds_per_hour())
            return "rate_limited"
        session.add(Watchlist(
            ecosystem=ecosystem, name=name, rank=AUTO_MALICIOUS_RANK,
            refreshed_at=datetime.now(timezone.utc),
        ))
        session.flush()
        log.info("watchlist_auto_added",
                 ecosystem=ecosystem, name=name, scan_id=scan_id,
                 rank=AUTO_MALICIOUS_RANK)
        return "added"
    except IntegrityError:
        session.rollback()
        return "already_popularity"


def prune_expired(session: Session) -> int:
    """Delete auto-added rows whose ``refreshed_at`` is older than the TTL.
    Popularity rows are untouched (different rank). Returns count deleted."""
    ttl = _ttl_days()
    if ttl <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=ttl)
    res = session.execute(
        delete(Watchlist).where(
            Watchlist.rank == AUTO_MALICIOUS_RANK,
            Watchlist.refreshed_at < cutoff,
        )
    )
    n = int(res.rowcount or 0)
    if n > 0:
        log.info("watchlist_auto_pruned_expired", n=n, ttl_days=ttl)
    return n


def prune_over_cap(session: Session) -> int:
    """For each ecosystem, if auto-added count > cap, evict oldest by
    ``refreshed_at``. Returns total count evicted."""
    cap = _max_per_eco()
    if cap <= 0:
        return 0
    total = 0
    for eco in ("pypi", "crates", "gomod", "npm"):
        rows = session.execute(
            select(Watchlist.id).where(
                Watchlist.ecosystem == eco,
                Watchlist.rank == AUTO_MALICIOUS_RANK,
            ).order_by(Watchlist.refreshed_at.asc())
        ).all()
        excess = len(rows) - cap
        if excess <= 0:
            continue
        ids = [r[0] for r in rows[:excess]]
        session.execute(delete(Watchlist).where(Watchlist.id.in_(ids)))
        total += excess
        log.info("watchlist_auto_pruned_over_cap",
                 ecosystem=eco, n=excess, cap=cap)
    return total


def list_auto_entries(
    session: Session, ecosystem: Optional[str] = None,
) -> list[tuple[str, str, datetime]]:
    """List all auto-added rows: ``[(ecosystem, name, refreshed_at), …]``."""
    q = select(Watchlist.ecosystem, Watchlist.name, Watchlist.refreshed_at).where(
        Watchlist.rank == AUTO_MALICIOUS_RANK,
    )
    if ecosystem:
        q = q.where(Watchlist.ecosystem == ecosystem)
    q = q.order_by(Watchlist.refreshed_at.desc())
    return [(r[0], r[1], r[2]) for r in session.execute(q).all()]


def is_watchlist_auto_only(
    session: Session, ecosystem: str, name: str,
) -> bool:
    """Return True iff `(ecosystem, name)` is on the Watchlist *only* as an
    auto-malicious entry (sentinel rank). Used by the finding-reuse path to
    decide whether to pull forward prior findings on SHA-unchanged files."""
    row = session.scalar(
        select(Watchlist).where(
            Watchlist.ecosystem == ecosystem,
            func.lower(Watchlist.name) == name.lower(),
            Watchlist.rank == AUTO_MALICIOUS_RANK,
        )
    )
    return row is not None


def remove_auto_entry(session: Session, ecosystem: str, name: str) -> bool:
    """Delete a single auto-added row. Won't touch popularity rows (filtered
    by rank). Returns True if a row was deleted."""
    res = session.execute(
        delete(Watchlist).where(
            Watchlist.ecosystem == ecosystem,
            func.lower(Watchlist.name) == name.lower(),
            Watchlist.rank == AUTO_MALICIOUS_RANK,
        )
    )
    return bool(res.rowcount)
