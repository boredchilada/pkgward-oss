# SPDX-License-Identifier: AGPL-3.0-or-later
"""Known-malicious dependency intel.

When package X is double-confirmed malicious it lands on the auto-watchlist
(sentinel rank). The names on that list, per ecosystem, are the confirmed-bad set.
A *different* package that declares a dependency on one of them is itself suspect —
compromised, complicit, or a victim pulling the payload in. This module is the
data layer for that signal: the confirmed-bad name set (cached), name
normalization, and dependency-string matching.

It is a scan-TRIGGER + weighted evidence signal, never an auto-verdict: a hit
force-scans the parent (npm ingest) or adds a finding (scan time), but the
pipeline + LLM still adjudicate. Deliberately not a self-confirming convict loop
(cf. the threat-intel auto-seed that is kept off for exactly that reason)."""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Optional

from sqlalchemy.orm import Session

from pkgward import watchlist_auto
from pkgward.logging_setup import get_logger
from pkgward.store import session as sess

log = get_logger("known_bad_deps")

# PyPI canonical form (PEP 503): lowercase, runs of -_. collapse to a single -.
_PYPI_NORM = re.compile(r"[-_.]+")
# Leading distribution name of a PEP 508 requirement ("requests>=2; markers" -> "requests").
_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

_CACHE_TTL = float(os.environ.get("KNOWN_BAD_DEPS_CACHE_TTL", "300"))
_cache: dict[str, tuple[float, frozenset[str]]] = {}
_cache_lock = threading.Lock()


def is_enabled() -> bool:
    return os.environ.get("KNOWN_BAD_DEPS_GATE", "1").lower() not in (
        "0", "false", "off", "no",
    )


def normalize(ecosystem: str, name: str) -> str:
    """Canonicalize a package name for cross-reference matching."""
    n = (name or "").strip().lower()
    if ecosystem == "pypi":
        n = _PYPI_NORM.sub("-", n).strip("-")
    return n


def extract_dep_name(ecosystem: str, entry: str) -> Optional[str]:
    """Pull the bare package name from a ``requires_dist`` entry. npm entries are
    already bare names; pypi entries are PEP 508 requirement strings."""
    if not entry:
        return None
    if ecosystem == "pypi":
        m = _PEP508_NAME.match(entry)
        return m.group(1) if m else None
    return entry.strip()


def load_known_bad(ecosystem: str, session: Optional[Session] = None) -> frozenset[str]:
    """Normalized set of confirmed-malicious names for ``ecosystem``.

    TTL-cached in-process: the set is small and changes slowly, so the ingest and
    scan hot paths don't query the DB per package. Pass ``session`` to reuse an
    open transaction; otherwise a short one is opened on a cache miss."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(ecosystem)
        if hit and (now - hit[0]) < _CACHE_TTL:
            return hit[1]
    try:
        names = _query_known_bad(ecosystem, session)
    except Exception as exc:
        # Fail-soft: a transient DB error must not crash an ingest poll or a scan.
        # Don't cache the empty result, so the next call retries.
        log.warning("known_bad_deps_load_failed", ecosystem=ecosystem, error=str(exc))
        return frozenset()
    with _cache_lock:
        _cache[ecosystem] = (now, names)
    return names


def _query_known_bad(ecosystem: str, session: Optional[Session]) -> frozenset[str]:
    blocked = watchlist_auto._blocklist().get(ecosystem, set())

    def _rows(s: Session) -> frozenset[str]:
        out = {
            normalize(ecosystem, name)
            for _eco, name, _ts in watchlist_auto.list_auto_entries(s, ecosystem)
            if name.lower() not in blocked
        }
        return frozenset(out)

    if session is not None:
        return _rows(session)
    with sess.session_scope() as s:
        return _rows(s)


def match_known_bad(
    ecosystem: str, requires_dist, known_bad: frozenset[str],
) -> dict[str, str]:
    """``{original_requirement_string: normalized_name}`` for declared deps that
    are confirmed malicious in this ecosystem."""
    if not requires_dist or not known_bad:
        return {}
    hits: dict[str, str] = {}
    for entry in requires_dist:
        name = extract_dep_name(ecosystem, entry)
        if not name:
            continue
        norm = normalize(ecosystem, name)
        if norm in known_bad:
            hits[entry] = norm
    return hits


def invalidate_cache() -> None:
    """Drop the cached sets (tests; or after a manual watchlist edit)."""
    with _cache_lock:
        _cache.clear()
