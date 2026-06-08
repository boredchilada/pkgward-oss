# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared version-update anomaly core for the ingest gates (crates / pypi; npm has
its own richer hook-aware module).

A new version of an established (known, non-watchlisted) package is normally SKIPPED
at ingest — the blind spot that let the IronWorm campaign's malicious version bumps
through. This core diffs the newest version against its predecessor using only cheap
registry metadata (no tarball) and flags the compromise tells that each ecosystem's
API actually exposes: a **size jump** (a bundled payload), a **publisher change**
(account takeover), and — where the API surfaces it — a hook that directly executes
a bundled path. An anomaly is a SCAN TRIGGER, not a verdict: the package enters the
queue and the full pipeline adjudicates, so a false positive costs only a wasted scan.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from pkgward.logging_setup import get_logger

log = get_logger("ingest.anomaly")

_SIZE_JUMP_FACTOR = float(os.environ.get("INGEST_ANOMALY_SIZE_FACTOR", "3.0"))
_SIZE_JUMP_MIN_BYTES = int(os.environ.get("INGEST_ANOMALY_SIZE_MIN_KB", "256")) * 1024
# Absolute-delta trigger, OR'd with the ratio trigger: a small payload bump hidden
# behind a large benign decoy makes the ratio tiny (5.00MB -> 5.05MB is 1.01x — the
# ratio gate never fires) while the absolute delta still reveals the added code (the
# nhmpy class). `=0` disables this trigger, leaving only the ratio gate.
#
# Base-size floor (PKGWARD_ANOMALY_ABS_MIN_BASE_BYTES): only apply the absolute
# trigger when the PREDECESSOR is already substantial. Data-driven (vault replay,
# 2026-06-07): of pypi+crates malware large enough to carry a >=50KB delta, a 256KB
# floor still covers 91% — and 100% of the >=1MB decoy class (nhmpy, the compromised-
# maintainer campaign) — while excluding the small-package firehose that would
# otherwise flood the queue with benign minor-release scans. Raising the *delta*
# threshold instead would wrongly miss the small payload the decoy is hiding; the
# floor is on the BASELINE, not the delta. `=0` removes the floor (fire on any base).
_SIZE_JUMP_ABS_BYTES = int(os.environ.get("PKGWARD_ANOMALY_SIZE_ABS_BYTES", "51200"))
_SIZE_JUMP_ABS_MIN_BASE = int(os.environ.get("PKGWARD_ANOMALY_ABS_MIN_BASE_BYTES", str(256 * 1024)))


@dataclass(frozen=True)
class VersionMeta:
    """Cheap per-version metadata for the diff (whatever the registry API exposes)."""
    version: str
    published_at: str                 # ISO timestamp — used to order newest-first
    size: Optional[int] = None        # bytes (unpacked/crate/download size)
    publisher: Optional[str] = None
    runs_bundled_hook: bool = False    # an install hook directly execs a bundled path


@dataclass(frozen=True)
class AnomalyResult:
    version: str
    flags: tuple[str, ...]

    @property
    def high_priority(self) -> bool:
        return "install_hook_bundled_exec" in self.flags


def detect_anomaly(metas: list[VersionMeta]) -> Optional[AnomalyResult]:
    """Diff the newest-by-publish-time version vs its predecessor. *metas* may be in
    any order. Returns the flags that fired, or None. Pure."""
    ordered = sorted(metas, key=lambda m: m.published_at, reverse=True)
    if len(ordered) < 2:
        return None
    new, prev = ordered[0], ordered[1]
    flags: list[str] = []
    if new.runs_bundled_hook and not prev.runs_bundled_hook:
        flags.append("install_hook_bundled_exec")
    if new.size and prev.size:
        delta = new.size - prev.size
        ratio_jump = (new.size >= prev.size * _SIZE_JUMP_FACTOR
                      and delta >= _SIZE_JUMP_MIN_BYTES)
        abs_jump = (_SIZE_JUMP_ABS_BYTES > 0 and delta >= _SIZE_JUMP_ABS_BYTES
                    and prev.size >= _SIZE_JUMP_ABS_MIN_BASE)
        if ratio_jump or abs_jump:
            flags.append("size_jump")
    if new.publisher and prev.publisher and new.publisher != prev.publisher:
        flags.append("publisher_change")
    if not flags:
        return None
    return AnomalyResult(version=new.version, flags=tuple(flags))


async def check_candidates(
    candidates: set[str],
    fetch_metas: Callable[[str], Awaitable[Optional[list[VersionMeta]]]],
    *,
    ecosystem: str,
    max_checks: int,
    limiter: asyncio.Semaphore,
) -> list[tuple[str, str, str]]:
    """For each candidate (bounded by *max_checks*), fetch its version metas and
    detect an anomaly. Returns ``[(name, version, priority)]`` to enqueue. Overflow
    is LOGGED, never silently dropped."""
    names = list(candidates)
    overflow = max(0, len(names) - max_checks)
    if overflow:
        names = names[:max_checks]
        log.warning("ingest_anomaly_overflow", ecosystem=ecosystem,
                    skipped=overflow, cap=max_checks, checked=len(names))
    out: list[tuple[str, str, str]] = []

    async def _one(name: str) -> None:
        async with limiter:
            try:
                metas = await fetch_metas(name)
            except Exception:
                return
        if not metas:
            return
        a = detect_anomaly(metas)
        if a is not None:
            priority = "high" if a.high_priority else "normal"
            out.append((name, a.version, priority))
            log.info("ingest_anomaly_hit", ecosystem=ecosystem, name=name,
                     version=a.version, flags=list(a.flags), priority=priority)

    if names:
        await asyncio.gather(*[_one(n) for n in names])
    return out
