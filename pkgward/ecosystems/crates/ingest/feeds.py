# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io RSS feed ingest — polls both crates.xml (new) and updates.xml."""
from __future__ import annotations

import asyncio
import os
import xml.etree.ElementTree as ET
from typing import Optional

import httpx
from sqlalchemy import select

from pkgward.adapter import DiscoveredItem
from pkgward.logging_setup import get_logger
from pkgward.queue import enqueue
from pkgward.store import session as sess
from pkgward.store.models import ScanQueue
from pkgward.util.user_agent import user_agent
from pkgward.ecosystems.crates.ingest.watchlist import is_watchlist

log = get_logger("crates.feeds")

ECOSYSTEM = "crates"
USER_AGENT = user_agent()
NEW_CRATES_URL = "https://static.crates.io/rss/crates.xml"
UPDATES_URL = "https://static.crates.io/rss/updates.xml"

# Version-update anomaly gate: a non-watchlisted crate's version bump is normally
# skipped. The crates.io API exposes per-version size (`crate_size`) and the real
# uploader (`published_by`), so a size jump (bundled payload) or a publisher change
# (account takeover) force-scans it — a scan trigger, not a verdict. Bounded;
# crates volume is low, but crates.io rate-limits hard so concurrency stays tiny.
CRATES_API_BASE = "https://crates.io/api/v1/crates"
CRATES_ANOMALY_GATE = os.environ.get("CRATES_ANOMALY_GATE", "1") == "1"
CRATES_ANOMALY_MAX_CHECKS = int(os.environ.get("CRATES_ANOMALY_MAX_CHECKS", "80"))
_anomaly_limiter = asyncio.Semaphore(int(os.environ.get("CRATES_ANOMALY_CONCURRENCY", "2")))


async def _fetch_crate_metas(client: httpx.AsyncClient, name: str):
    """Per-version (size, uploader) for the anomaly diff, from the crates.io API."""
    from pkgward.ecosystems.version_anomaly import VersionMeta
    resp = await client.get(f"{CRATES_API_BASE}/{name}", timeout=20.0)
    await asyncio.sleep(1.0)  # crates.io politeness (~1 req/s)
    if resp.status_code != 200:
        return None
    metas = []
    for v in (resp.json().get("versions") or []):
        pb = v.get("published_by")
        metas.append(VersionMeta(
            version=str(v.get("num", "")),
            published_at=str(v.get("created_at", "")),
            size=v.get("crate_size") if isinstance(v.get("crate_size"), int) else None,
            publisher=(pb.get("login") or pb.get("name")) if isinstance(pb, dict) else None,
        ))
    return metas


_NEW_CRATE_PREFIX = "New crate created: "
_UPDATE_PREFIX = "New crate version published: "


def _parse_title(title: str) -> Optional[tuple[str, str]]:
    """Extract (name, version) from a single RSS title.

    Real crates.io title formats:
      - "New crate created: {name}"                      (crates.xml)
      - "New crate version published: {name} v{version}" (updates.xml)
    """
    if title.startswith(_UPDATE_PREFIX):
        rest = title[len(_UPDATE_PREFIX):]
        parts = rest.rsplit(" ", 1)
        if len(parts) == 2:
            name, ver = parts
            return name.strip(), ver.lstrip("v").strip()
    elif title.startswith(_NEW_CRATE_PREFIX):
        name = title[len(_NEW_CRATE_PREFIX):].strip()
        if name:
            return name, "latest"
    return None


def _version_from_link(link: str) -> Optional[str]:
    """Extract version from a crates.io link like /crates/{name}/{version}."""
    parts = link.rstrip("/").split("/")
    # .../crates/{name}/{version} has at least 2 trailing segments after 'crates'
    try:
        idx = parts.index("crates")
        if len(parts) > idx + 2:
            return parts[idx + 2]
    except ValueError:
        pass
    return None


def parse_rss_items(xml_text: str) -> list[tuple[str, str]]:
    """Parse (name, version) pairs from crates.io RSS XML."""
    items: list[tuple[str, str]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.warning("rss_parse_error")
        return items
    for item in root.iter("item"):
        title = item.findtext("title", "").strip()
        if not title:
            continue
        parsed = _parse_title(title)
        if parsed is None:
            continue
        name, version = parsed
        # For new crates, try to resolve version from the <link> element
        if version == "latest":
            link = item.findtext("link", "").strip()
            link_ver = _version_from_link(link)
            if link_ver:
                version = link_ver
        items.append((name, version))
    return items


async def _fetch_rss(url: str) -> list[tuple[str, str]]:
    """Fetch and parse an RSS feed. Returns (name, version) pairs."""
    try:
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.get(url, timeout=30.0)
            resp.raise_for_status()
    except Exception as e:
        log.warning("rss_fetch_error", url=url, error=str(e))
        return []
    return parse_rss_items(resp.text)


async def _resolve_new_latest(names: set[str]) -> dict[str, str]:
    """Resolve crates.xml 'latest' placeholders to concrete newest versions.

    crates.xml yields ``(name, 'latest')`` for a new crate whose RSS link carries
    no version. Enqueuing the literal ``latest`` creates a second Version row and
    a spurious 0-finding code-diff rescan when the same publish also arrives via
    updates.xml as a concrete version. Resolving here converges both to a single
    ``(name, version)``. Respects the crates.io 1 req/s limiter inside
    ``_resolve_latest``."""
    from pkgward.ecosystems.crates.fetch.download import _resolve_latest
    out: dict[str, str] = {}
    if not names:
        return out
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        for name in names:
            try:
                out[name] = await _resolve_latest(client, name)
            except Exception:
                pass  # leave unresolved; caller keeps the placeholder
    return out


def _dedup_new_items(
    new_items: list[tuple[str, str]],
    known: set[str],
    resolved: dict[str, str],
) -> list[tuple[str, str]]:
    """Rewrite 'latest' placeholders: drop crates already queued under a concrete
    version, swap in resolved concrete versions, keep the placeholder only when
    resolution failed (so coverage isn't lost)."""
    out: list[tuple[str, str]] = []
    for name, version in new_items:
        if version != "latest":
            out.append((name, version))
        elif name in known:
            continue
        elif name in resolved:
            out.append((name, resolved[name]))
        else:
            out.append((name, version))
    return out


async def poll_feeds_once() -> int:
    """Poll both RSS feeds with ingest gates.

    crates.xml (new crates) → all enqueued at normal priority (brand-new).
    updates.xml (version bumps) → watchlist only at high priority.
    """
    new_items = await _fetch_rss(NEW_CRATES_URL)
    update_items = await _fetch_rss(UPDATES_URL)

    # Resolve brand-new "latest" placeholders to concrete versions so a publish
    # that also shows up in updates.xml dedups to one scan. Only resolve crates
    # not already queued, to bound crates.io API calls.
    latest_names = {n for n, v in new_items if v == "latest"}
    if latest_names:
        with sess.session_scope() as s:
            known = set(
                s.scalars(
                    select(ScanQueue.name).where(
                        ScanQueue.ecosystem == ECOSYSTEM,
                        ScanQueue.name.in_(latest_names),
                    )
                ).all()
            )
        resolved = await _resolve_new_latest(latest_names - known)
        new_items = _dedup_new_items(new_items, known, resolved)

    from pkgward.focus import load_focus_names, on_focus, gate_decision, focus_exclusive
    exclusive = focus_exclusive()
    enqueued_new = 0
    enqueued_wl = 0
    skipped = 0
    anomaly_candidates: set[str] = set()

    with sess.session_scope() as s:
        focus_names = load_focus_names(s, ECOSYSTEM)  # preloaded once per poll

        # crates.xml — brand-new crates (normal), or focus/exclusive (high).
        for name, version in new_items:
            pri = gate_decision(
                on_focus=on_focus(name, focus_names, ECOSYSTEM),
                on_watchlist=False, brand_new=True, exclusive=exclusive,
            )
            if pri is None:
                skipped += 1
                continue
            try:
                enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority=pri)
                enqueued_new += 1
            except Exception:
                pass

        # updates.xml — watchlist version bumps (high), or focus (high).
        for name, version in update_items:
            on_wl = (not exclusive) and is_watchlist(s, name) is not None
            pri = gate_decision(
                on_focus=on_focus(name, focus_names, ECOSYSTEM),
                on_watchlist=on_wl, brand_new=False, exclusive=exclusive,
            )
            if pri is None:
                skipped += 1
                # known, non-watchlisted version bump → anomaly-gate candidate
                if CRATES_ANOMALY_GATE and not exclusive:
                    anomaly_candidates.add(name)
                continue
            try:
                enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority=pri)
                enqueued_wl += 1
            except Exception as e:
                # Don't silently drop a watchlisted (high-value) crate update — surface
                # it. The crates_reconcile job re-derives recent crates as the backstop.
                log.warning("crates_wl_enqueue_failed", name=name, version=version, error=str(e))

    anomaly_enq = 0
    if CRATES_ANOMALY_GATE and anomaly_candidates:
        from pkgward.ecosystems.version_anomaly import check_candidates
        async with httpx.AsyncClient(headers={"User-Agent": user_agent()}) as client:
            hits = await check_candidates(
                anomaly_candidates,
                lambda n: _fetch_crate_metas(client, n),
                ecosystem=ECOSYSTEM, max_checks=CRATES_ANOMALY_MAX_CHECKS,
                limiter=_anomaly_limiter,
            )
        if hits:
            with sess.session_scope() as s:
                for name, version, priority in hits:
                    try:
                        if enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority=priority):
                            anomaly_enq += 1
                    except Exception:
                        pass

    total = enqueued_new + enqueued_wl + anomaly_enq
    if total or skipped:
        log.info("crates_feeds_polled", new_crates=enqueued_new,
                 updates=enqueued_wl, anomaly=anomaly_enq, skipped=skipped,
                 focus=len(focus_names), exclusive=exclusive)
    return total


# --- Reconciliation backstop -------------------------------------------------
# Unlike PyPI/npm/gomod, crates has no cursor — discovery is a pure RSS snapshot.
# A failed/slow poll, a publish burst exceeding the RSS window, or a restart
# spanning the window silently drops every crate in that gap, permanently. This
# periodic backstop re-derives the newest crates from the crates.io API (sort=new,
# authoritative) and enqueues any the RSS feed missed. Additive — it only ever
# *adds* (enqueue dedups), so it can never drop a package.
API_NEW_URL = "https://crates.io/api/v1/crates"
RECONCILE_PAGES = int(os.environ.get("CRATES_RECONCILE_PAGES", "3"))


async def _fetch_new_crates(pages: int) -> list[tuple[str, str]]:
    """Newest crates from the API (sort=new), oldest-bounded by `pages` × 100."""
    from pkgward.ecosystems.crates.fetch.download import _api_limiter
    out: list[tuple[str, str]] = []
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        for page in range(1, pages + 1):
            try:
                async with _api_limiter:
                    resp = await client.get(
                        API_NEW_URL,
                        params={"sort": "new", "per_page": 100, "page": page},
                        timeout=30.0,
                    )
                    await asyncio.sleep(1.0)  # crates.io 1 req/s
                resp.raise_for_status()
                crates = resp.json().get("crates", [])
            except Exception as e:
                log.warning("crates_reconcile_fetch_error", page=page, error=str(e))
                break
            if not crates:
                break
            for c in crates:
                name = c.get("name") or ""
                version = c.get("newest_version") or c.get("max_version") or ""
                if name and version:
                    out.append((name, version))
    return out


async def reconcile_new_crates() -> int:
    """Enqueue brand-new crates the RSS feed may have missed. Additive backstop."""
    items = await _fetch_new_crates(RECONCILE_PAGES)
    if not items:
        return 0
    from pkgward.focus import load_focus_names, on_focus, gate_decision, focus_exclusive
    exclusive = focus_exclusive()
    enqueued = 0
    skipped = 0
    with sess.session_scope() as s:
        focus_names = load_focus_names(s, ECOSYSTEM)
        names = {n for n, _ in items}
        known = set(s.scalars(
            select(ScanQueue.name).where(
                ScanQueue.ecosystem == ECOSYSTEM, ScanQueue.name.in_(names)
            )
        ).all())
        for name, version in items:
            if name in known:
                continue
            pri = gate_decision(
                on_focus=on_focus(name, focus_names, ECOSYSTEM),
                on_watchlist=False, brand_new=True, exclusive=exclusive,
            )
            if pri is None:
                skipped += 1
                continue
            try:
                if enqueue(s, ecosystem=ECOSYSTEM, name=name,
                           version=version, priority=pri) is not None:
                    enqueued += 1
            except Exception:
                pass
    if enqueued or skipped:
        log.info("crates_reconciled", enqueued=enqueued,
                 skipped=skipped, candidates=len(items))
    return enqueued
