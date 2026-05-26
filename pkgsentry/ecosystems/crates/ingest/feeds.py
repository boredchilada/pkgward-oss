# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io RSS feed ingest — polls both crates.xml (new) and updates.xml."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

import httpx
from sqlalchemy import select

from pkgsentry.adapter import DiscoveredItem
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue
from pkgsentry.util.user_agent import user_agent
from pkgsentry.ecosystems.crates.ingest.watchlist import is_watchlist

log = get_logger("crates.feeds")

ECOSYSTEM = "crates"
USER_AGENT = user_agent()
NEW_CRATES_URL = "https://static.crates.io/rss/crates.xml"
UPDATES_URL = "https://static.crates.io/rss/updates.xml"


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
    from pkgsentry.ecosystems.crates.fetch.download import _resolve_latest
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

    from pkgsentry.focus import load_focus_names, on_focus, gate_decision, focus_exclusive
    exclusive = focus_exclusive()
    enqueued_new = 0
    enqueued_wl = 0
    skipped = 0

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
                continue
            try:
                enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority=pri)
                enqueued_wl += 1
            except Exception:
                pass

    total = enqueued_new + enqueued_wl
    if total or skipped:
        log.info("crates_feeds_polled", new_crates=enqueued_new,
                 updates=enqueued_wl, skipped=skipped,
                 focus=len(focus_names), exclusive=exclusive)
    return total
