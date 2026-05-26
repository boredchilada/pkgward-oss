# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io RSS feed ingest — polls both crates.xml (new) and updates.xml."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

import httpx

from pkgsentry.adapter import DiscoveredItem
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
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


async def poll_feeds_once() -> int:
    """Poll both RSS feeds with ingest gates.

    crates.xml (new crates) → all enqueued at normal priority (brand-new).
    updates.xml (version bumps) → watchlist only at high priority.
    """
    new_items = await _fetch_rss(NEW_CRATES_URL)
    update_items = await _fetch_rss(UPDATES_URL)

    enqueued_new = 0
    enqueued_wl = 0
    skipped = 0

    with sess.session_scope() as s:
        for name, version in new_items:
            try:
                enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority="normal")
                enqueued_new += 1
            except Exception:
                pass

        for name, version in update_items:
            if is_watchlist(s, name) is None:
                skipped += 1
                continue
            try:
                enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority="high")
                enqueued_wl += 1
            except Exception:
                pass

    total = enqueued_new + enqueued_wl
    if total or skipped:
        log.info("crates_feeds_polled", new_crates=enqueued_new,
                 updates=enqueued_wl, skipped=skipped)
    return total
