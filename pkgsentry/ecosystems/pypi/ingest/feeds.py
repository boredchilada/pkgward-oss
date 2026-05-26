# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import re
from typing import Iterable

import httpx
from packaging.version import InvalidVersion, Version as PkgVersion

from pkgsentry.adapter import DiscoveredItem
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.util.user_agent import user_agent

log = get_logger("ingest.feeds")
ECOSYSTEM = "pypi"

UPDATES_URL = "https://pypi.org/rss/updates.xml"
PACKAGES_URL = "https://pypi.org/rss/packages.xml"

_TITLE_RE = re.compile(rb"<title>([^<]+)</title>")


def parse_feed(xml_bytes: bytes) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _TITLE_RE.finditer(xml_bytes):
        title = m.group(1).decode("utf-8", errors="replace").strip()
        # Skip channel title and entries without "<name> <version>"
        if " " not in title:
            continue
        name, _, version = title.rpartition(" ")
        name = name.strip()
        version = version.strip()
        if not name or not version:
            continue
        # Filter obvious non-package titles
        if name.lower().startswith(("pypi", "python package")):
            continue
        # Reject entries from packages.xml whose titles are "name added to PyPI"
        # — rpartition produces version="PyPI" and a mangled name.
        try:
            PkgVersion(version)
        except InvalidVersion:
            continue
        out.append((name, version))
    return out


def parse_new_package_names(xml_bytes: bytes) -> list[str]:
    """Extract names from packages.xml entries (format: '<name> added to PyPI').

    packages.xml lists brand-new package registrations. The version is not in
    the feed — we only learn the name. Returns the list of brand-new names
    seen in this RSS snapshot.
    """
    names: list[str] = []
    suffix = " added to PyPI"
    for m in _TITLE_RE.finditer(xml_bytes):
        title = m.group(1).decode("utf-8", errors="replace").strip()
        if title.lower().startswith(("pypi", "python package")):
            continue
        if title.endswith(suffix):
            name = title[: -len(suffix)].strip()
            if name:
                names.append(name)
    return names


async def _fetch(client: httpx.AsyncClient, url: str) -> bytes:
    r = await client.get(url, timeout=20.0)
    r.raise_for_status()
    return r.content


async def poll_feeds_once() -> list[DiscoveredItem]:
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": user_agent()},
            follow_redirects=True,
        ) as client:
            updates_raw = await _fetch(client, UPDATES_URL)
            packages_raw = await _fetch(client, PACKAGES_URL)
    except Exception as e:
        log.warning("feed_fetch_failed", error=str(e))
        return []

    # packages.xml entries have title "<name> added to PyPI" — version not in
    # the feed. Parse with the dedicated helper to populate the brand-new set.
    # updates.xml entries have title "<name> <version>" — these we can enqueue.
    new_package_names: set[str] = set(parse_new_package_names(packages_raw))

    seen: set[tuple[str, str]] = set()
    items: list[DiscoveredItem] = []
    for nv in parse_feed(updates_raw):
        if nv in seen:
            continue
        seen.add(nv)
        items.append(DiscoveredItem(name=nv[0], version=nv[1], priority="normal"))

    from pkgsentry.ecosystems.pypi.ingest.watchlist import is_watchlist
    from pkgsentry.focus import load_focus_names, on_focus, gate_decision, focus_exclusive
    exclusive = focus_exclusive()
    enq = 0
    enq_new = 0
    skipped = 0
    with sess.session_scope() as s:
        focus_names = load_focus_names(s, ECOSYSTEM)  # preloaded once per poll
        for it in items:
            on_foc = on_focus(it.name, focus_names, ECOSYSTEM)
            # Exclusive mode admits only focus packages — skip the per-item
            # watchlist/brand-new work entirely.
            on_watchlist = (not exclusive) and is_watchlist(s, it.name) is not None
            brand_new = (not exclusive) and not on_watchlist and it.name in new_package_names

            pri = gate_decision(
                on_focus=on_foc, on_watchlist=on_watchlist,
                brand_new=brand_new, exclusive=exclusive,
            )
            if pri is None:
                skipped += 1
                continue
            if enqueue(s, ecosystem=ECOSYSTEM, name=it.name, version=it.version, priority=pri):
                enq += 1
                if brand_new:
                    enq_new += 1

    log.info(
        "feeds_poll",
        enqueued=enq, enqueued_new=enq_new,
        skipped=skipped, candidates=len(items),
        focus=len(focus_names), exclusive=exclusive,
    )
    return items
