# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import os
import re
from typing import Iterable

import httpx
from packaging.version import InvalidVersion, Version as PkgVersion

from pkgward.adapter import DiscoveredItem
from pkgward.logging_setup import get_logger
from pkgward.queue import enqueue
from pkgward.store import session as sess
from pkgward.util.user_agent import user_agent

# Version-update anomaly gate: a non-watchlisted package's version bump is normally
# skipped. PyPI's JSON API exposes per-release file sizes, so a size jump (a bundled
# payload — the dipeen-agent / telnyx-litellm class) force-scans it. (PyPI has no
# cheap per-release uploader or install-hook surface — that needs the sdist — so the
# size jump is the cheap signal here.) A scan trigger, not a verdict.
PYPI_ANOMALY_GATE = os.environ.get("PYPI_ANOMALY_GATE", "1") == "1"
PYPI_ANOMALY_MAX_CHECKS = int(os.environ.get("PYPI_ANOMALY_MAX_CHECKS", "150"))
_anomaly_limiter = asyncio.Semaphore(int(os.environ.get("PYPI_ANOMALY_CONCURRENCY", "6")))


async def _fetch_pypi_metas(client: httpx.AsyncClient, name: str):
    """Per-release size + upload time for the anomaly diff, from the PyPI JSON API."""
    from pkgward.ecosystems.version_anomaly import VersionMeta
    resp = await client.get(f"https://pypi.org/pypi/{name}/json", timeout=20.0)
    if resp.status_code != 200:
        return None
    metas = []
    for ver, files in (resp.json().get("releases") or {}).items():
        if not files:
            continue
        size = max((f["size"] for f in files if isinstance(f.get("size"), int)), default=None)
        t = max((f.get("upload_time_iso_8601") or "" for f in files), default="")
        if t:
            metas.append(VersionMeta(version=ver, published_at=t, size=size, publisher=None))
    return metas

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

    from pkgward.ecosystems.pypi.ingest.watchlist import is_watchlist
    from pkgward.focus import load_focus_names, on_focus, gate_decision, focus_exclusive
    exclusive = focus_exclusive()
    enq = 0
    enq_new = 0
    skipped = 0
    anomaly_candidates: set[str] = set()
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
                # known, non-watchlisted version bump → anomaly-gate candidate
                if PYPI_ANOMALY_GATE and not exclusive:
                    anomaly_candidates.add(it.name)
                continue
            if enqueue(s, ecosystem=ECOSYSTEM, name=it.name, version=it.version, priority=pri):
                enq += 1
                if brand_new:
                    enq_new += 1

    anomaly_enq = 0
    if PYPI_ANOMALY_GATE and anomaly_candidates:
        from pkgward.ecosystems.version_anomaly import check_candidates
        async with httpx.AsyncClient(headers={"User-Agent": user_agent()}) as client:
            hits = await check_candidates(
                anomaly_candidates,
                lambda n: _fetch_pypi_metas(client, n),
                ecosystem=ECOSYSTEM, max_checks=PYPI_ANOMALY_MAX_CHECKS,
                limiter=_anomaly_limiter,
            )
        if hits:
            with sess.session_scope() as s:
                for name, version, priority in hits:
                    if enqueue(s, ecosystem=ECOSYSTEM, name=name, version=version, priority=priority):
                        anomaly_enq += 1

    log.info(
        "feeds_poll",
        enqueued=enq, enqueued_new=enq_new, anomaly=anomaly_enq,
        skipped=skipped, candidates=len(items),
        focus=len(focus_names), exclusive=exclusive,
    )
    return items
