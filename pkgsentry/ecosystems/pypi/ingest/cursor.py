# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import xmlrpc.client
from typing import Optional

from sqlalchemy import select

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import Package, ScanCursor
from pkgsentry.util.user_agent import user_agent
from pkgsentry.ecosystems.pypi.ingest.watchlist import is_watchlist

log = get_logger("ingest.cursor")
ECOSYSTEM = "pypi"
XMLRPC_URL = "https://pypi.org/pypi"

# Safety cap: on any single pull, never enqueue more than this many events.
# Without this, the FIRST poll on a fresh DB would fetch the entire PyPI
# changelog history (millions of records) and overwhelm SQLite.
DEFAULT_MAX_ITEMS = 2000


def _xmlrpc_client() -> xmlrpc.client.ServerProxy:
    transport = xmlrpc.client.SafeTransport()
    transport.user_agent = user_agent()
    return xmlrpc.client.ServerProxy(XMLRPC_URL, transport=transport)


def _fetch_current_serial(client: xmlrpc.client.ServerProxy) -> Optional[int]:
    """Ask PyPI for its latest serial. Used to bootstrap the cursor at
    'now' on first run so we don't replay all of history."""
    try:
        return int(client.changelog_last_serial())
    except Exception as e:
        log.warning("xmlrpc_last_serial_failed", error=str(e))
        return None


def get_last_serial() -> int:
    """Return the persisted cursor. On first call (no row yet), bootstrap to
    PyPI's CURRENT serial — anything older is historical and not relevant for
    a live malware monitor."""
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        if row is None:
            client = _xmlrpc_client()
            current = _fetch_current_serial(client)
            if current is None:
                log.warning("cursor_bootstrap_skipped_no_serial")
                return 0
            row = ScanCursor(ecosystem=ECOSYSTEM, last_serial=current)
            s.add(row)
            s.flush()
            log.info("cursor_bootstrapped", initial_serial=current)
        return row.last_serial


def set_last_serial(serial: int) -> None:
    with sess.session_scope() as s:
        row = s.get(ScanCursor, ECOSYSTEM)
        if row is None:
            row = ScanCursor(ecosystem=ECOSYSTEM, last_serial=serial)
            s.add(row)
        else:
            row.last_serial = serial


def pull_since(max_items: Optional[int] = DEFAULT_MAX_ITEMS) -> int:
    """Fetch changelog since last serial, enqueue new (name,version), update cursor.
    Returns count enqueued.

    `max_items` is capped at DEFAULT_MAX_ITEMS by default so a single tick can
    never overwhelm the queue or SQLite — large backlogs drain incrementally.
    Pass None explicitly to disable the cap (only safe for short backfills).
    """
    serial = get_last_serial()
    client = _xmlrpc_client()
    try:
        entries = client.changelog_since_serial(serial)
    except Exception as e:  # network/xmlrpc errors are recoverable
        log.warning("xmlrpc_failed", error=str(e), serial=serial)
        return 0

    if not entries:
        return 0
    if max_items is not None:
        entries = entries[:max_items]

    enqueued = 0
    enqueued_new = 0
    skipped = 0
    max_serial = serial
    # Track which packages had a "create" action in this batch
    _created_in_batch: set[str] = set()
    with sess.session_scope() as s:
        for entry in entries:
            # (name, version, timestamp, action, serial)
            name = entry[0]
            version = entry[1]
            action = str(entry[3]).lower() if entry[3] else ""
            ent_serial = entry[4]
            if ent_serial > max_serial:
                max_serial = ent_serial

            # Track create events FIRST — PyPI's "create" action has version=None
            # but the subsequent "new release X" event is what we want to enqueue.
            # Must record the create before the version-skip filter or we lose it.
            if action == "create":
                _created_in_batch.add(name)

            if not version:
                continue
            if "remove" in action:
                continue

            on_watchlist = is_watchlist(s, name) is not None
            brand_new = not on_watchlist and name in _created_in_batch

            if not on_watchlist and not brand_new:
                skipped += 1
                continue

            pri = "high" if on_watchlist else "normal"
            row = enqueue(s, ecosystem=ECOSYSTEM, name=name, version=str(version), priority=pri)
            if row is not None:
                enqueued += 1
                if brand_new:
                    enqueued_new += 1

    if max_serial > serial:
        set_last_serial(max_serial)
    log.info(
        "cursor_pull",
        enqueued=enqueued, enqueued_new=enqueued_new,
        skipped=skipped, new_serial=max_serial,
    )
    return enqueued
