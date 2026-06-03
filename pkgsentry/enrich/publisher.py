# SPDX-License-Identifier: AGPL-3.0-or-later
"""Publisher identity for the alert (author / email / maintainers / uploader).

Read from the `Version` row captured at scan time — no network call. Surfaced in the
Discord alert because the publisher's email domain and the actual uploader are
first-order supply-chain triage signal (a fresh gmail, a research firm, a typo'd org).
Best-effort: any failure returns None so an alert never breaks on it.
"""
from __future__ import annotations

from typing import Optional

from pkgsentry.store import session as sess
from pkgsentry.store.models import Scan, Version


def from_scan(scan_id: int) -> Optional[dict]:
    try:
        with sess.session_scope() as s:
            sc = s.get(Scan, scan_id)
            if sc is None:
                return None
            v = s.get(Version, sc.version_id)
            if v is None:
                return None
            pub = {
                "author": v.author,
                "author_email": v.author_email,
                "maintainers": v.maintainers,
                "upload_user": v.upload_user,
            }
            return pub if any(pub.values()) else None
    except Exception:
        return None
