# SPDX-License-Identifier: AGPL-3.0-or-later
"""Abuse-prone hosting / tunnel callback detection (by domain)."""
from __future__ import annotations

from pkgsentry.analyze.iocs import _is_abuse_hosting_url as is_abuse


def test_abuse_hosts_flagged():
    for u in (
        b"https://callback-monitor.cyb3rsh4ykh.workers.dev/c",   # brave-search
        b"https://x.trycloudflare.com/download/datab1",          # faster-axios
        b"https://abc.ngrok-free.app/x",
        b"https://foo.pages.dev/beacon",
        b"https://bar.r2.dev/p",
    ):
        assert is_abuse(u), u


def test_legit_hosts_not_flagged():
    for u in (
        b"https://registry.npmjs.org/foo",
        b"https://github.com/user/repo",
        b"https://api.example.com/v1",
        b"https://cdn.jsdelivr.net/npm/x",
        b"https://notworkers.dev.example.com/x",  # must not match on substring
    ):
        assert not is_abuse(u), u
