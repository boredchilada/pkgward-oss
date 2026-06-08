# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import httpx
import pytest

from pkgward.enrich import downloads


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)


def _patch(monkeypatch, resp):
    monkeypatch.setattr(downloads, "_get", lambda url: resp)


def test_format_field():
    assert downloads.format_field(None) == "n/a"
    assert downloads.format_field(0) == "0 (no install base)"
    assert downloads.format_field(-3) == "0 (no install base)"
    assert downloads.format_field(12345) == "~12,345"


def test_unknown_ecosystem_and_empty_name():
    assert downloads.weekly_downloads("gomod", "x") is None
    assert downloads.weekly_downloads("npm", "") is None


def test_npm_ok(monkeypatch):
    _patch(monkeypatch, _Resp(200, {"downloads": 9876}))
    assert downloads.weekly_downloads("npm", "left-pad") == 9876


def test_npm_404_is_zero(monkeypatch):
    # npm 404 = no download record yet -> a real zero/new package.
    _patch(monkeypatch, _Resp(404))
    assert downloads.weekly_downloads("npm", "@scope/brand-new") == 0


def test_pypi_ok(monkeypatch):
    _patch(monkeypatch, _Resp(200, {"data": {"last_week": 555}}))
    assert downloads.weekly_downloads("pypi", "Requests") == 555


def test_pypi_404_is_unknown(monkeypatch):
    # pypistats 404 = no stats yet -> unknown (None), not a confirmed zero.
    _patch(monkeypatch, _Resp(404))
    assert downloads.weekly_downloads("pypi", "no-such-pkg") is None


def test_crates_weekly_estimate(monkeypatch):
    # recent_downloads is ~90d; weekly est = round(rd * 7 / 90).
    _patch(monkeypatch, _Resp(200, {"crate": {"recent_downloads": 9000}}))
    assert downloads.weekly_downloads("crates", "serde") == round(9000 * 7 / 90)


def test_fetch_error_is_soft(monkeypatch):
    def _boom(url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(downloads, "_get", _boom)
    assert downloads.weekly_downloads("npm", "x") is None


def test_missing_field_is_none(monkeypatch):
    _patch(monkeypatch, _Resp(200, {"crate": {}}))
    assert downloads.weekly_downloads("crates", "x") is None
