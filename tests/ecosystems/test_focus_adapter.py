# SPDX-License-Identifier: AGPL-3.0-or-later
"""schedule_jobs guards watchlist refresh on focus-exclusive mode and always
registers the focus poller."""
import pytest

from pkgsentry.ecosystems.pypi.adapter import PyPIAdapter
from pkgsentry.ecosystems.crates.adapter import CratesAdapter
from pkgsentry.ecosystems.gomod.adapter import GoModAdapter


class _StubScheduler:
    def __init__(self):
        self.ids = []

    def add_job(self, func, trigger=None, **kwargs):
        self.ids.append(kwargs.get("id"))


CASES = [
    (PyPIAdapter, "pypi_focus", "pypi_watchlist_refresh"),
    (CratesAdapter, "crates_focus", "crates_watchlist_refresh"),
    (GoModAdapter, "gomod_focus", "gomod_watchlist_refresh"),
]


@pytest.mark.parametrize("adapter_cls,focus_id,wl_id", CASES)
def test_additive_registers_both(adapter_cls, focus_id, wl_id, monkeypatch):
    monkeypatch.delenv("PKGSENTRY_FOCUS_EXCLUSIVE", raising=False)
    sch = _StubScheduler()
    adapter_cls().schedule_jobs(sch)
    assert focus_id in sch.ids
    assert wl_id in sch.ids


@pytest.mark.parametrize("adapter_cls,focus_id,wl_id", CASES)
def test_exclusive_omits_watchlist_keeps_focus(adapter_cls, focus_id, wl_id, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    sch = _StubScheduler()
    adapter_cls().schedule_jobs(sch)
    assert focus_id in sch.ids
    assert wl_id not in sch.ids
