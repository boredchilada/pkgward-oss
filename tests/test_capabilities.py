# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import importlib

import pkgsentry.util.capabilities as capabilities


def test_capabilities_reports_all_three():
    caps = capabilities.capabilities()
    assert set(caps) == {"yara", "ppdeep", "tlsh"}
    assert all(isinstance(v, bool) for v in caps.values())


def test_log_capabilities_warns_when_missing(monkeypatch):
    events = []
    monkeypatch.setattr(capabilities.log, "warning", lambda *a, **k: events.append(("warn", a, k)))
    monkeypatch.setattr(capabilities.log, "info", lambda *a, **k: events.append(("info", a, k)))

    monkeypatch.setattr(capabilities, "HAS_TLSH", False)
    monkeypatch.setattr(capabilities, "HAS_YARA", True)
    monkeypatch.setattr(capabilities, "HAS_PPDEEP", True)

    capabilities.log_capabilities()
    assert events and events[0][0] == "warn"
    assert events[0][2]["missing"] == ["tlsh"]


def test_log_capabilities_info_when_all_present(monkeypatch):
    events = []
    monkeypatch.setattr(capabilities.log, "warning", lambda *a, **k: events.append(("warn", a, k)))
    monkeypatch.setattr(capabilities.log, "info", lambda *a, **k: events.append(("info", a, k)))

    monkeypatch.setattr(capabilities, "HAS_TLSH", True)
    monkeypatch.setattr(capabilities, "HAS_YARA", True)
    monkeypatch.setattr(capabilities, "HAS_PPDEEP", True)

    capabilities.log_capabilities()
    assert events and events[0][0] == "info"
