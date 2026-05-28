# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from pkgsentry.adapter import Finding
from pkgsentry.detonate.client import DetonationResult, PhaseResult
from pkgsentry.detonate.gate import should_detonate


def test_gate_triggers_for_suspicious():
    """Pipeline-level: suspicious verdict triggers detonation gate."""
    findings = [
        Finding(rule_id="yara.staged_payload_exec", category="yara", severity="high", confidence="medium"),
    ]
    assert should_detonate(
        verdict="suspicious", score=25, findings=findings,
        watchlist_rank=None, is_new_package=False,
    ) is True


def test_gate_skips_clean_no_watchlist():
    """Pipeline-level: clean non-watchlist package skips detonation."""
    assert should_detonate(
        verdict="clean", score=5, findings=[
            Finding(rule_id="iocs.url", category="iocs", severity="low", confidence="low"),
        ],
        watchlist_rank=None, is_new_package=False,
    ) is False


def test_detonation_findings_merge():
    """Static + dynamic findings merge and re-score correctly."""
    from pkgsentry.detect.score import score_and_verdict

    static_findings = [
        Finding(rule_id="malware.obfuscation", category="malware", severity="high", confidence="medium"),
    ]
    dynamic_findings = [
        Finding(rule_id="dyn_install_exfil", category="dynamic", severity="critical", confidence="high",
                evidence="connect(AF_INET, 45.33.32.156:443)"),
    ]
    combined = static_findings + dynamic_findings
    result = score_and_verdict(combined, watchlist_rank=None)
    assert result.verdict == "malicious"


def test_detonation_result_empty_findings_no_change():
    """Clean detonation doesn't change a suspicious verdict."""
    from pkgsentry.detect.score import score_and_verdict

    static_findings = [
        Finding(rule_id="malware.obfuscation", category="malware", severity="high", confidence="medium"),
    ]
    dynamic_findings = []
    combined = static_findings + dynamic_findings
    result = score_and_verdict(combined, watchlist_rank=None)
    assert result.verdict == "suspicious"


def test_enqueue_gate_local_detonation_enabled(monkeypatch):
    """A host with a local detonation client enqueues (unchanged behavior)."""
    from types import SimpleNamespace
    from pkgsentry.pipeline import _detonation_cluster_enabled
    monkeypatch.delenv("DETONATION_ENABLED", raising=False)
    assert _detonation_cluster_enabled(SimpleNamespace(is_enabled=lambda: True)) is True


def test_enqueue_gate_scan_only_host(monkeypatch):
    """A scan-only host (no local detonation) still enqueues when DETONATION_ENABLED=1."""
    from types import SimpleNamespace
    from pkgsentry.pipeline import _detonation_cluster_enabled
    monkeypatch.setenv("DETONATION_ENABLED", "1")
    assert _detonation_cluster_enabled(SimpleNamespace(is_enabled=lambda: False)) is True


def test_enqueue_gate_detonation_absent(monkeypatch):
    """No local client and no DETONATION_ENABLED → don't enqueue (no undrained pileup)."""
    from types import SimpleNamespace
    from pkgsentry.pipeline import _detonation_cluster_enabled
    monkeypatch.delenv("DETONATION_ENABLED", raising=False)
    assert _detonation_cluster_enabled(SimpleNamespace(is_enabled=lambda: False)) is False
