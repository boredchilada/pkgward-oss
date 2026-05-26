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
