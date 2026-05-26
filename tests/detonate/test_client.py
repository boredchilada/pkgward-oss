# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.detonate.client import (
    DetonationClient,
    DetonationResult,
    PhaseResult,
)


def test_result_to_findings():
    result = DetonationResult(
        detonation_id="det-abc123",
        status="completed",
        install_phase=PhaseResult(exit_code=0, duration_ms=4200, timed_out=False),
        import_phase=PhaseResult(exit_code=0, duration_ms=1100, timed_out=False),
        findings_json=[
            {
                "rule_id": "dyn_install_exfil",
                "category": "dynamic",
                "severity": "critical",
                "confidence": "high",
                "evidence": "connect(AF_INET, 45.33.32.156:443) during install phase",
            },
        ],
        total_trace_events=1247,
        trace_events_json=[],
        filtered_trace_events=3,
    )
    findings = result.to_findings()
    assert len(findings) == 1
    assert findings[0].rule_id == "dyn_install_exfil"
    assert findings[0].category == "dynamic"
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "high"


def test_result_no_findings():
    result = DetonationResult(
        detonation_id="det-xyz789",
        status="completed",
        install_phase=PhaseResult(exit_code=0, duration_ms=2000, timed_out=False),
        import_phase=PhaseResult(exit_code=0, duration_ms=500, timed_out=False),
        findings_json=[],
        total_trace_events=500,
        trace_events_json=[],
        filtered_trace_events=0,
    )
    assert result.to_findings() == []


def test_client_disabled_no_config():
    client = DetonationClient(socket_path=None, base_url=None)
    assert client.is_enabled() is False


def test_client_enabled_with_socket():
    client = DetonationClient(socket_path="/var/run/detonation/detonation.sock")
    assert client.is_enabled() is True


def test_client_enabled_with_url():
    client = DetonationClient(base_url="http://127.0.0.1:9100")
    assert client.is_enabled() is True


def test_result_timeout_status():
    result = DetonationResult(
        detonation_id="det-timeout",
        status="timeout",
        install_phase=PhaseResult(exit_code=-1, duration_ms=120000, timed_out=True),
        import_phase=None,
        findings_json=[
            {
                "rule_id": "dyn_install_exfil",
                "category": "dynamic",
                "severity": "critical",
                "confidence": "medium",
                "evidence": "connect attempt before timeout",
            },
        ],
        total_trace_events=200,
        trace_events_json=[],
        filtered_trace_events=1,
    )
    findings = result.to_findings()
    assert len(findings) == 1
    assert result.status == "timeout"
