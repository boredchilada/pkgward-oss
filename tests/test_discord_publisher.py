# SPDX-License-Identifier: AGPL-3.0-or-later
"""Discord alert: publisher/author identity is surfaced, and finding evidence is no
longer truncated so short of showing the exfil host."""
from __future__ import annotations

from pkgward.adapter import Finding
from pkgward.llm.triage import LLMTriageResult
from pkgward.notify.discord import _build_embed, _publisher_field


def _tri():
    return LLMTriageResult(verdict="malicious", confidence=0.9, reasoning="x", iocs=[],
                           agrees_with_rules=True, model="m", prompt_tokens=0,
                           completion_tokens=0, cost_usd=0.0, latency_ms=0, raw_response={})


def test_publisher_field_rendered():
    pub = {"author": "arielsimon", "author_email": "ariel@vigilance.security",
           "maintainers": [{"name": "arielsimon", "email": "ariel@vigilance.security"}],
           "upload_user": "arielsimon"}
    f = _publisher_field(pub)
    assert f and f["name"] == "Publisher"
    assert "arielsimon" in f["value"] and "vigilance" in f["value"]
    assert _publisher_field(None) is None
    assert _publisher_field({}) is None


def test_full_exfil_host_not_truncated():
    host = "npm-package-logger-228835561205.europe-west1.run.app"
    f = Finding(rule_id="dyn_install_exfil", category="dynamic", severity="high",
                confidence="high", file="", line=None,
                evidence=f"connect to a non-allowlisted host during install phase: {host} (1.2.3.4):443")
    pub = {"author": "arielsimon", "author_email": "ariel@vigilance.security",
           "maintainers": None, "upload_user": "arielsimon"}
    e = _build_embed(pkg_name="ai-sdk-helpers", pkg_version="1.3.1", ecosystem="npm",
                     rule_verdict="malicious", rule_score=83, n_findings=9, triage=_tri(),
                     findings=[f], downloads_weekly=0, publisher=pub)
    hits = next(fld["value"] for fld in e["fields"] if fld["name"] == "Top Rule Hits")
    # The full host survives (the old [:80] cut it at "...logger-22883"); it's defanged,
    # so check the distinctive tail parts rather than the raw dotted host.
    assert "europe-west1" in hits and "run.app" in hits, "the full exfil host must survive (was cut at 80 chars before)"
    assert any(fld["name"] == "Publisher" for fld in e["fields"])
