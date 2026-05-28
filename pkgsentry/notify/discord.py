# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import re
import time
import threading
from typing import Optional

import httpx

from pkgsentry.adapter import Finding
from pkgsentry.llm.triage import LLMTriageResult
from pkgsentry.logging_setup import get_logger

log = get_logger("notify.discord")

REGISTRY_URLS: dict[str, str] = {
    "pypi": "https://pypi.org/project/{name}/{version}/",
    "crates": "https://crates.io/crates/{name}/{version}",
    "gomod": "https://pkg.go.dev/{name}@{version}",
}

WEBHOOK_URL_ENV = "DISCORD_WEBHOOK_URL"
WEBHOOK_TIMEOUT = 15.0

# Rate-limit: Discord allows 30 requests per 60s per webhook.
_rate_lock = threading.Lock()
_last_send: float = 0.0
MIN_INTERVAL = 2.5  # seconds between sends


def is_enabled() -> bool:
    return bool(os.environ.get(WEBHOOK_URL_ENV))


def _defang(text: str) -> str:
    """Defang URLs, IPs, and domains so Discord/AV doesn't flag the message."""
    text = re.sub(r"https?://", lambda m: m.group(0).replace("://", "[://]"), text)
    text = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", text)
    text = re.sub(r"(?<=[a-zA-Z0-9])\.(?=com|net|org|io|ai|dev|xyz|ru|cn|tk|ml|ga|cf|info|biz|top|cc|pw)", "[.]", text)
    return text


def _severity_color(verdict: str, confidence: float) -> int:
    """Discord embed color as int. Red for malicious, orange for suspicious."""
    if verdict == "malicious":
        return 0xED4245 if confidence >= 0.7 else 0xE67E22
    return 0xFEE75C


def _build_embed(
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    rule_verdict: str,
    rule_score: int,
    n_findings: int,
    triage: LLMTriageResult,
    top_findings: list[Finding],
) -> dict:
    # Grey when the LLM couldn't adjudicate (fail-open alert); red/orange when it did.
    unverified = triage.verdict not in ("malicious", "suspicious", "benign")
    color = 0x95A5A6 if unverified else _severity_color(triage.verdict, triage.confidence)
    url_template = REGISTRY_URLS.get(ecosystem, f"https://example.com/{ecosystem}/{{name}}/{{version}}")
    registry_url = _defang(url_template.format(name=pkg_name, version=pkg_version))

    fields = [
        {"name": "Package", "value": f"`{pkg_name}=={pkg_version}`", "inline": True},
        {"name": "Ecosystem", "value": ecosystem, "inline": True},
        {"name": "LLM Verdict", "value": f"**{triage.verdict.upper()}** ({triage.confidence:.0%})", "inline": True},
        {"name": "Rule Verdict", "value": f"{rule_verdict} (score: {rule_score})", "inline": True},
        {"name": "Findings", "value": str(n_findings), "inline": True},
        {"name": "Model", "value": triage.model, "inline": True},
    ]

    reasoning = _defang(triage.reasoning[:1000]) if triage.reasoning else "No reasoning provided"
    fields.append({"name": "LLM Reasoning", "value": reasoning, "inline": False})

    if triage.iocs:
        ioc_lines = []
        for ioc in triage.iocs[:15]:
            ioc_type = ioc.get("type", "unknown")
            ioc_value = _defang(ioc.get("value", ""))
            ioc_lines.append(f"`{ioc_type}`: `{ioc_value}`")
        fields.append({
            "name": f"IOCs ({len(triage.iocs)})",
            "value": "\n".join(ioc_lines),
            "inline": False,
        })

    if top_findings:
        finding_lines = []
        for f in top_findings[:8]:
            loc = f"`{f.file}:{f.line}`" if f.file and f.line else "`N/A`"
            evidence = _defang(f.evidence[:80]) if f.evidence else ""
            finding_lines.append(f"**{f.rule_id}** [{f.severity}/{f.confidence}] {loc}\n{evidence}")
        fields.append({
            "name": "Top Rule Hits",
            "value": "\n".join(finding_lines)[:1024],
            "inline": False,
        })

    fields.append({
        "name": "Registry",
        "value": f"`{registry_url}`",
        "inline": False,
    })

    if unverified:
        desc = (f"Rules flagged **{pkg_name}** {pkg_version} as **{rule_verdict}** — "
                f"LLM could not verify ({triage.verdict}). Review manually.")
    elif triage.agrees_with_rules is False:
        desc = f"Rules flagged **{pkg_name}** {pkg_version} as **{triage.verdict}** (LLM disagrees)"
    else:
        desc = f"LLM triage confirmed **{pkg_name}** {pkg_version} as **{triage.verdict}**"
    title = "⚠️ Suspect Package (LLM unverified)" if unverified else "⚠️ Malicious Package Detected"
    embed = {
        "title": title,
        "description": desc,
        "color": color,
        "fields": fields,
        "footer": {
            "text": f"pkgsentry | latency: {triage.latency_ms}ms | cost: ${triage.cost_usd:.4f}",
        },
    }
    return embed


def _pick_top_findings(findings: list[Finding], limit: int = 8) -> list[Finding]:
    """Pick the most interesting findings — high severity + high confidence first."""
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        findings,
        key=lambda f: (severity_rank.get(f.severity, 9), confidence_rank.get(f.confidence, 9)),
    )[:limit]


def _post_embed(embed: dict, *, pkg_name: str, pkg_version: str) -> bool:
    """Rate-limited webhook POST. Best-effort — never raises."""
    url = os.environ.get(WEBHOOK_URL_ENV)
    if not url:
        return False

    global _last_send
    with _rate_lock:
        now = time.monotonic()
        wait = MIN_INTERVAL - (now - _last_send)
        if wait > 0:
            time.sleep(wait)
        _last_send = time.monotonic()

    payload = {"username": "pkgsentry", "embeds": [embed]}
    try:
        resp = httpx.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
        if resp.status_code == 204:
            log.info("discord_alert_sent", name=pkg_name, version=pkg_version)
            return True
        log.warning("discord_alert_failed", status=resp.status_code, body=resp.text[:200])
        return False
    except Exception as e:
        log.warning("discord_alert_error", error=str(e))
        return False


def send_alert(
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    rule_verdict: str,
    rule_score: int,
    n_findings: int,
    triage: LLMTriageResult,
    findings: list[Finding],
) -> bool:
    """Post a Discord webhook alert. Returns True on success, False on failure.
    Best-effort — never raises."""
    if not os.environ.get(WEBHOOK_URL_ENV):
        return False
    embed = _build_embed(
        pkg_name=pkg_name,
        pkg_version=pkg_version,
        ecosystem=ecosystem,
        rule_verdict=rule_verdict,
        rule_score=rule_score,
        n_findings=n_findings,
        triage=triage,
        top_findings=_pick_top_findings(findings),
    )
    return _post_embed(embed, pkg_name=pkg_name, pkg_version=pkg_version)


def send_dynamic_alert(
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    static_verdict: str,
    new_verdict: str,
    new_score: int,
    n_findings: int,
    findings: list[Finding],
) -> bool:
    """Alert for a verdict flipped to malicious by async detonation (no LLM triage).
    Best-effort — never raises."""
    if not os.environ.get(WEBHOOK_URL_ENV):
        return False
    url_template = REGISTRY_URLS.get(ecosystem, f"https://example.com/{ecosystem}/{{name}}/{{version}}")
    registry_url = _defang(url_template.format(name=pkg_name, version=pkg_version))

    fields = [
        {"name": "Package", "value": f"`{pkg_name}=={pkg_version}`", "inline": True},
        {"name": "Ecosystem", "value": ecosystem, "inline": True},
        {"name": "Verdict", "value": f"**{new_verdict.upper()}** (score: {new_score})", "inline": True},
        {"name": "Static verdict", "value": static_verdict, "inline": True},
        {"name": "Findings", "value": str(n_findings), "inline": True},
    ]
    top = _pick_top_findings(findings)
    if top:
        finding_lines = []
        for f in top[:8]:
            loc = f"`{f.file}:{f.line}`" if f.file and f.line else "`N/A`"
            evidence = _defang(f.evidence[:80]) if f.evidence else ""
            finding_lines.append(f"**{f.rule_id}** [{f.severity}/{f.confidence}] {loc}\n{evidence}")
        fields.append({"name": "Top Rule Hits", "value": "\n".join(finding_lines)[:1024], "inline": False})
    fields.append({"name": "Registry", "value": f"`{registry_url}`", "inline": False})

    embed = {
        "title": "⚠️ Malicious Package Detected (detonation)",
        "description": f"Detonation flipped **{pkg_name}** {pkg_version} to **{new_verdict}** (static verdict: {static_verdict})",
        "color": 0xED4245,
        "fields": fields,
        "footer": {"text": "pkgsentry | dynamic detonation"},
    }
    return _post_embed(embed, pkg_name=pkg_name, pkg_version=pkg_version)
