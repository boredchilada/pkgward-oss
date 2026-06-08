# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import re
import time
import threading
from typing import Optional

import httpx

from pkgward.adapter import Finding
from pkgward.enrich.downloads import format_field as _downloads_field
from pkgward.llm.triage import LLMTriageResult
from pkgward.node_id import node_label
from pkgward.logging_setup import get_logger

log = get_logger("notify.discord")

REGISTRY_URLS: dict[str, str] = {
    "pypi": "https://pypi.org/project/{name}/{version}/",
    "crates": "https://crates.io/crates/{name}/{version}",
    "gomod": "https://pkg.go.dev/{name}@{version}",
    "npm": "https://www.npmjs.com/package/{name}/v/{version}",
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


def _fmt_maintainers(m) -> str:
    """Render the maintainers column (npm list of {name,email} / list / string)."""
    if isinstance(m, str):
        return m
    if isinstance(m, list):
        out = []
        for x in m[:6]:
            if isinstance(x, dict):
                nm = x.get("name") or x.get("email") or ""
                if nm:
                    out.append(str(nm))
            elif x:
                out.append(str(x))
        return ", ".join(out)
    return ""


def _publisher_field(publisher: Optional[dict]) -> Optional[dict]:
    """Author / publisher identity for supply-chain triage — the email domain and the
    actual uploader often reveal the actor (a fresh gmail, a research firm, a typo'd
    org). Defanged so Discord doesn't auto-link it."""
    if not publisher:
        return None
    lines = []
    author = (publisher.get("author") or "").strip()
    email = (publisher.get("author_email") or "").strip()
    if author or email:
        lines.append("Author: " + (_defang(author) if author else "")
                     + (f" <{_defang(email)}>" if email else ""))
    uploader = (publisher.get("upload_user") or "").strip()
    if uploader:
        lines.append(f"Published by: `{_defang(uploader)}`")
    names = _fmt_maintainers(publisher.get("maintainers"))
    if names:
        lines.append(f"Maintainers: {_defang(names)}")
    if not lines:
        return None
    return {"name": "Publisher", "value": "\n".join(lines)[:1024], "inline": False}


def _build_embed(
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    rule_verdict: str,
    rule_score: int,
    n_findings: int,
    triage: LLMTriageResult,
    findings: list[Finding],
    downloads_weekly: Optional[int] = None,
    publisher: Optional[dict] = None,
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
        {"name": "Downloads/week", "value": _downloads_field(downloads_weekly), "inline": True},
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

    if findings:
        fields.append({
            "name": "Top Rule Hits",
            "value": _render_top_findings(findings)[:1024],
            "inline": False,
        })

    pub = _publisher_field(publisher)
    if pub:
        fields.append(pub)

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
            "text": f"pkgward | {node_label()} | latency: {triage.latency_ms}ms | cost: ${triage.cost_usd:.4f}",
        },
    }
    return embed


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def _render_top_findings(
    findings: list[Finding], *, limit: int = 8, evidence_cap: int = 240,
) -> str:
    """Render the Top Rule Hits field: one line per distinct (rule_id, evidence),
    highest severity/confidence first. Identical hits across files collapse into a
    ×N count with the file list summarized — the deepalpha alert rendered the same
    URL finding three times verbatim (once per file) and showed `N/A` for findings
    that had a file but no line."""
    groups: dict[tuple[str, str], dict] = {}
    for f in findings:
        g = groups.setdefault((f.rule_id, f.evidence or ""), {"f": f, "count": 0, "files": []})
        g["count"] += 1
        if (_SEVERITY_RANK.get(f.severity, 9), _CONFIDENCE_RANK.get(f.confidence, 9)) < (
            _SEVERITY_RANK.get(g["f"].severity, 9), _CONFIDENCE_RANK.get(g["f"].confidence, 9)
        ):
            g["f"] = f
        loc = f"{f.file}:{f.line}" if f.file and f.line is not None else (f.file or "")
        if loc and loc not in g["files"]:
            g["files"].append(loc)
    ordered = sorted(
        groups.values(),
        key=lambda g: (_SEVERITY_RANK.get(g["f"].severity, 9),
                       _CONFIDENCE_RANK.get(g["f"].confidence, 9)),
    )
    lines = []
    for g in ordered[:limit]:
        f = g["f"]
        head = f"**{f.rule_id}** [{f.severity}/{f.confidence}]"
        if g["count"] > 1:
            head += f" ×{g['count']}"
        if g["files"]:
            head += f" `{g['files'][0]}`"
            if len(g["files"]) > 1:
                head += f" (+{len(g['files']) - 1} more files)"
        evidence = _defang(f.evidence[:evidence_cap]) if f.evidence else ""
        lines.append(head + (f"\n{evidence}" if evidence else ""))
    if len(ordered) > limit:
        lines.append(f"… +{len(ordered) - limit} more distinct hits")
    return "\n".join(lines)


_ALERT_MAX_ATTEMPTS = 4


def _throttle() -> None:
    """Stagger sends by MIN_INTERVAL without holding the lock across the sleep.
    Reserve this send's slot under the lock, then sleep unlocked, so concurrent
    senders (scan workers + the detonation pool) don't serialize on a held lock
    during a malware burst."""
    global _last_send
    with _rate_lock:
        now = time.monotonic()
        target = max(now, _last_send + MIN_INTERVAL)
        _last_send = target
    wait = target - time.monotonic()
    if wait > 0:
        time.sleep(wait)


def _sanitize_embed(embed: dict) -> dict:
    """Clamp an embed to Discord's hard limits so a long field can't 400 the whole
    alert (the IOC/Top-Rule-Hits fields can exceed 1024 chars, which Discord rejects
    with `{"embeds": ["0"]}` — silently dropping a real alert). Limits: field value
    ≤1024, name ≤256, title ≤256, description ≤4096, footer ≤2048, ≤25 fields, and a
    6000-char overall budget. Empty field values are rejected by Discord, so we
    placeholder them rather than drop (keeps the field's label visible)."""
    if embed.get("title"):
        embed["title"] = embed["title"][:256]
    if embed.get("description"):
        embed["description"] = embed["description"][:4096]
    foot = embed.get("footer", {}).get("text")
    if foot:
        embed["footer"]["text"] = foot[:2048]
    fields = embed.get("fields", [])[:25]
    budget = 6000 - len(embed.get("title", "")) - len(embed.get("description", ""))
    out = []
    for f in fields:
        name = (f.get("name") or "·")[:256]
        value = (f.get("value") or "—")[:1024] or "—"
        if budget - len(name) - len(value) < 0:
            break  # would blow the 6000 overall cap — stop adding fields
        budget -= len(name) + len(value)
        out.append({**f, "name": name, "value": value})
    embed["fields"] = out
    return embed


def _post_embed(embed: dict, *, pkg_name: str, pkg_version: str) -> bool:
    """Rate-limited webhook POST with bounded retry. Best-effort — never raises.

    Discord is the only signal an operator gets, so a transient failure must not
    silently drop a real malicious-package alert. Retries timeouts / connection
    errors / 5xx with backoff, and honors a 429 ``retry_after``. A non-retryable
    4xx (e.g. a bad webhook URL) fails fast and loud."""
    url = os.environ.get(WEBHOOK_URL_ENV)
    if not url:
        return False

    payload = {"username": "pkgward", "embeds": [_sanitize_embed(embed)]}
    for attempt in range(_ALERT_MAX_ATTEMPTS):
        _throttle()
        try:
            resp = httpx.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
            if resp.status_code == 204:
                log.info("discord_alert_sent", name=pkg_name, version=pkg_version)
                return True
            if resp.status_code == 429:
                try:
                    retry_after = float(resp.json().get("retry_after", 1.0))
                except Exception:
                    retry_after = 1.0
                log.warning("discord_alert_rate_limited", retry_after=retry_after,
                            attempt=attempt + 1)
                if attempt < _ALERT_MAX_ATTEMPTS - 1:
                    time.sleep(min(retry_after, 30.0))
                    continue
                return False
            if 500 <= resp.status_code < 600 and attempt < _ALERT_MAX_ATTEMPTS - 1:
                log.warning("discord_alert_retrying", status=resp.status_code,
                            attempt=attempt + 1)
                time.sleep(0.5 * (2 ** attempt))
                continue
            # Non-retryable (4xx other than 429) — fail fast and loud.
            log.warning("discord_alert_failed", status=resp.status_code, body=resp.text[:200])
            return False
        except Exception as e:
            log.warning("discord_alert_error", error=str(e), attempt=attempt + 1)
            if attempt < _ALERT_MAX_ATTEMPTS - 1:
                time.sleep(0.5 * (2 ** attempt))
                continue
            return False
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
    downloads_weekly: Optional[int] = None,
    publisher: Optional[dict] = None,
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
        findings=findings,
        downloads_weekly=downloads_weekly,
        publisher=publisher,
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
    downloads_weekly: Optional[int] = None,
    publisher: Optional[dict] = None,
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
        {"name": "Downloads/week", "value": _downloads_field(downloads_weekly), "inline": True},
    ]
    if findings:
        fields.append({"name": "Top Rule Hits",
                       "value": _render_top_findings(findings)[:1024], "inline": False})
    pub = _publisher_field(publisher)
    if pub:
        fields.append(pub)
    fields.append({"name": "Registry", "value": f"`{registry_url}`", "inline": False})

    embed = {
        "title": "⚠️ Malicious Package Detected (detonation)",
        "description": f"Detonation flipped **{pkg_name}** {pkg_version} to **{new_verdict}** (static verdict: {static_verdict})",
        "color": 0xED4245,
        "fields": fields,
        "footer": {"text": f"pkgward | {node_label()} | dynamic detonation"},
    }
    return _post_embed(embed, pkg_name=pkg_name, pkg_version=pkg_version)


def send_review_alert(
    *,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    rule_verdict: str,
    rule_score: int,
    n_findings: int,
    triage: LLMTriageResult,
    findings: list[Finding],
    publisher: Optional[dict] = None,
) -> bool:
    """Lower-key 'needs human review' alert: the LLM returned *inconclusive* — it
    refused to escalate a weak signal, or could not see the evidence it needed. Leads
    with what it was missing so a human can decide. Best-effort — never raises."""
    if not os.environ.get(WEBHOOK_URL_ENV):
        return False
    url_template = REGISTRY_URLS.get(ecosystem, f"https://example.com/{ecosystem}/{{name}}/{{version}}")
    registry_url = _defang(url_template.format(name=pkg_name, version=pkg_version))

    fields = [
        {"name": "Package", "value": f"`{pkg_name}=={pkg_version}`", "inline": True},
        {"name": "Ecosystem", "value": ecosystem, "inline": True},
        {"name": "Rule Verdict", "value": f"{rule_verdict} (score: {rule_score})", "inline": True},
        {"name": "LLM Verdict", "value": "INCONCLUSIVE", "inline": True},
        {"name": "Findings", "value": str(n_findings), "inline": True},
        {"name": "Model", "value": triage.model, "inline": True},
    ]
    if triage.missing_evidence:
        fields.append({"name": "Missing Evidence", "value": _defang(triage.missing_evidence[:1024]), "inline": False})
    if triage.reasoning:
        fields.append({"name": "LLM Reasoning", "value": _defang(triage.reasoning[:1024]), "inline": False})
    if findings:
        fields.append({"name": "Top Rule Hits",
                       "value": _render_top_findings(findings, limit=6, evidence_cap=200)[:1024],
                       "inline": False})
    pub = _publisher_field(publisher)
    if pub:
        fields.append(pub)
    fields.append({"name": "Registry", "value": f"`{registry_url}`", "inline": False})

    embed = {
        "title": "🔍 Needs Review (LLM inconclusive)",
        "description": f"**{pkg_name}** {pkg_version} — the LLM could not decide; a human should look. See Missing Evidence.",
        "color": 0xFEE75C,  # amber — distinct from the red malicious alarm
        "fields": fields,
        "footer": {"text": f"pkgward | {node_label()} | needs review"},
    }
    return _post_embed(embed, pkg_name=pkg_name, pkg_version=pkg_version)
