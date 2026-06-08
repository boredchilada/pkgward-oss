# SPDX-License-Identifier: AGPL-3.0-or-later
"""Maintainer-pivot sweep — the THIRD sibling defense.

Three orthogonal "the wave is spreading" defenses key off a double-confirmed
malicious verdict:

  * same NAME      -> ``watchlist_auto``  (mark the name known-bad; every future
                                           release force-scanned, joins known_bad_deps)
  * same ORG/SCOPE -> ``scope_watchlist`` (watch the whole ``@org`` / path prefix)
  * same MAINTAINER -> **this module**    (force-scan the maintainer's OTHER
                                           packages — a compromised-account campaign
                                           that spreads across unrelated package
                                           NAMES with no shared org/scope)

The 2026-06-07 incident is the motivating case: a compromised PyPI account pushed
malicious versions across ~19 of its scientific-Python packages. We caught every
artifact we *ingested*, but missed 10 siblings whose payload never tripped the
size-anomaly ingest gate. A maintainer pivot turns one conviction into a sweep of
that account's catalog.

CRITICAL DESIGN — FORCE-SCAN ONLY, NEVER WATCHLIST. This module enqueues the
catalog at high priority and stops. Each swept package earns its own verdict
through the full detection+LLM+conf-floor pipeline; a legit sibling scans clean
and nothing happens. The worst case of a false-positive trigger is *wasted scans
on an innocent author's catalog* — pure throughput cost, zero watchlist
pollution and no self-reinforcing FP cascade (the graphifyy class). Contrast
``watchlist_auto``, which marks a name known-bad — we deliberately do NOT do that
here.

Trigger gate (far stricter than the alert bar — a single soft conviction must
never sweep an innocent maintainer's catalog). Requires EITHER:

  * CORRELATION — >= 2 of the maintainer's packages carry a recent
    double-confirmed (rule AND llm ``malicious``) scan (the campaign signal), OR
  * a single HIGH-FIDELITY conviction — an exact threat-intel hash match, a
    behavioral-chain rule, or LLM confidence >= 0.95.

The convicting evidence must itself be a non-shadow, high/critical, PRIMARY
finding that survived the conf-floor — the caller only invokes us inside the
``_auto_watchlist_qualifies`` gate, and we re-check the primary-evidence bar here.
Shadow opengrep findings are never trigger-eligible.

SHADOW-FIRST. Default (``PKGWARD_MAINTAINER_PIVOT_SHADOW=1``) logs the
would-sweep set + trigger reason and enqueues NOTHING. Flip to active only after a
week of shadow data confirms triggers are real campaigns, not our FPs. Mirrors the
``OPENGREP_SHADOW`` rollout.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select

from pkgward import intel
from pkgward.adapter import Finding
from pkgward.detect.score import _is_shadow_finding
from pkgward.logging_setup import get_logger
from pkgward.store import session as sess
from pkgward.store.models import Package, Scan, Version
from pkgward.util.user_agent import user_agent

log = get_logger("maintainer_pivot")

# Only the two ecosystems with a real per-account catalog surface. crates is a flat
# namespace with owner metadata we don't ingest; gomod has no publisher account —
# both are gated out here and never crash.
SUPPORTED = ("pypi", "npm")

# Categories that are FP-prone or are themselves propagation signals — a lone
# high/critical hit from one of these is NOT primary evidence. Mirrors
# pipeline._NON_PRIMARY_PROMOTE_CATEGORIES.
_NON_PRIMARY = frozenset({"iocs", "dep_intel", "metadata", "version_diff"})

_HIGH_FIDELITY_CONF = 0.95


# --------------------------------------------------------------------------- env
def is_enabled() -> bool:
    return os.environ.get("PKGWARD_MAINTAINER_PIVOT", "1").lower() not in (
        "0", "false", "off", "no",
    )


def is_shadow() -> bool:
    return os.environ.get("PKGWARD_MAINTAINER_PIVOT_SHADOW", "1").lower() not in (
        "0", "false", "off", "no",
    )


def _max_pkgs() -> int:
    return int(os.environ.get("PKGWARD_MAINTAINER_PIVOT_MAX_PKGS", "100"))


def _timeout() -> float:
    return float(os.environ.get("PKGWARD_MAINTAINER_PIVOT_TIMEOUT", "15"))


def _corr_days() -> int:
    return int(os.environ.get("PKGWARD_MAINTAINER_PIVOT_CORR_DAYS", "30"))


def _dedup_ttl() -> float:
    return float(os.environ.get("PKGWARD_MAINTAINER_PIVOT_DEDUP_TTL", "3600"))


def _trigger_rule_set(var: str) -> frozenset[str]:
    raw = os.environ.get(var, "").strip()
    if not raw:
        return frozenset()
    return frozenset(t.strip() for t in raw.split(",") if t.strip())


def _trigger_allow() -> frozenset[str]:
    """If set, ONLY these rule_ids may drive the pivot (precision-harness output)."""
    return _trigger_rule_set("PKGWARD_MAINTAINER_PIVOT_TRIGGER_ALLOW")


def _trigger_deny() -> frozenset[str]:
    """Rule_ids that may NEVER drive the pivot (a flaky rule's FP exit ramp)."""
    return _trigger_rule_set("PKGWARD_MAINTAINER_PIVOT_TRIGGER_DENY")


def _blocklisted(ecosystem: str, name: str) -> bool:
    """Reuse the watchlist_auto blocklist as the shared FP exit ramp."""
    from pkgward import watchlist_auto

    return name.lower() in watchlist_auto._blocklist().get(ecosystem, set())


# ---------------------------------------------------------------- per-maintainer dedup
# A 27-package campaign convicts ~27 times in a wave; each conviction would otherwise
# re-resolve and re-sweep the same catalog. Fire ~once per (eco, maintainer) per TTL.
_dedup_lock = threading.Lock()
_recent_sweeps: dict[str, float] = {}


def _dedup_key(ecosystem: str, maintainer: str) -> str:
    return f"{ecosystem}:{maintainer.lower()}"


def _recently_swept(key: str) -> bool:
    ttl = _dedup_ttl()
    if ttl <= 0:
        return False
    now = time.monotonic()
    with _dedup_lock:
        ts = _recent_sweeps.get(key)
        if ts is not None and (now - ts) < ttl:
            return True
        return False


def _mark_swept(key: str) -> None:
    with _dedup_lock:
        now = time.monotonic()
        _recent_sweeps[key] = now
        # Opportunistic prune so the dict can't grow unbounded across a long run.
        ttl = _dedup_ttl()
        if ttl > 0 and len(_recent_sweeps) > 4096:
            cutoff = now - ttl
            for k in [k for k, v in _recent_sweeps.items() if v < cutoff]:
                _recent_sweeps.pop(k, None)


def _reset_dedup_for_tests() -> None:
    with _dedup_lock:
        _recent_sweeps.clear()


# ----------------------------------------------------------------- trigger eligibility
def _trigger_eligible_findings(findings: list[Finding]) -> list[Finding]:
    """Non-shadow, high/critical, PRIMARY-category findings that pass the
    allow/deny rule filter — the only findings allowed to drive a sweep."""
    allow = _trigger_allow()
    deny = _trigger_deny()
    out: list[Finding] = []
    for f in findings:
        if _is_shadow_finding(f):
            continue
        if f.severity not in ("high", "critical"):
            continue
        if f.category in _NON_PRIMARY:
            continue
        if f.rule_id in deny:
            continue
        if allow and f.rule_id not in allow:
            continue
        out.append(f)
    return out


def _high_fidelity(findings: list[Finding], tri) -> tuple[bool, str]:
    """A single conviction strong enough to sweep on its own: exact threat-intel
    hash match, a behavioral-chain rule, or a >= 0.95-confidence LLM malicious
    verdict. Shadow/denied rules are excluded; PRIMARY-category filtering does not
    apply to threat_intel (its own category) or chains (inherently primary)."""
    deny = _trigger_deny()
    allow = _trigger_allow()
    chain_ids = intel.current().behavioral_chain_ids
    for f in findings:
        if _is_shadow_finding(f) or f.severity not in ("high", "critical"):
            continue
        if f.rule_id in deny or (allow and f.rule_id not in allow):
            continue
        if f.rule_id in chain_ids:
            return True, f"chain:{f.rule_id}"
        if f.category == "threat_intel":
            return True, f"threat_intel:{f.rule_id}"
    conf = getattr(tri, "confidence", None) or 0.0
    if getattr(tri, "verdict", None) == "malicious" and conf >= _HIGH_FIDELITY_CONF:
        return True, f"llm_conf:{conf:.2f}"
    return False, ""


# ------------------------------------------------------------------------ HTTP (sync)
# Runs in the synchronous persist thread (no event loop) and the CLI — sync httpx.
# SSRF-guarded + bounded + no redirect-following, mirroring ecosystems/npm/url_deps.
_MAX_BODY_BYTES = 8 * 1024 * 1024


def _ssrf_safe(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    if not infos:
        return False
    for *_rest, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True


def _get_text(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if not host or not _ssrf_safe(host):
        log.warning("maintainer_pivot_ssrf_blocked", host=host)
        return ""
    try:
        with httpx.Client(headers={"User-Agent": user_agent()},
                          follow_redirects=False, timeout=_timeout()) as client:
            with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return ""
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > _MAX_BODY_BYTES:
                        return ""
                return buf.decode("utf-8", errors="replace")
    except Exception as e:
        log.warning("maintainer_pivot_fetch_failed", url=url[:120], error=str(e))
        return ""


def _get_json(url: str):
    import json

    text = _get_text(url)
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


# --------------------------------------------------------------------- catalog: pypi
_PYPI_USER_RE = re.compile(r'href="/user/([^/"]+)/"')
_PYPI_PROJECT_RE = re.compile(r'href="/project/([^/"]+)/"')


def parse_pypi_maintainers(project_html: str) -> list[str]:
    """Usernames linked from a PyPI project page sidebar (``/user/<name>/``)."""
    seen: list[str] = []
    for u in _PYPI_USER_RE.findall(project_html):
        if u and u not in seen:
            seen.append(u)
    return seen


def parse_pypi_user_projects(user_html: str) -> list[str]:
    """Project names linked from a PyPI user profile page (``/project/<name>/``)."""
    seen: list[str] = []
    for p in _PYPI_PROJECT_RE.findall(user_html):
        if p and p not in seen:
            seen.append(p)
    return seen


def _pypi_resolve(name: str) -> tuple[list[str], list[str]]:
    """(maintainer usernames, catalog project names) for a PyPI package."""
    html = _get_text(f"https://pypi.org/project/{name}/")
    maintainers = parse_pypi_maintainers(html)
    catalog: list[str] = []
    for user in maintainers[:3]:
        user_html = _get_text(f"https://pypi.org/user/{user}/")
        for proj in parse_pypi_user_projects(user_html):
            if proj not in catalog:
                catalog.append(proj)
    return maintainers, catalog


def _pypi_latest_version(name: str) -> Optional[str]:
    data = _get_json(f"https://pypi.org/pypi/{name}/json")
    if isinstance(data, dict):
        v = (data.get("info") or {}).get("version")
        return str(v) if v else None
    return None


# ---------------------------------------------------------------------- catalog: npm
def parse_npm_maintainers(packument: dict) -> list[str]:
    out: list[str] = []
    for m in (packument.get("maintainers") or []):
        nm = m.get("name") if isinstance(m, dict) else None
        if nm and nm not in out:
            out.append(nm)
    return out


def parse_npm_search(search_json: dict) -> dict[str, str]:
    """``{package_name: version}`` from a registry ``/-/v1/search`` response."""
    out: dict[str, str] = {}
    for obj in (search_json.get("objects") or []):
        pkg = obj.get("package") if isinstance(obj, dict) else None
        if isinstance(pkg, dict) and pkg.get("name"):
            out[str(pkg["name"])] = str(pkg.get("version") or "")
    return out


def _npm_resolve(name: str) -> tuple[list[str], dict[str, str]]:
    """(maintainer usernames, {catalog_name: version}) for an npm package."""
    packument = _get_json(f"https://registry.npmjs.org/{name}")
    maintainers = parse_npm_maintainers(packument) if isinstance(packument, dict) else []
    catalog: dict[str, str] = {}
    for user in maintainers[:3]:
        res = _get_json(
            f"https://registry.npmjs.org/-/v1/search?text=maintainer:{user}&size=250"
        )
        if isinstance(res, dict):
            catalog.update(parse_npm_search(res))
    return maintainers, catalog


# ----------------------------------------------------------------------- correlation
def _double_confirmed_names(session, ecosystem: str, names: set[str]) -> set[str]:
    """The subset of *names* carrying a recent double-confirmed (rule AND llm
    malicious) scan — the campaign signal (its size is the correlation count, and the
    set itself is excluded from the clean-sibling watch). Bounded by the window."""
    if not names:
        return set()
    cutoff = datetime.now(timezone.utc) - timedelta(days=_corr_days())
    rows = session.execute(
        select(func.distinct(Package.name))
        .select_from(Scan)
        .join(Version, Scan.version_id == Version.id)
        .join(Package, Version.package_id == Package.id)
        .where(
            Package.ecosystem == ecosystem,
            func.lower(Package.name).in_({n.lower() for n in names}),
            Scan.verdict == "malicious",
            Scan.llm_verdict == "malicious",
            Scan.finished_at >= cutoff,
        )
    ).all()
    return {r[0].lower() for r in rows}


def _register_clean_watches(
    ecosystem: str, clean_siblings: list[str], maintainer: str,
) -> int:
    """Bounded force-scan watch on the maintainer's CLEAN siblings (force-scan only,
    never known-bad). Fresh short session. Returns the number watched."""
    from pkgward import maintainer_watch

    if not maintainer_watch.is_enabled() or not clean_siblings:
        return 0
    n = 0
    with sess.session_scope() as s:
        for sib in clean_siblings:
            if _blocklisted(ecosystem, sib):
                continue
            try:
                if maintainer_watch.add_watch(s, ecosystem, sib, maintainer=maintainer):
                    n += 1
            except Exception as e:
                log.warning("maintainer_watch_add_failed",
                            ecosystem=ecosystem, name=sib, error=str(e))
    return n


# ---------------------------------------------------------------------------- enqueue
def _enqueue_catalog(
    ecosystem: str, catalog: dict[str, str], *, exclude: str,
) -> int:
    """Force-scan each catalog package's latest version at HIGH priority in a fresh,
    short session. NEVER touches the watchlist. Returns the number enqueued."""
    from pkgward import queue

    enqueued = 0
    budget_until = time.monotonic() + max(_timeout() * 4, 30.0)
    with sess.session_scope() as s:
        for name, version in catalog.items():
            if name.lower() == exclude.lower():
                continue
            if not version:
                if time.monotonic() > budget_until:
                    log.warning("maintainer_pivot_version_budget_exhausted",
                                ecosystem=ecosystem, remaining=name)
                    break
                if ecosystem == "pypi":
                    version = _pypi_latest_version(name) or ""
            if not version:
                continue
            try:
                queue.enqueue(s, ecosystem=ecosystem, name=name,
                              version=version, priority="high")
                enqueued += 1
            except Exception as e:
                log.warning("maintainer_pivot_enqueue_failed",
                            ecosystem=ecosystem, name=name, error=str(e))
    return enqueued


# --------------------------------------------------------------------------- the sweep
def sweep_on_malicious(
    ecosystem: str,
    name: str,
    *,
    findings: Optional[list[Finding]] = None,
    tri=None,
    source: str = "auto",
) -> dict:
    """Maintainer-pivot entry point. Resolves the maintainer's catalog and, if the
    trigger gate passes, force-scans it (or shadow-logs the would-sweep set).

    Manages its own network + DB lifecycle — call it with NO session held: the
    catalog fetch must not run inside a held transaction, and the enqueue writes go
    through a fresh short ``session_scope`` (detonation-worker discipline).

    *source* ``"manual"`` (CLI) bypasses the evidence-bar pre-check so an operator
    can force a backfill sweep; the shadow flag is still honored.

    Returns a structured outcome dict (logged by the caller / printed by the CLI).
    """
    findings = findings or []
    if not is_enabled():
        return {"action": "disabled"}
    if ecosystem not in SUPPORTED:
        return {"action": "unsupported_ecosystem", "ecosystem": ecosystem}
    if _blocklisted(ecosystem, name):
        return {"action": "blocklisted", "name": name}

    auto = source != "manual"
    eligible = _trigger_eligible_findings(findings)
    hi, hi_reason = _high_fidelity(findings, tri)
    if auto and not eligible and not hi:
        return {"action": "skip", "reason": "no_primary_evidence", "name": name}

    try:
        if ecosystem == "pypi":
            maintainers, catalog_names = _pypi_resolve(name)
            catalog = {n: "" for n in catalog_names}
        else:  # npm
            maintainers, catalog = _npm_resolve(name)
    except Exception as e:
        log.warning("maintainer_pivot_resolve_failed",
                    ecosystem=ecosystem, name=name, error=str(e))
        return {"action": "skip", "reason": "resolve_failed", "name": name}

    if not maintainers:
        return {"action": "skip", "reason": "no_maintainer_resolved", "name": name}

    dkey = _dedup_key(ecosystem, maintainers[0])
    if _recently_swept(dkey):
        return {"action": "skip", "reason": "deduped", "maintainer": maintainers[0]}

    catalog_size = len(set(catalog) | {name})
    if catalog_size > _max_pkgs():
        # A huge catalog is almost certainly a legit prolific author, not a campaign.
        log.info("maintainer_pivot_catalog_too_large", ecosystem=ecosystem,
                 maintainer=maintainers[0], catalog_size=catalog_size, cap=_max_pkgs())
        _mark_swept(dkey)
        return {"action": "skip", "reason": "catalog_too_large",
                "maintainer": maintainers[0], "catalog_size": catalog_size}

    # Correlation needs DB; fresh short session, no network held across it.
    corr_names = set(catalog) | {name}
    try:
        with sess.session_scope() as s:
            malicious_names = _double_confirmed_names(s, ecosystem, corr_names)
    except Exception as e:
        log.warning("maintainer_pivot_correlation_failed",
                    ecosystem=ecosystem, name=name, error=str(e))
        malicious_names = set()
    corr = len(malicious_names)

    triggered = hi or corr >= 2
    if not triggered:
        return {"action": "skip", "reason": "single_soft_conviction_no_correlation",
                "maintainer": maintainers[0], "correlation": corr,
                "catalog_size": catalog_size}

    trigger = hi_reason if hi else f"correlation:{corr}"
    _mark_swept(dkey)

    # Clean siblings = catalog minus the trigger and minus any sibling already known
    # malicious (those graduate to watchlist_auto on their own scan). These get the
    # bounded force-scan watch so a sibling poisoned a release or two LATER is caught.
    excluded = {name.lower()} | malicious_names
    clean_siblings = [c for c in catalog if c.lower() not in excluded]

    if is_shadow():
        log.info("maintainer_pivot_shadow", ecosystem=ecosystem,
                 maintainer=maintainers[0], catalog_size=catalog_size,
                 trigger=trigger, source=source,
                 would_sweep=sorted(set(catalog) | {name})[:50],
                 would_watch=len(clean_siblings))
        return {"action": "shadow", "maintainer": maintainers[0],
                "catalog_size": catalog_size, "trigger": trigger,
                "would_watch": len(clean_siblings)}

    enqueued = _enqueue_catalog(ecosystem, catalog, exclude=name)
    try:
        watched = _register_clean_watches(ecosystem, clean_siblings, maintainers[0])
    except Exception as e:
        log.warning("maintainer_pivot_watch_failed",
                    ecosystem=ecosystem, name=name, error=str(e))
        watched = 0
    log.warning("maintainer_pivot_swept", ecosystem=ecosystem,
                maintainer=maintainers[0], catalog_size=catalog_size,
                enqueued=enqueued, watched=watched, trigger=trigger, source=source)
    return {"action": "swept", "maintainer": maintainers[0],
            "catalog_size": catalog_size, "enqueued": enqueued,
            "watched": watched, "trigger": trigger}
