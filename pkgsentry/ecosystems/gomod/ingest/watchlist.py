# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go modules watchlist — combined GitHub stars + awesome-go + critical infra."""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select, delete, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue, MAX_AUTO_ATTEMPTS
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Watchlist
from pkgsentry.util.user_agent import user_agent

log = get_logger("gomod.watchlist")

ECOSYSTEM = "gomod"
USER_AGENT = user_agent()
TOP_N = 10_000

GITHUB_API = "https://api.github.com"
AWESOME_GO_URL = "https://raw.githubusercontent.com/avelino/awesome-go/main/README.md"
GO_PROXY = "https://proxy.golang.org"

_GH_REPO_RE = re.compile(r"https?://github\.com/([^/\s\)]+/[^/\s\)#]+)")

STAR_BUCKETS = [
    (10000, None),
    (5000, 9999),
    (2000, 4999),
    (1000, 1999),
    (500, 999),
    (200, 499),
    (100, 199),
    (50, 99),
]

CRITICAL_INFRA: list[tuple[str, int]] = [
    ("k8s.io/kubernetes", 100_000),
    ("k8s.io/client-go", 90_000),
    ("k8s.io/api", 89_000),
    ("k8s.io/apimachinery", 88_000),
    ("k8s.io/kubectl", 87_000),
    ("k8s.io/klog/v2", 86_000),
    ("k8s.io/utils", 85_000),
    ("cloud.google.com/go", 80_000),
    ("cloud.google.com/go/storage", 79_000),
    ("cloud.google.com/go/bigquery", 78_000),
    ("google.golang.org/grpc", 75_000),
    ("google.golang.org/protobuf", 74_000),
    ("google.golang.org/api", 73_000),
    ("golang.org/x/crypto", 70_000),
    ("golang.org/x/net", 69_000),
    ("golang.org/x/oauth2", 68_000),
    ("golang.org/x/text", 67_000),
    ("golang.org/x/sys", 66_000),
    ("golang.org/x/tools", 65_000),
    ("golang.org/x/sync", 64_000),
    ("golang.org/x/mod", 63_000),
    ("golang.org/x/exp", 62_000),
    ("golang.org/x/time", 61_000),
    ("go.uber.org/zap", 55_000),
    ("go.uber.org/atomic", 54_000),
    ("go.uber.org/multierr", 53_000),
    ("go.uber.org/goleak", 52_000),
    ("go.etcd.io/etcd/client/v3", 50_000),
    ("go.etcd.io/bbolt", 49_000),
    ("go.opentelemetry.io/otel", 48_000),
    ("go.opentelemetry.io/contrib", 47_000),
    ("sigs.k8s.io/controller-runtime", 45_000),
    ("sigs.k8s.io/yaml", 44_000),
    ("sigs.k8s.io/kustomize", 43_000),
    ("helm.sh/helm/v3", 40_000),
    ("istio.io/istio", 38_000),
    ("oras.land/oras-go/v2", 35_000),
    ("mvdan.cc/sh/v3", 30_000),
    ("honnef.co/go/tools", 29_000),
]


def is_watchlist(session: Session, name: str) -> Optional[int]:
    # Case-insensitive: GitHub-hosted module paths are case-insensitive at the
    # platform level even though the Go proxy stores case-encoded variants.
    row = session.scalars(
        select(Watchlist).where(
            Watchlist.ecosystem == ECOSYSTEM,
            func.lower(Watchlist.name) == name.lower(),
        )
    ).first()
    return row.rank if row else None


async def _github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _fetch_github_top_go_repos() -> dict[str, int]:
    """Fetch top Go repos by stars using bucketed star-range queries.
    Returns {module_path: star_count}."""
    modules: dict[str, int] = {}
    headers = await _github_headers()
    has_token = "Authorization" in headers
    rate_delay = 2.5 if has_token else 6.5

    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        for lo, hi in STAR_BUCKETS:
            if len(modules) >= TOP_N:
                break

            stars_q = f"stars:{lo}..{hi}" if hi else f"stars:>={lo}"
            page = 1

            while page <= 10:
                q = f"language:go {stars_q}"
                try:
                    resp = await client.get(
                        f"{GITHUB_API}/search/repositories",
                        params={
                            "q": q,
                            "sort": "stars",
                            "order": "desc",
                            "per_page": 100,
                            "page": page,
                        },
                    )

                    if resp.status_code == 403:
                        retry_after = resp.headers.get("Retry-After", "60")
                        wait = min(int(retry_after), 120)
                        log.warning("github_rate_limited", wait=wait, bucket=stars_q)
                        await asyncio.sleep(wait)
                        continue

                    if resp.status_code == 422:
                        break

                    resp.raise_for_status()
                except httpx.HTTPStatusError as e:
                    log.warning("github_search_error", status=e.response.status_code, bucket=stars_q)
                    break
                except Exception as e:
                    log.warning("github_search_error", error=str(e), bucket=stars_q)
                    break

                data = resp.json()
                items = data.get("items", [])
                if not items:
                    break

                for repo in items:
                    full_name = repo.get("full_name", "")
                    stars = repo.get("stargazers_count", 0)
                    if full_name:
                        mod_path = f"github.com/{full_name}"
                        if mod_path not in modules:
                            modules[mod_path] = stars

                if len(items) < 100:
                    break
                page += 1
                await asyncio.sleep(rate_delay)

            log.info("github_bucket_done", bucket=stars_q, total_so_far=len(modules))

    return modules


async def _fetch_awesome_go_modules() -> dict[str, int]:
    """Parse awesome-go README for GitHub-hosted Go module paths.
    Returns {module_path: 0} (no star data from this source)."""
    modules: dict[str, int] = {}
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            resp = await client.get(AWESOME_GO_URL, timeout=30.0)
            resp.raise_for_status()
            readme = resp.text
    except Exception as e:
        log.warning("awesome_go_fetch_failed", error=str(e))
        return modules

    for match in _GH_REPO_RE.finditer(readme):
        owner_repo = match.group(1).rstrip("/").rstrip(".")
        if "/" not in owner_repo:
            continue
        parts = owner_repo.split("/")
        if len(parts) != 2:
            continue
        mod_path = f"github.com/{parts[0]}/{parts[1]}"
        if mod_path not in modules:
            modules[mod_path] = 0

    log.info("awesome_go_parsed", modules=len(modules))
    return modules


async def refresh_watchlist() -> int:
    """Build combined Go watchlist from GitHub stars + awesome-go + critical infra.
    Returns count of modules written."""
    log.info("watchlist_refresh_start")

    combined: dict[str, int] = {}

    for mod_path, pseudo_stars in CRITICAL_INFRA:
        combined[mod_path] = pseudo_stars

    gh_modules = await _fetch_github_top_go_repos()
    for mod_path, stars in gh_modules.items():
        if mod_path not in combined or stars > combined[mod_path]:
            combined[mod_path] = stars

    awesome_modules = await _fetch_awesome_go_modules()
    for mod_path in awesome_modules:
        if mod_path not in combined:
            combined[mod_path] = 0

    ranked = sorted(combined.items(), key=lambda x: -x[1])[:TOP_N]

    if not ranked:
        log.warning("watchlist_empty")
        return 0

    with sess.session_scope() as s:
        s.execute(delete(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM))
        for rank, (mod_path, stars) in enumerate(ranked, start=1):
            s.add(Watchlist(
                ecosystem=ECOSYSTEM,
                name=mod_path,
                rank=rank,
                downloads_last_30d=stars,
            ))

    log.info("gomod_watchlist_refreshed", count=len(ranked),
             github=len(gh_modules), awesome_go=len(awesome_modules),
             critical_infra=len(CRITICAL_INFRA))
    return len(ranked)


_VN_SUFFIXES: tuple[str, ...] = ("/v2", "/v3", "/v4", "/v5")


async def _resolve_latest_canonical(
    client: httpx.AsyncClient, mod_path: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve a module to (canonical_path, version, fail_reason).

    Probes the bare path; on 404 retries with /v2..v5 to handle Go's
    major-version path rule. Returns:
      (path, version, None)  on success
      (path, None, reason)   when proxy permanently rejects every variant
      (None, None, error)    on transient network error (caller should retry later)
    """
    async def _probe(path: str) -> tuple[str, Optional[str], str]:
        url = f"{GO_PROXY}/{_case_encode(path)}/@latest"
        try:
            resp = await client.get(url, timeout=15.0)
            if resp.status_code == 200:
                return "ok", resp.json().get("Version"), ""
            return "fail", None, resp.text[:200].replace("\n", " ")
        except Exception as e:
            return "err", None, repr(e)[:200]

    status, version, body = await _probe(mod_path)
    if status == "ok" and version:
        return mod_path, version, None
    if status == "err":
        return None, None, body
    for v in _VN_SUFFIXES:
        s2, v2, _ = await _probe(mod_path + v)
        if s2 == "ok" and v2:
            return mod_path + v, v2, None
    return mod_path, None, body


def _rename_watchlist_to_canonical(
    session: Session, original: str, canonical: str,
) -> bool:
    """Update Watchlist.name from original→canonical. Returns True if renamed.

    Watchlist has UNIQUE(ecosystem, name); if a row already exists at canonical
    we delete the original (its rank/stars info is already captured elsewhere)
    rather than fail the rename.
    """
    if original == canonical:
        return False
    existing = session.scalars(
        select(Watchlist).where(
            Watchlist.ecosystem == ECOSYSTEM,
            Watchlist.name == canonical,
        )
    ).first()
    if existing is not None:
        session.execute(
            delete(Watchlist).where(
                Watchlist.ecosystem == ECOSYSTEM,
                Watchlist.name == original,
            )
        )
        return True
    session.execute(
        update(Watchlist)
        .where(Watchlist.ecosystem == ECOSYSTEM, Watchlist.name == original)
        .values(name=canonical)
    )
    return True


def _record_unscannable(session: Session, mod_path: str, reason: str) -> bool:
    """Insert a sentinel failed scan_queue row so seed_missing_watchlist sees
    this path as 'known' on future boots and skips the redundant proxy probe.

    Marker shape: status='failed', version='unscannable', attempts=MAX so
    workers won't auto-retry. Idempotent; returns True if a new row was added.
    """
    existing = session.scalars(
        select(ScanQueue).where(
            ScanQueue.ecosystem == ECOSYSTEM,
            ScanQueue.name == mod_path,
            ScanQueue.version == "unscannable",
        )
    ).first()
    if existing is not None:
        return False
    row = ScanQueue(
        ecosystem=ECOSYSTEM,
        name=mod_path,
        version="unscannable",
        priority="normal",
        status="failed",
        attempts=MAX_AUTO_ATTEMPTS,
        last_error=f"proxy_unscannable:{reason[:240]}",
        finished_at=datetime.now(timezone.utc),
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
        return True
    except IntegrityError:
        return False


def _case_encode(path: str) -> str:
    out = []
    for ch in path:
        if ch.isupper():
            out.append("!")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)


async def seed_watchlist_queue(concurrency: int = 20) -> int:
    """Enqueue the latest version of every gomod watchlist module at high priority.
    Uses proxy.golang.org/@latest to resolve versions."""
    with sess.session_scope() as s:
        rows = s.scalars(
            select(Watchlist)
            .where(Watchlist.ecosystem == ECOSYSTEM)
            .order_by(Watchlist.rank.asc())
        ).all()
        names = [(r.name, r.rank) for r in rows]

    if not names:
        return 0

    sem = asyncio.Semaphore(concurrency)
    # (original_path, canonical_path|None, version|None, fail_reason|None)
    results: list[tuple[str, Optional[str], Optional[str], Optional[str]]] = []

    async def _resolve(client: httpx.AsyncClient, mod_path: str):
        async with sem:
            canonical, version, reason = await _resolve_latest_canonical(client, mod_path)
            results.append((mod_path, canonical, version, reason))

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        await asyncio.gather(*[_resolve(client, name) for name, _ in names])

    enq = renamed = sentinels = transient = 0
    successes = [(o, c, v) for o, c, v, _ in results if v is not None]
    unscannable = [(o, r) for o, c, v, r in results if c is not None and v is None]
    transient_errors = [(o, r) for o, c, v, r in results if c is None]
    transient = len(transient_errors)

    for i in range(0, len(successes), 100):
        chunk = successes[i:i + 100]
        for attempt in range(5):
            try:
                with sess.session_scope() as s:
                    for original, canonical, version in chunk:
                        if canonical != original and _rename_watchlist_to_canonical(s, original, canonical):
                            renamed += 1
                        row = enqueue(s, ecosystem=ECOSYSTEM, name=canonical,
                                      version=version, priority="high")
                        if row is not None and row.status == "pending":
                            enq += 1
                break
            except Exception as e:
                if attempt < 4:
                    await asyncio.sleep(2 * (attempt + 1))
                else:
                    log.warning("seed_enqueue_batch_failed", offset=i, error=str(e))

    if unscannable:
        try:
            with sess.session_scope() as s:
                for original, reason in unscannable:
                    if _record_unscannable(s, original, reason or "unknown"):
                        sentinels += 1
        except Exception as e:
            log.warning("sentinel_batch_failed", error=str(e))

    log.info("watchlist_seeded",
             enqueued=enq, resolved=len(successes), renamed=renamed,
             sentinels=sentinels, transient_errors=transient,
             total=len(names))
    return enq


async def seed_missing_watchlist(concurrency: int = 20) -> int:
    """Re-seed watchlist modules that have no scan_queue entry yet.

    For each missing path, probe proxy.golang.org/@latest (bare + /v2..v5).
    On success enqueue at high priority and rename Watchlist row to canonical
    path if /vN was needed. On permanent 404 record an unscannable sentinel so
    we stop reprobing on every boot. Comparison is case-insensitive."""
    with sess.session_scope() as s:
        already = set(
            (r or "").lower()
            for r in s.scalars(
                select(ScanQueue.name).where(ScanQueue.ecosystem == ECOSYSTEM)
            ).all()
        )
        wl_names = [
            r.name for r in s.scalars(
                select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM)
            ).all()
        ]

    missing = [n for n in wl_names if n.lower() not in already]
    if not missing:
        return 0

    log.info("seed_missing_start", missing=len(missing), total=len(wl_names))

    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, Optional[str], Optional[str], Optional[str]]] = []

    async def _resolve(client: httpx.AsyncClient, mod_path: str):
        async with sem:
            canonical, version, reason = await _resolve_latest_canonical(client, mod_path)
            results.append((mod_path, canonical, version, reason))

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        await asyncio.gather(*[_resolve(client, n) for n in missing])

    enq = renamed = sentinels = 0
    successes = [(o, c, v) for o, c, v, _ in results if v is not None]
    unscannable = [(o, r) for o, c, v, r in results if c is not None and v is None]
    transient = sum(1 for o, c, v, r in results if c is None)

    for i in range(0, len(successes), 100):
        chunk = successes[i:i + 100]
        try:
            with sess.session_scope() as s:
                for original, canonical, version in chunk:
                    if canonical != original and _rename_watchlist_to_canonical(s, original, canonical):
                        renamed += 1
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=canonical,
                                  version=version, priority="high")
                    if row is not None and row.status == "pending":
                        enq += 1
        except Exception as e:
            log.warning("seed_missing_batch_failed", offset=i, error=str(e))

    if unscannable:
        try:
            with sess.session_scope() as s:
                for original, reason in unscannable:
                    if _record_unscannable(s, original, reason or "unknown"):
                        sentinels += 1
        except Exception as e:
            log.warning("sentinel_batch_failed", error=str(e))

    log.info("seed_missing_done",
             enqueued=enq, resolved=len(successes), renamed=renamed,
             sentinels=sentinels, transient_errors=transient,
             missing=len(missing))
    return enq

    log.info("seed_missing_done", enqueued=enq, resolved=len(resolved),
             missing=len(missing))
    return enq
