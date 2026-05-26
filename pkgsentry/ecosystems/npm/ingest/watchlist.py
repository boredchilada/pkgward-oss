# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm watchlist — combined registry-search popularity + awesome-nodejs + critical infra.

npm has no single ranked "top-N by downloads" endpoint, so the watchlist is
assembled from three sources (mirroring gomod's stars + awesome-go + infra):

1. ``CRITICAL_INFRA`` — hardcoded keystone packages everything depends on
   (always present, top ranks).
2. Registry search popularity — paginate ``/-/v1/search`` over broad seed
   keywords with popularity weighting; rank by the popularity sub-score.
3. ``awesome-nodejs`` README — best-effort extraction of npm-shaped link texts;
   fills remaining slots, contributes little when extraction is sparse.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import enqueue
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Watchlist
from pkgsentry.util.user_agent import user_agent

log = get_logger("npm.watchlist")

ECOSYSTEM = "npm"
USER_AGENT = user_agent()
REGISTRY_BASE = "https://registry.npmjs.org"
SEARCH_URL = f"{REGISTRY_BASE}/-/v1/search"
AWESOME_NODEJS_URL = "https://raw.githubusercontent.com/sindresorhus/awesome-nodejs/main/readme.md"
TOP_N = 10_000
SEARCH_PAGE = 250

# npm's search endpoint rate-limits hard; keep it nearly serial + backoff.
_search_limiter = asyncio.Semaphore(2)

# Valid (lowercase) npm package name, optionally scoped.
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
# Markdown link text used in awesome-nodejs list entries.
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(https?://[^)]+\)")

# Keystone packages — assigned a download proxy weight so they rank at the top.
CRITICAL_INFRA: list[tuple[str, int]] = [
    ("react", 100_000_000), ("react-dom", 99_000_000), ("lodash", 98_000_000),
    ("express", 97_000_000), ("axios", 96_000_000), ("chalk", 95_000_000),
    ("debug", 94_000_000), ("commander", 93_000_000), ("semver", 92_000_000),
    ("typescript", 91_000_000), ("@babel/core", 90_000_000), ("webpack", 89_000_000),
    ("eslint", 88_000_000), ("@types/node", 87_000_000), ("rxjs", 86_000_000),
    ("moment", 85_000_000), ("uuid", 84_000_000), ("glob", 83_000_000),
    ("yargs", 82_000_000), ("dotenv", 81_000_000), ("classnames", 80_000_000),
    ("prop-types", 79_000_000), ("vue", 78_000_000), ("next", 77_000_000),
    ("react-router-dom", 76_000_000), ("redux", 75_000_000), ("zod", 74_000_000),
    ("node-fetch", 73_000_000), ("cross-env", 72_000_000), ("rimraf", 71_000_000),
    ("fs-extra", 70_000_000), ("inquirer", 69_000_000), ("colors", 68_000_000),
    ("minimist", 67_000_000), ("ws", 66_000_000), ("body-parser", 65_000_000),
    ("cors", 64_000_000), ("mongoose", 63_000_000), ("pg", 62_000_000),
    ("mysql2", 61_000_000), ("redis", 60_000_000), ("ioredis", 59_000_000),
    ("jsonwebtoken", 58_000_000), ("bcrypt", 57_000_000), ("passport", 56_000_000),
    ("socket.io", 55_000_000), ("nodemon", 54_000_000), ("ts-node", 53_000_000),
    ("jest", 52_000_000), ("mocha", 51_000_000), ("chai", 50_000_000),
    ("vite", 49_000_000), ("rollup", 48_000_000), ("esbuild", 47_000_000),
    ("@babel/preset-env", 46_000_000), ("postcss", 45_000_000), ("tailwindcss", 44_000_000),
    ("prettier", 43_000_000), ("husky", 42_000_000), ("dayjs", 41_000_000),
    ("date-fns", 40_000_000), ("validator", 39_000_000), ("winston", 38_000_000),
    ("pino", 37_000_000), ("nanoid", 36_000_000), ("undici", 35_000_000),
    ("@aws-sdk/client-s3", 34_000_000), ("graphql", 33_000_000), ("apollo-server", 32_000_000),
    ("sequelize", 31_000_000), ("prisma", 30_000_000), ("knex", 29_000_000),
]

# Broad seed terms to surface the popular npm surface via the search index.
SEARCH_SEEDS: list[str] = [
    "react", "vue", "angular", "svelte", "http", "cli", "test", "util",
    "types", "babel", "webpack", "eslint", "stream", "async", "promise",
    "logger", "config", "parser", "server", "express", "date", "string",
    "array", "object", "file", "fs", "path", "crypto", "json", "css",
    "html", "aws", "sdk", "graphql", "database", "orm", "redis", "mongodb",
    "socket", "websocket", "template", "markdown", "cache", "queue", "auth",
    "jwt", "oauth", "validation", "schema", "format", "color", "spinner",
    "prompt", "table", "csv", "xml", "yaml", "i18n", "router", "store",
    "state", "hook", "component", "icon", "build", "bundle", "compiler",
    "transform", "lint", "prettier", "jest", "mock", "uuid", "hash",
    "compress", "image", "pdf", "email", "metrics", "trace", "docker", "git",
]


def is_watchlist(session: Session, name: str) -> Optional[int]:
    """Return the watchlist rank for *name*, or None. Case-insensitive."""
    row = session.scalars(
        select(Watchlist).where(
            Watchlist.ecosystem == ECOSYSTEM,
            func.lower(Watchlist.name) == name.lower(),
        )
    ).first()
    return row.rank if row else None


async def _search_popular(client: httpx.AsyncClient) -> list[str]:
    """Return package names surfaced by popularity-weighted search, ranked desc."""
    from pkgsentry.ecosystems.npm.fetch.download import get_with_retry
    candidates: dict[str, float] = {}
    for kw in SEARCH_SEEDS:
        async with _search_limiter:
            try:
                resp = await get_with_retry(
                    client, SEARCH_URL,
                    params={"text": kw, "size": SEARCH_PAGE, "popularity": "1.0"},
                    timeout=30.0,
                )
                resp.raise_for_status()
            except Exception as e:
                log.warning("search_failed", kw=kw, error=str(e))
                continue
            await asyncio.sleep(0.3)
        for obj in resp.json().get("objects", []):
            pkg = obj.get("package", {})
            name = pkg.get("name")
            pop = (obj.get("score", {}).get("detail", {}) or {}).get("popularity", 0.0)
            if not name:
                continue
            prev = candidates.get(name, -1.0)
            if pop > prev:
                candidates[name] = pop
    return [n for n, _ in sorted(candidates.items(), key=lambda kv: kv[1], reverse=True)]


async def _fetch_awesome(client: httpx.AsyncClient) -> list[str]:
    """Best-effort: npm-shaped link texts from the awesome-nodejs README."""
    try:
        resp = await client.get(AWESOME_NODEJS_URL, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
    except Exception as e:
        log.warning("awesome_fetch_failed", error=str(e))
        return []
    names: list[str] = []
    seen: set[str] = set()
    for text in _MD_LINK_RE.findall(resp.text):
        cand = text.strip()
        if cand.lower() in seen:
            continue
        if _NPM_NAME_RE.match(cand):
            seen.add(cand.lower())
            names.append(cand)
    log.info("awesome_parsed", names=len(names))
    return names


async def refresh_watchlist(top_n: int = TOP_N) -> int:
    """Rebuild the npm watchlist from all three sources. Returns count written."""
    downloads_map = {n.lower(): w for n, w in CRITICAL_INFRA}
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        search_names = await _search_popular(client)
        awesome_names = await _fetch_awesome(client)

    ordered = [n for n, _ in CRITICAL_INFRA] + search_names + awesome_names
    seen: set[str] = set()
    final: list[str] = []
    for n in ordered:
        key = n.lower()
        if key in seen:
            continue
        seen.add(key)
        final.append(n)
        if len(final) >= top_n:
            break

    if not final:
        log.warning("watchlist_empty")
        return 0

    now = datetime.now(timezone.utc)
    with sess.session_scope() as s:
        existing = {
            w.name.lower(): w
            for w in s.scalars(select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM)).all()
        }
        kept: set[str] = set()
        for idx, name in enumerate(final, start=1):
            key = name.lower()
            kept.add(key)
            dl = downloads_map.get(key, 0)
            row = existing.get(key)
            if row is None:
                s.add(Watchlist(ecosystem=ECOSYSTEM, name=name, rank=idx,
                                downloads_last_30d=dl, refreshed_at=now))
            else:
                row.rank = idx
                row.downloads_last_30d = dl
                row.refreshed_at = now
        for key, row in existing.items():
            if key not in kept:
                s.delete(row)

    log.info("npm_watchlist_refreshed", count=len(final),
             search=len(search_names), awesome=len(awesome_names))
    return len(final)


async def _resolve_latest(client: httpx.AsyncClient, name: str) -> Optional[str]:
    from pkgsentry.ecosystems.npm.fetch.download import _encode_name, get_with_retry
    try:
        resp = await get_with_retry(client, f"{REGISTRY_BASE}/{_encode_name(name)}/latest", timeout=20.0)
        if resp.status_code != 200:
            return None
        v = resp.json().get("version")
        return str(v) if v else None
    except Exception:
        return None


async def _enqueue_latest(names: list[str], concurrency: int = 8) -> int:
    """Resolve + enqueue the latest version of each name at high priority."""
    if not names:
        return 0
    sem = asyncio.Semaphore(concurrency)
    resolved: list[tuple[str, str]] = []

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        async def _one(name: str):
            async with sem:
                v = await _resolve_latest(client, name)
            if v:
                resolved.append((name, v))
        await asyncio.gather(*[_one(n) for n in names])

    enq = 0
    for i in range(0, len(resolved), 100):
        chunk = resolved[i:i + 100]
        try:
            with sess.session_scope() as s:
                for name, v in chunk:
                    row = enqueue(s, ecosystem=ECOSYSTEM, name=name, version=v, priority="high")
                    if row is not None and row.status == "pending":
                        enq += 1
        except Exception as e:
            log.warning("enqueue_batch_failed", offset=i, error=str(e))
    return enq


async def poll_watchlist_releases() -> int:
    """Enqueue the latest version of every watchlist package at high priority."""
    with sess.session_scope() as s:
        names = [
            w.name for w in s.scalars(
                select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM)
                .order_by(Watchlist.rank.asc())
            ).all()
        ]
    enq = await _enqueue_latest(names)
    log.info("npm_watchlist_poll", enqueued=enq, candidates=len(names))
    return enq


async def seed_missing_watchlist() -> int:
    """Re-seed watchlist packages with no scan_queue row yet (gap-healing)."""
    with sess.session_scope() as s:
        already = set(
            s.scalars(select(ScanQueue.name).where(ScanQueue.ecosystem == ECOSYSTEM)).all()
        )
        wl_names = [
            w.name for w in s.scalars(
                select(Watchlist).where(Watchlist.ecosystem == ECOSYSTEM)
            ).all()
        ]
    missing = [n for n in wl_names if n not in already]
    if not missing:
        return 0
    log.info("npm_seed_missing_start", missing=len(missing), total=len(wl_names))
    enq = await _enqueue_latest(missing)
    log.info("npm_seed_missing_done", enqueued=enq, missing=len(missing))
    return enq
