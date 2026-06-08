# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-ecosystem SCOPE watchlist — watch a whole org/namespace, not single names.

An ingest gate enqueues only brand-new names or top-N watchlist packages; an
*established* (non-top-N) org package's new version is otherwise skipped. That is
exactly how the ``@redhat-cloud-services`` worm slipped through. A watched scope
says "every package + every release under this org is ingested at high priority".

"Scope" is per-ecosystem, matched as a **prefix with a boundary**:
  * **npm**     — ``@org`` (boundary ``/``):              ``@aws-sdk`` → ``@aws-sdk/client-s3``
  * **gomod**   — module path prefix (boundary ``/``):    ``github.com/aws`` → ``github.com/aws/aws-sdk-go-v2``
  * **pypi**    — name prefix (boundary ``-`` ``_`` ``.``): ``azure`` → ``azure-storage-blob``
  * **crates**  — NOT supported (flat namespace, no name-based org grouping; an
                  owner-metadata mechanism would be needed — deferred).

Two sources: **baseline** (curated high-blast-radius vendor scopes per ecosystem)
and **auto_malicious** (added at runtime when one package in a scope is
double-confirmed malicious — sibling-worm defense, catches the spread to the org's
*other* packages within the same wave).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pkgward.logging_setup import get_logger
from pkgward.store.models import WatchlistScope

log = get_logger("scope_watchlist")

SUPPORTED = ("npm", "gomod", "pypi")  # crates: flat namespace, not name-scopable

# Per-ecosystem baseline scopes — curated, high-blast-radius official orgs. These
# are starting points; operators trim/extend via the `pkgward scope` CLI, and
# the auto-escalate path adds compromised orgs at runtime.
BASELINE_SCOPES: dict[str, tuple[str, ...]] = {
    "npm": (
        "@aws-sdk", "@aws-amplify", "@azure", "@google-cloud", "@cloudflare",
        "@vercel", "@netlify", "@supabase", "@firebase", "@datadog", "@sentry",
        "@elastic", "@grafana", "@newrelic",
        "@angular", "@vue", "@nestjs", "@remix-run", "@sveltejs", "@nuxt",
        "@astrojs", "@apollo", "@prisma",
        "@octokit", "@actions", "@npmcli", "@yarnpkg", "@nrwl", "@nx",
        "@changesets", "@vitejs", "@swc", "@typescript-eslint", "@storybook",
        "@okta", "@auth0", "@clerk", "@stripe", "@paypal", "@snyk",
        "@redhat-cloud-services", "@redhat", "@microsoft", "@ibm",
    ),
    "gomod": (
        "golang.org/x", "google.golang.org", "k8s.io", "sigs.k8s.io",
        "go.uber.org", "cloud.google.com/go",
        "github.com/aws", "github.com/Azure", "github.com/googleapis",
        "github.com/google", "github.com/kubernetes", "github.com/hashicorp",
        "github.com/grafana", "github.com/prometheus", "github.com/open-telemetry",
        "github.com/cloudflare", "github.com/docker", "github.com/sigstore",
        "github.com/gohugoio", "github.com/spf13",
    ),
    "pypi": (
        "azure", "google-cloud", "aws-cdk", "opentelemetry", "apache-airflow",
        "snowflake", "databricks", "msrest", "boto3", "botocore",
    ),
}

# Excluded from the default seed: extremely prolific, would flood the queue. Opt
# in with PKGWARD_SCOPE_WATCH_PROLIFIC=1 when there's headroom.
PROLIFIC_SCOPES: dict[str, tuple[str, ...]] = {
    "npm": ("@types", "@babel"),
    "gomod": (),
    "pypi": ("types",),
}

# Name-prefix boundary chars per ecosystem.
_PYPI_SEPS = ("-", "_", ".")


def is_enabled() -> bool:
    return os.environ.get("PKGWARD_SCOPE_WATCHLIST", "1") != "0"


def supported(ecosystem: str) -> bool:
    return ecosystem in SUPPORTED


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _matches(ecosystem: str, scope: str, name: str) -> bool:
    """Does *name* fall under *scope* for *ecosystem* (prefix + boundary)?"""
    s = scope.lower()
    n = name.lower()
    if ecosystem == "npm":
        return n == s or n.startswith(s + "/")
    if ecosystem == "gomod":
        return n == s or n.startswith(s + "/")
    if ecosystem == "pypi":
        if n == s:
            return True
        return any(n.startswith(s + sep) for sep in _PYPI_SEPS)
    return False


def scope_of(ecosystem: str, name: str) -> Optional[str]:
    """The canonical scope to auto-watch when *name* is caught malicious, or None
    when extraction is ambiguous (so we don't over-broaden)."""
    if ecosystem == "npm":
        if not name.startswith("@"):
            return None
        slash = name.find("/")
        return name[:slash].lower() if slash > 1 else None
    if ecosystem == "gomod":
        parts = name.split("/")
        # host/org (first two path segments); single-segment hosts (k8s.io/api)
        # also give host/firstseg — a reasonable org boundary.
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else None
    if ecosystem == "pypi":
        low = name.lower()
        for sep in _PYPI_SEPS:
            i = low.find(sep)
            if i > 1:  # require a real multi-part name; bare names are too broad
                return low[:i]
        return None
    return None


def load_scopes(session: Session, ecosystem: str) -> set[str]:
    """All watched scopes for an ecosystem (lowercased). Load once per poll batch."""
    rows = session.scalars(
        select(WatchlistScope.scope).where(WatchlistScope.ecosystem == ecosystem)
    ).all()
    return {r.lower() for r in rows}


def is_scope_watchlisted(
    session: Session, ecosystem: str, name: str, *, scopes: Optional[set[str]] = None
) -> bool:
    """True if *name* falls under any watched scope. Pass a pre-loaded *scopes* set
    in a loop to avoid a per-row query."""
    if not is_enabled() or not supported(ecosystem) or not name:
        return False
    if scopes is None:
        scopes = load_scopes(session, ecosystem)
    if not scopes:
        return False
    return any(_matches(ecosystem, s, name) for s in scopes)


def add_scope(session: Session, ecosystem: str, scope: str, *, source: str = "manual") -> str:
    """Add or refresh a watched scope. Returns 'added' | 'refreshed' | 'unsupported'."""
    if not supported(ecosystem):
        return "unsupported"
    scope = scope.strip().lower().rstrip("/")
    if ecosystem == "npm" and not scope.startswith("@"):
        scope = "@" + scope
    existing = session.scalar(
        select(WatchlistScope).where(
            WatchlistScope.ecosystem == ecosystem,
            func.lower(WatchlistScope.scope) == scope,
        )
    )
    if existing is not None:
        existing.refreshed_at = _now()
        session.flush()
        return "refreshed"
    session.add(WatchlistScope(ecosystem=ecosystem, scope=scope, source=source))
    session.flush()
    return "added"


def remove_scope(session: Session, ecosystem: str, scope: str) -> int:
    """Remove a watched scope. Returns rows deleted."""
    scope = scope.strip().lower().rstrip("/")
    if ecosystem == "npm" and not scope.startswith("@"):
        scope = "@" + scope
    row = session.scalar(
        select(WatchlistScope).where(
            WatchlistScope.ecosystem == ecosystem,
            func.lower(WatchlistScope.scope) == scope,
        )
    )
    if row is None:
        return 0
    session.delete(row)
    session.flush()
    return 1


# Ecosystems whose scope is a genuine, unambiguous namespace safe to AUTO-watch on
# a single catch: npm (@org) and gomod (host/org path prefix). pypi name-prefixes are
# too generic (a malicious "chain-signer" must NOT auto-watch every "chain-*"); pypi
# scopes are still usable via the baseline seed + manual `scope add`.
_AUTO_WATCH_ECOSYSTEMS = ("npm", "gomod")


def auto_watch_on_malicious(session: Session, ecosystem: str, name: str) -> Optional[str]:
    """Sibling-worm defense: when *name* is double-confirmed malicious, watch its
    whole scope. Returns the scope added/refreshed, or None."""
    if not is_enabled() or ecosystem not in _AUTO_WATCH_ECOSYSTEMS:
        return None
    sc = scope_of(ecosystem, name)
    if not sc:
        return None
    status = add_scope(session, ecosystem, sc, source="auto_malicious")
    if status == "added":
        log.info("scope_watchlist_auto_added", ecosystem=ecosystem, scope=sc, name=name)
    return sc


def seed_baseline(session: Session) -> int:
    """Idempotently insert the baseline scopes for every supported ecosystem
    (+ prolific scopes if opted in). Returns the number newly inserted."""
    want_prolific = os.environ.get("PKGWARD_SCOPE_WATCH_PROLIFIC", "0") == "1"
    inserted = 0
    for eco in SUPPORTED:
        have = load_scopes(session, eco)
        wanted = list(BASELINE_SCOPES.get(eco, ()))
        if want_prolific:
            wanted += list(PROLIFIC_SCOPES.get(eco, ()))
        for sc in wanted:
            s = sc.strip().lower().rstrip("/")
            if s not in have:
                session.add(WatchlistScope(ecosystem=eco, scope=s, source="baseline"))
                have.add(s)
                inserted += 1
    if inserted:
        session.flush()
    return inserted
