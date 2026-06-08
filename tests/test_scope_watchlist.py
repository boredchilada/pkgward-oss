# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-ecosystem scope-watchlist (npm @scope / gomod path-prefix / pypi name-prefix).

Closes the gap that let the @redhat-cloud-services worm through: an established,
non-top-N org package's compromised version bump was skipped by the ingest gate.
"""
from __future__ import annotations

from pkgward import scope_watchlist as sw


# --- scope extraction (for auto-escalate) ---

def test_scope_of_npm():
    assert sw.scope_of("npm", "@redhat-cloud-services/types") == "@redhat-cloud-services"
    assert sw.scope_of("npm", "@aws-sdk/client-s3") == "@aws-sdk"
    assert sw.scope_of("npm", "lodash") is None
    assert sw.scope_of("npm", "@foo") is None  # no slash


def test_scope_of_gomod():
    assert sw.scope_of("gomod", "github.com/aws/aws-sdk-go-v2/service/s3") == "github.com/aws"
    assert sw.scope_of("gomod", "golang.org/x/crypto") == "golang.org/x"


def test_scope_of_pypi_requires_multipart():
    assert sw.scope_of("pypi", "azure-storage-blob") == "azure"
    assert sw.scope_of("pypi", "google_cloud_storage") == "google"
    assert sw.scope_of("pypi", "requests") is None  # bare name is too broad to auto-watch


def test_scope_of_crates_none():
    assert sw.scope_of("crates", "anything") is None


# --- prefix-with-boundary matching ---

def test_matches_npm_boundary():
    sc = {"@aws-sdk"}
    assert sw.is_scope_watchlisted(None, "npm", "@aws-sdk/client-s3", scopes=sc)
    assert not sw.is_scope_watchlisted(None, "npm", "@aws-sdkx/evil", scopes=sc)  # boundary
    assert not sw.is_scope_watchlisted(None, "npm", "lodash", scopes=sc)


def test_matches_gomod_boundary():
    sc = {"github.com/aws"}
    assert sw.is_scope_watchlisted(None, "gomod", "github.com/aws/aws-sdk-go", scopes=sc)
    assert not sw.is_scope_watchlisted(None, "gomod", "github.com/awsx/evil", scopes=sc)


def test_matches_pypi_separators():
    sc = {"azure"}
    assert sw.is_scope_watchlisted(None, "pypi", "azure-storage", scopes=sc)
    assert sw.is_scope_watchlisted(None, "pypi", "azure_identity", scopes=sc)
    assert sw.is_scope_watchlisted(None, "pypi", "azure.mgmt", scopes=sc)
    assert not sw.is_scope_watchlisted(None, "pypi", "azurite", scopes=sc)  # no boundary


def test_crates_unsupported():
    assert not sw.supported("crates")
    assert not sw.is_scope_watchlisted(None, "crates", "github.com/x", scopes={"github.com/x"})


def test_disabled_via_env(monkeypatch):
    monkeypatch.setenv("PKGWARD_SCOPE_WATCHLIST", "0")
    assert not sw.is_scope_watchlisted(None, "npm", "@aws-sdk/x", scopes={"@aws-sdk"})


# --- DB-backed add / load / remove / seed / auto-escalate ---

def test_add_load_remove(db_session):
    assert sw.add_scope(db_session, "npm", "redhat-cloud-services") == "added"  # @ normalized in
    assert sw.add_scope(db_session, "npm", "@redhat-cloud-services") == "refreshed"
    scopes = sw.load_scopes(db_session, "npm")
    assert "@redhat-cloud-services" in scopes
    assert sw.is_scope_watchlisted(db_session, "npm", "@redhat-cloud-services/rbac-client")
    assert sw.remove_scope(db_session, "npm", "@redhat-cloud-services") == 1
    assert not sw.is_scope_watchlisted(db_session, "npm", "@redhat-cloud-services/rbac-client")


def test_seed_baseline_idempotent(db_session):
    n1 = sw.seed_baseline(db_session)
    assert n1 > 0
    assert "@redhat-cloud-services" in sw.load_scopes(db_session, "npm")
    assert "golang.org/x" in sw.load_scopes(db_session, "gomod")
    assert "azure" in sw.load_scopes(db_session, "pypi")
    assert sw.seed_baseline(db_session) == 0  # idempotent


def test_auto_watch_on_malicious_adds_scope(db_session):
    sc = sw.auto_watch_on_malicious(db_session, "npm", "@evilcorp/pkg-a")
    assert sc == "@evilcorp"
    # now a sibling of the same org is watched (worm-spread defense)
    assert sw.is_scope_watchlisted(db_session, "npm", "@evilcorp/pkg-b")


def test_auto_watch_skips_unscoped(db_session):
    assert sw.auto_watch_on_malicious(db_session, "npm", "lodash") is None
    assert sw.auto_watch_on_malicious(db_session, "crates", "serde") is None


def test_pypi_auto_watch_skipped_npm_gomod_kept(db_session):
    # pypi name-prefixes are too generic to auto-watch on one catch (chain-signer
    # must NOT auto-watch every chain-*); npm @scope + gomod host/org still do.
    assert sw.auto_watch_on_malicious(db_session, "pypi", "chain-signer") is None
    assert sw.auto_watch_on_malicious(db_session, "npm", "@evil/pkg") == "@evil"
    assert sw.auto_watch_on_malicious(db_session, "gomod", "github.com/evil/repo") == "github.com/evil"
