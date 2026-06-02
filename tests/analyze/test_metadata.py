# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone, timedelta

from pkgsentry.analyze.metadata import (
    analyze_metadata,
    file_list_mismatch,
    typosquat_distance,
    MetadataContext,
)


def test_typosquat_distance_close():
    findings = typosquat_distance("reqests", watchlist_top_names=["requests", "numpy"])
    assert any(f.rule_id == "metadata.typosquat_candidate" for f in findings)


def test_typosquat_distance_far():
    findings = typosquat_distance("totally-unique-name", watchlist_top_names=["requests"])
    assert findings == []


def test_typosquat_exact_match_skipped():
    assert typosquat_distance("requests", watchlist_top_names=["requests"]) == []


def test_file_list_mismatch_flags_wheel_only_file():
    f = file_list_mismatch(
        sdist_files=["pkg/__init__.py", "setup.py"],
        wheel_files=["pkg/__init__.py", "pkg/_extra.py"],
    )
    assert any(x.rule_id == "metadata.sdist_wheel_mismatch" for x in f)


def test_file_list_match_no_finding():
    f = file_list_mismatch(
        sdist_files=["pkg/__init__.py"],
        wheel_files=["pkg/__init__.py"],
    )
    assert f == []


def test_rapid_release_flagged():
    ctx = MetadataContext(
        name="requests", version="2.32.1",
        previous_release_at=datetime.now(timezone.utc) - timedelta(hours=2),
        maintainers_now=["alice"], maintainers_prev=["alice"],
        watchlist_top_names=[],
        sdist_files=[], wheel_files=[],
    )
    findings = analyze_metadata(ctx)
    assert any(f.rule_id == "metadata.rapid_release" for f in findings)


def test_maintainer_change_flagged():
    ctx = MetadataContext(
        name="requests", version="2.32.1",
        previous_release_at=datetime.now(timezone.utc) - timedelta(days=30),
        maintainers_now=["bob"], maintainers_prev=["alice"],
        watchlist_top_names=[],
        sdist_files=[], wheel_files=[],
    )
    findings = analyze_metadata(ctx)
    assert any(f.rule_id == "metadata.maintainer_change" for f in findings)


# ── dependency-confusion version finding (low) ──────────────────────
import pytest as _pytest
from pkgsentry.analyze.metadata import _dependency_confusion_version, analyze_metadata, MetadataContext


@_pytest.mark.parametrize("v,expected", [
    ("99.99.99", True), ("9.9.9", True), ("10.10.10", True), ("11.11.11", True),
    ("1.2.3", False), ("2.0.0", False), ("1.1.1", False),
    ("2024.1.1", False),   # calver must NOT fire (tighter than the cursor's priority check)
    ("9.9.10", False),
])
def test_dependency_confusion_version_predicate(v, expected):
    assert _dependency_confusion_version(v) is expected


def test_dep_confusion_finding_emitted():
    ctx = MetadataContext(name="adminui-deps", version="11.10.11")
    # 11.10.11 is not repdigit/all-nines -> no finding (caught by install hook instead)
    assert not any(f.rule_id == "metadata.dependency_confusion_version" for f in analyze_metadata(ctx))
    ctx2 = MetadataContext(name="evil", version="99.99.99")
    fs = analyze_metadata(ctx2)
    dc = [f for f in fs if f.rule_id == "metadata.dependency_confusion_version"]
    assert len(dc) == 1 and dc[0].severity == "low"


@_pytest.mark.parametrize("name", [
    "github.1485827954.workers.dev/influxdata/telegraf",
    "gh.173371.xyz/daytonaio/daytona",
    "git.832008.xyz/uber/kraken",
    "github.832008.xyz/foo/bar",
    "gitlab.99999.xyz/a/b",
])
def test_gomod_impersonating_host_flagged(name):
    fs = analyze_metadata(MetadataContext(name=name, version="v1.0.0"))
    hits = [f for f in fs if f.rule_id == "metadata.gomod_impersonating_forge_host"]
    assert len(hits) == 1 and hits[0].severity == "high"


@_pytest.mark.parametrize("name", [
    "github.com/influxdata/telegraf", "gitlab.com/foo/bar", "k8s.io/api",
    "go.uber.org/zap", "google.golang.org/grpc", "gopkg.in/yaml.v3",
    "golang.org/x/net", "code.forgejo.org/forgejo/runner", "code.gitea.io/gitea",
    "git.sr.ht/~user/repo", "modernc.org/cc/v5", "sigs.k8s.io/yaml",
    "git.erwanleboucher.dev/eleboucher/runner",  # personal self-hosted git — not an impersonation
    # self-hosted GitLab / Gitea / GitHub-Enterprise legitimately use <forge>.<org>.<tld>
    "gitlab.arm.com/foo/bar", "gitlab.eclipse.org/a/b", "gitlab.isc.org/x/y",
    "gitlab.modaps.eosdis.nasa.gov/m/n", "gitea.unbound.se/p/q", "github.mycompany.com/team/repo",
    "@scope/pkg", "requests", "left-pad",         # non-gomod names never match
])
def test_gomod_impersonating_host_clean(name):
    fs = analyze_metadata(MetadataContext(name=name, version="1.0.0"))
    assert not any(f.rule_id == "metadata.gomod_impersonating_forge_host" for f in fs)
