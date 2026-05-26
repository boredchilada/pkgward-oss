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
