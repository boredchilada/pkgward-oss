# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.ecosystems.gomod.ingest.cursor import (
    _cursor_to_since,
    _is_pseudo_version,
    _parse_ndjson,
    _ts_to_cursor,
)
from pkgsentry.ecosystems.gomod.ingest.watchlist import _drop_pseudo


def test_pseudo_version_detected():
    assert _is_pseudo_version("v0.0.0-20260524162133-d0041de52970")


def test_pseudo_version_with_base_tag_detected():
    # Go's other two pseudo-version forms: base is a prior release/prerelease.
    # The old ^v0.0.0-…$ anchor missed these, leaking popular-repo snapshots.
    assert _is_pseudo_version("v2.0.6-0.20260527234050-cfc1f1127b38+incompatible")
    assert _is_pseudo_version("v1.4.6-0.20260527232346-619543fb65c5")
    assert _is_pseudo_version("v0.32.5-rc.1.0.20260527234838-28e2817b6f40")
    assert _is_pseudo_version("v2.0.0-20260527235025-e245d2e6fcd6+incompatible")


def test_tagged_version_not_pseudo():
    assert not _is_pseudo_version("v1.2.3")
    assert not _is_pseudo_version("v0.1.0")
    assert not _is_pseudo_version("v2.0.0-beta.1")
    assert not _is_pseudo_version("v1.10.0-rc.1")
    assert not _is_pseudo_version("v1.4.6")


def test_drop_pseudo_filters_watchlist_seed(monkeypatch):
    monkeypatch.delenv("GOMOD_SCAN_PSEUDO", raising=False)
    successes = [
        ("github.com/a/tagged", "github.com/a/tagged", "v1.4.6"),
        ("github.com/b/snap", "github.com/b/snap", "v1.4.6-0.20260527232346-619543fb65c5"),
    ]
    kept = _drop_pseudo(successes)
    assert kept == [("github.com/a/tagged", "github.com/a/tagged", "v1.4.6")]


def test_drop_pseudo_respects_opt_in(monkeypatch):
    monkeypatch.setenv("GOMOD_SCAN_PSEUDO", "1")
    successes = [("github.com/b/snap", "github.com/b/snap", "v1.4.6-0.20260527232346-619543fb65c5")]
    assert _drop_pseudo(successes) == successes


def test_cursor_roundtrip():
    ts = "2026-05-24T18:02:40.831870Z"
    cursor = _ts_to_cursor(ts)
    back = _cursor_to_since(cursor)
    assert back == ts


def test_cursor_roundtrip_truncated_micros():
    ts = "2026-05-24T18:02:40.83187Z"
    cursor = _ts_to_cursor(ts)
    back = _cursor_to_since(cursor)
    assert back.startswith("2026-05-24T18:02:40.831870")


def test_parse_ndjson_valid():
    text = (
        '{"Path":"github.com/foo/bar","Version":"v1.0.0","Timestamp":"2026-05-24T18:02:40Z"}\n'
        '{"Path":"github.com/baz/qux","Version":"v0.1.0","Timestamp":"2026-05-24T18:03:00Z"}\n'
    )
    entries = _parse_ndjson(text)
    assert len(entries) == 2
    assert entries[0]["Path"] == "github.com/foo/bar"
    assert entries[1]["Version"] == "v0.1.0"


def test_parse_ndjson_empty_lines():
    text = "\n\n"
    assert _parse_ndjson(text) == []


def test_parse_ndjson_bad_line_skipped():
    text = '{"Path":"ok","Version":"v1.0.0","Timestamp":"2026-01-01T00:00:00Z"}\nnot json\n'
    entries = _parse_ndjson(text)
    assert len(entries) == 1
