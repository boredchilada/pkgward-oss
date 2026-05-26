# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.ecosystems.gomod.ingest.cursor import (
    _cursor_to_since,
    _is_pseudo_version,
    _parse_ndjson,
    _ts_to_cursor,
)


def test_pseudo_version_detected():
    assert _is_pseudo_version("v0.0.0-20260524162133-d0041de52970")


def test_tagged_version_not_pseudo():
    assert not _is_pseudo_version("v1.2.3")
    assert not _is_pseudo_version("v0.1.0")
    assert not _is_pseudo_version("v2.0.0-beta.1")


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
