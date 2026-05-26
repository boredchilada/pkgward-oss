# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from unittest.mock import AsyncMock, patch

from pkgsentry.ecosystems.crates.ingest.feeds import parse_rss_items, _parse_title


# ── _parse_title unit tests ─────────────────────────────────────────

def test_parse_title_new_crate():
    assert _parse_title("New crate created: ecmd") == ("ecmd", "latest")


def test_parse_title_update():
    assert _parse_title("New crate version published: ecmd v0.2.0") == ("ecmd", "0.2.0")


def test_parse_title_update_no_v_prefix():
    """Some feeds might omit the v prefix."""
    assert _parse_title("New crate version published: tokio 1.45.0") == ("tokio", "1.45.0")


def test_parse_title_pre_release():
    result = _parse_title("New crate version published: my-crate v0.1.0-alpha.1")
    assert result == ("my-crate", "0.1.0-alpha.1")


def test_parse_title_unknown_format_returns_none():
    assert _parse_title("something unexpected") is None


def test_parse_title_empty():
    assert _parse_title("") is None


# ── parse_rss_items integration tests ───────────────────────────────

def test_parse_rss_items_updates_feed():
    """Parse the updates.xml feed format."""
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>New crate version published: serde_json v1.0.140</title>
          <link>https://crates.io/crates/serde_json/1.0.140</link>
        </item>
        <item>
          <title>New crate version published: tokio v1.45.0</title>
          <link>https://crates.io/crates/tokio/1.45.0</link>
        </item>
      </channel>
    </rss>"""
    items = parse_rss_items(xml)
    assert len(items) == 2
    assert items[0] == ("serde_json", "1.0.140")
    assert items[1] == ("tokio", "1.45.0")


def test_parse_rss_items_new_crates_feed():
    """Parse the crates.xml feed format — new crates with no version in title."""
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>New crate created: ecmd</title>
          <link>https://crates.io/crates/ecmd</link>
        </item>
        <item>
          <title>New crate created: leaksnow</title>
          <link>https://crates.io/crates/leaksnow</link>
        </item>
      </channel>
    </rss>"""
    items = parse_rss_items(xml)
    assert len(items) == 2
    # No version in title or link → "latest"
    assert items[0] == ("ecmd", "latest")
    assert items[1] == ("leaksnow", "latest")


def test_parse_rss_items_new_crate_with_version_in_link():
    """If the link contains a version, use it instead of 'latest'."""
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>New crate created: ecmd</title>
          <link>https://crates.io/crates/ecmd/0.1.0</link>
        </item>
      </channel>
    </rss>"""
    items = parse_rss_items(xml)
    assert items[0] == ("ecmd", "0.1.0")


def test_parse_rss_items_pre_release():
    """Pre-release versions like 0.1.0-alpha.1 are parsed correctly."""
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>New crate version published: my-crate v0.1.0-alpha.1</title>
          <link>https://crates.io/crates/my-crate/0.1.0-alpha.1</link>
        </item>
      </channel>
    </rss>"""
    items = parse_rss_items(xml)
    assert items[0] == ("my-crate", "0.1.0-alpha.1")


def test_parse_rss_items_malformed_xml():
    items = parse_rss_items("<not valid xml")
    assert items == []


def test_parse_rss_items_empty_titles_skipped():
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item><title></title></item>
        <item><title>   </title></item>
      </channel>
    </rss>"""
    items = parse_rss_items(xml)
    assert items == []
