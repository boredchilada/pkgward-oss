# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgsentry.ecosystems.crates.ingest.watchlist import parse_crates_page


def test_parse_crates_page():
    """Parse crate names and download counts from API JSON response."""
    data = {
        "crates": [
            {"name": "serde", "downloads": 500_000_000, "max_version": "1.0.219"},
            {"name": "rand", "downloads": 300_000_000, "max_version": "0.8.5"},
        ],
        "meta": {"total": 180000, "next_page": "?page=2&per_page=100&sort=downloads"},
    }
    result = parse_crates_page(data)
    assert len(result) == 2
    assert result[0] == ("serde", 500_000_000)
    assert result[1] == ("rand", 300_000_000)
