# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
from pkgsentry.ecosystems.crates.fetch.download import _build_download_url, _build_api_url


def test_build_download_url():
    url = _build_download_url("serde", "1.0.219")
    assert url == "https://static.crates.io/crates/serde/serde-1.0.219.crate"


def test_build_api_url():
    url = _build_api_url("serde", "1.0.219")
    assert url == "https://crates.io/api/v1/crates/serde/1.0.219"
