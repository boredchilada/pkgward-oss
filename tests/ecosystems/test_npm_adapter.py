# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.adapter import adapter_registry
from pkgsentry.ecosystems.npm.fetch.download import _normalize_metadata


def test_npm_adapter_registered():
    import pkgsentry.ecosystems  # noqa: F401  -- trigger registration
    a = adapter_registry["npm"]
    assert a.ecosystem_id == "npm"
    assert a.install_archive_kind == "npm_tarball"
    assert a.strips_top_dir is True


def test_normalize_metadata_object_author():
    meta = _normalize_metadata({
        "description": "d",
        "author": {"name": "Jane", "email": "jane@example.com"},
        "license": "MIT",
        "keywords": ["a", "b"],
        "repository": {"type": "git", "url": "git+https://github.com/x/y.git"},
        "dependencies": {"left-pad": "^1.0.0", "chalk": "^5"},
    })
    assert meta["author"] == "Jane"
    assert meta["author_email"] == "jane@example.com"
    assert meta["keywords"] == "a, b"
    assert meta["home_page"].endswith("y.git")
    assert meta["requires_dist"] == ["chalk", "left-pad"]


def test_normalize_metadata_string_author_and_obj_license():
    meta = _normalize_metadata({
        "author": "Bob <bob@example.com>",
        "license": {"type": "Apache-2.0", "url": "http://x"},
    })
    assert meta["author"] == "Bob <bob@example.com>"
    assert meta["license"] == "Apache-2.0"
