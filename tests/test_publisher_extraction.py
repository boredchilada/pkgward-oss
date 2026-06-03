# SPDX-License-Identifier: AGPL-3.0-or-later
"""Publisher/uploader identity is captured per-ecosystem onto the Version row so
the Discord alert can surface *who* published (first-order supply-chain signal)."""
from __future__ import annotations

from pkgsentry.ecosystems.gomod.fetch.download import _publisher_from_path
from pkgsentry.ecosystems.npm.fetch.download import _normalize_metadata


def test_gomod_publisher_from_forge_path():
    assert _publisher_from_path("github.com/stretchr/testify") == "github.com/stretchr"
    assert _publisher_from_path("gitlab.com/acme/widget/v2") == "gitlab.com/acme"
    assert _publisher_from_path("codeberg.org/u/p") == "codeberg.org/u"


def test_gomod_publisher_from_vanity_path_falls_back_to_host():
    assert _publisher_from_path("gopkg.in/yaml.v3") == "gopkg.in"
    assert _publisher_from_path("rsc.io/quote") == "rsc.io"


def test_gomod_publisher_none_when_not_a_path():
    assert _publisher_from_path("localmodule") is None
    assert _publisher_from_path("") is None


def test_npm_captures_npmuser_as_uploader_and_maintainers():
    m = _normalize_metadata({
        "_npmUser": {"name": "attacker7"},
        "maintainers": [{"name": "realdev"}, {"name": "attacker7"}],
        "author": "Real Dev",
    })
    assert m["upload_user"] == "attacker7"
    assert m["maintainers"] == ["realdev", "attacker7"]


def test_npm_publisher_absent_is_none_not_crash():
    m = _normalize_metadata({"author": {"name": "x", "email": "x@y.z"}})
    assert m["upload_user"] is None
    assert m["maintainers"] is None
