# SPDX-License-Identifier: AGPL-3.0-or-later
"""Known-malicious dependency intel: normalization, dep-name extraction, and the
confirmed-bad set matching that backs both the npm ingest gate and the scan-time
finding."""
from __future__ import annotations

import pytest

from pkgward import known_bad_deps as kbd


def test_normalize_pypi_pep503():
    assert kbd.normalize("pypi", "Foo.Bar_Baz") == "foo-bar-baz"
    assert kbd.normalize("pypi", "requests") == "requests"
    # collapse runs and trim edges
    assert kbd.normalize("pypi", "a__b--c..d") == "a-b-c-d"


def test_normalize_npm_keeps_scope():
    assert kbd.normalize("npm", "@Scope/Pkg") == "@scope/pkg"
    assert kbd.normalize("npm", "express") == "express"


def test_extract_dep_name_pypi_pep508():
    assert kbd.extract_dep_name("pypi", "requests>=2.25.0; python_version>='3.6'") == "requests"
    assert kbd.extract_dep_name("pypi", "typing-extensions (>=3.7)") == "typing-extensions"
    assert kbd.extract_dep_name("pypi", "") is None


def test_extract_dep_name_npm_is_bare():
    assert kbd.extract_dep_name("npm", "@nuxt/ui") == "@nuxt/ui"
    assert kbd.extract_dep_name("npm", "lodash") == "lodash"


def test_match_known_bad_pypi_normalizes_both_sides():
    known = frozenset({"evil-pkg"})  # already normalized
    hits = kbd.match_known_bad("pypi", ["Evil_Pkg>=1.0", "requests>=2"], known)
    assert hits == {"Evil_Pkg>=1.0": "evil-pkg"}


def test_match_known_bad_npm():
    known = frozenset({"@bad/dropper", "evil-utils"})
    hits = kbd.match_known_bad("npm", ["lodash", "evil-utils", "@bad/dropper"], known)
    assert set(hits.values()) == {"evil-utils", "@bad/dropper"}


def test_match_empty_when_no_known_or_no_deps():
    assert kbd.match_known_bad("npm", ["lodash"], frozenset()) == {}
    assert kbd.match_known_bad("npm", None, frozenset({"x"})) == {}


def test_load_known_bad_is_cached_and_ecosystem_scoped(monkeypatch):
    kbd.invalidate_cache()
    calls = {"n": 0}

    def _fake_entries(_s, ecosystem=None):
        calls["n"] += 1
        rows = [("npm", "Evil-Utils", None), ("pypi", "BadPkg", None)]
        return [r for r in rows if ecosystem is None or r[0] == ecosystem]

    monkeypatch.setattr(kbd.watchlist_auto, "list_auto_entries", _fake_entries)
    monkeypatch.setattr(kbd.watchlist_auto, "_blocklist", lambda: {})

    npm_set = kbd.load_known_bad("npm", session=object())
    assert npm_set == frozenset({"evil-utils"})  # pypi row excluded, lowercased
    # second call within TTL must not re-query
    again = kbd.load_known_bad("npm", session=object())
    assert again == npm_set and calls["n"] == 1
    kbd.invalidate_cache()


def test_load_known_bad_respects_blocklist(monkeypatch):
    kbd.invalidate_cache()
    monkeypatch.setattr(
        kbd.watchlist_auto, "list_auto_entries",
        lambda _s, ecosystem=None: [("npm", "evil-utils", None), ("npm", "falsepos", None)],
    )
    monkeypatch.setattr(kbd.watchlist_auto, "_blocklist", lambda: {"npm": {"falsepos"}})
    assert kbd.load_known_bad("npm", session=object()) == frozenset({"evil-utils"})
    kbd.invalidate_cache()
