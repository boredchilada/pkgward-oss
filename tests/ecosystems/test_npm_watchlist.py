# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.ecosystems.npm.ingest.watchlist import (
    CRITICAL_INFRA,
    _MD_LINK_RE,
    _NPM_NAME_RE,
    is_watchlist,
)
from pkgsentry.store.models import Watchlist


def test_npm_name_regex_accepts_valid():
    for n in ("react", "left-pad", "@scope/pkg", "lodash.merge", "is-odd"):
        assert _NPM_NAME_RE.match(n), n


def test_npm_name_regex_rejects_invalid():
    for n in ("React", "has space", "UPPER", "Web Framework", "a/b/c"):
        assert not _NPM_NAME_RE.match(n), n


def test_awesome_link_extraction_filters_to_npm_names():
    md = (
        "- [chalk](https://github.com/chalk/chalk) - Terminal styling.\n"
        "- [Some Article About Node](https://example.com/post) - not a pkg.\n"
        "- [express](https://github.com/expressjs/express) - web framework\n"
    )
    texts = _MD_LINK_RE.findall(md)
    names = [t for t in texts if _NPM_NAME_RE.match(t.strip())]
    assert "chalk" in names and "express" in names
    assert "Some Article About Node" not in names


def test_critical_infra_names_are_valid_npm_names():
    for name, _weight in CRITICAL_INFRA:
        assert _NPM_NAME_RE.match(name), name


def test_is_watchlist_case_insensitive(db_session):
    db_session.add(Watchlist(ecosystem="npm", name="lodash", rank=3, downloads_last_30d=0))
    db_session.commit()
    assert is_watchlist(db_session, "lodash") == 3
    assert is_watchlist(db_session, "LoDaSh") == 3
    assert is_watchlist(db_session, "nonexistent") is None
