# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import pytest
from sqlalchemy import select

from pkgsentry import focus
from pkgsentry.focus import FocusEntry
from pkgsentry.store.models import FocusList


# --- parse_focus_file ---------------------------------------------------

def test_parse_pypi_names_and_pins():
    text = """
    # a comment
    requests
    cryptography==42.0.0   # inline comment

    Django == 5.0
    """
    entries = focus.parse_focus_file(text, "pypi")
    got = {(e.name, e.pinned_version) for e in entries}
    assert got == {
        ("requests", None),
        ("cryptography", "42.0.0"),
        ("Django", "5.0"),
    }


@pytest.mark.parametrize("eco,line,exp_name,exp_ver", [
    # Lenient: accept any specifier form companies paste from their dep files.
    # Name is what's monitored; version present = scan once (range -> lower bound).
    ("pypi", "requests==2.31.0", "requests", "2.31.0"),
    ("pypi", "requests>=2.31.0", "requests", "2.31.0"),
    ("pypi", "requests >= 2.31.0", "requests", "2.31.0"),
    ("pypi", "requests>=2.0,<3.0", "requests", "2.0"),     # range -> lower bound
    ("pypi", "rich~=13.0", "rich", "13.0"),
    ("pypi", "flask>2", "flask", "2"),
    ("pypi", "numpy", "numpy", None),
    ("pypi", "pandas==2.*", "pandas", None),               # wildcard -> no concrete pin
    ("crates", "serde^1.0", "serde", "1.0"),               # cargo caret
    ("crates", "tokio~1.2", "tokio", "1.2"),               # cargo tilde
    ("gomod", "github.com/x/y v1.2.3", "github.com/x/y", "v1.2.3"),
    ("gomod", "github.com/x/y >= v1.2.3", "github.com/x/y", "v1.2.3"),
    ("gomod", "github.com/c/d", "github.com/c/d", None),
])
def test_parse_lenient_version_forms(eco, line, exp_name, exp_ver):
    e = focus.parse_focus_file(line, eco)[0]
    assert (e.name, e.pinned_version) == (exp_name, exp_ver)


def test_parse_gomod_space_separated():
    text = "github.com/gin-gonic/gin v1.9.1\ngolang.org/x/crypto\n"
    entries = focus.parse_focus_file(text, "gomod")
    assert entries == [
        FocusEntry("github.com/gin-gonic/gin", "v1.9.1"),
        FocusEntry("golang.org/x/crypto", None),
    ]


# --- upsert / is_focus / clear ------------------------------------------

def test_upsert_and_is_focus_exact(db_session):
    focus.upsert_focus(db_session, "pypi", [FocusEntry("requests", "2.31.0")])
    assert focus.is_focus(db_session, "pypi", "requests") is True
    assert focus.is_focus(db_session, "pypi", "Requests") is False  # exact
    assert focus.is_focus(db_session, "pypi", "absent") is False


def test_upsert_updates_pinned_version(db_session):
    focus.upsert_focus(db_session, "pypi", [FocusEntry("requests", "2.31.0")])
    focus.upsert_focus(db_session, "pypi", [FocusEntry("requests", "2.32.0")])
    rows = db_session.scalars(select(FocusList).where(FocusList.name == "requests")).all()
    assert len(rows) == 1
    assert rows[0].pinned_version == "2.32.0"


def test_is_focus_gomod_case_insensitive(db_session):
    focus.upsert_focus(db_session, "gomod", [FocusEntry("github.com/Gin-Gonic/Gin", None)])
    assert focus.is_focus(db_session, "gomod", "github.com/gin-gonic/gin") is True
    assert focus.is_focus(db_session, "gomod", "GitHub.com/GIN-GONIC/GIN") is True


def test_load_focus_names_lowercases_gomod(db_session):
    focus.upsert_focus(db_session, "gomod", [FocusEntry("github.com/Foo/Bar", None)])
    focus.upsert_focus(db_session, "pypi", [FocusEntry("Flask", None)])
    g = focus.load_focus_names(db_session, "gomod")
    p = focus.load_focus_names(db_session, "pypi")
    assert g == {"github.com/foo/bar"}
    assert p == {"Flask"}  # pypi exact, not lowercased
    assert focus.on_focus("github.com/FOO/bar", g, "gomod") is True
    assert focus.on_focus("flask", p, "pypi") is False  # case-sensitive
    assert focus.on_focus("Flask", p, "pypi") is True


def test_clear_focus_scoped(db_session):
    focus.upsert_focus(db_session, "pypi", [FocusEntry("a")])
    focus.upsert_focus(db_session, "crates", [FocusEntry("b")])
    assert focus.clear_focus(db_session, "pypi") == 1
    assert focus.load_focus_names(db_session, "pypi") == set()
    assert focus.load_focus_names(db_session, "crates") == {"b"}


# --- gate_decision truth table ------------------------------------------

@pytest.mark.parametrize(
    "on_foc,on_wl,brand_new,exclusive,expected",
    [
        # exclusive: only focus admitted (high), everything else skipped
        (True, False, False, True, "high"),
        (False, True, False, True, None),
        (False, False, True, True, None),
        (False, False, False, True, None),
        # additive: focus or watchlist -> high; brand-new -> normal; else skip
        (True, False, False, False, "high"),
        (False, True, False, False, "high"),
        (False, False, True, False, "normal"),
        (False, False, False, False, None),
        (True, True, True, False, "high"),  # focus wins priority
    ],
)
def test_gate_decision(on_foc, on_wl, brand_new, exclusive, expected):
    assert (
        focus.gate_decision(
            on_focus=on_foc, on_watchlist=on_wl, brand_new=brand_new, exclusive=exclusive
        )
        == expected
    )


def test_focus_exclusive_env(monkeypatch):
    monkeypatch.delenv("PKGSENTRY_FOCUS_EXCLUSIVE", raising=False)
    assert focus.focus_exclusive() is False
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    assert focus.focus_exclusive() is True
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "0")
    assert focus.focus_exclusive() is False


def test_focus_list_table_created(sqlite_engine):
    # init_db / create_all auto-creates the focus_list table.
    from sqlalchemy import inspect
    assert "focus_list" in inspect(sqlite_engine).get_table_names()


# --- combined file parsing / sync ---------------------------------------

def test_parse_combined_focus_file():
    text = (
        "# header comment\n"
        "[pypi]\n"
        "requests==2.31.0\n"
        "flask\n"
        "[crates]\n"
        "serde\n"
        "[gomod]\n"
        "github.com/Gin/Gin v1.9.1\n"
    )
    sections = focus.parse_combined_focus_file(text)
    assert set(sections) == {"pypi", "crates", "gomod"}
    assert {(e.name, e.pinned_version) for e in sections["pypi"]} == {
        ("requests", "2.31.0"), ("flask", None)
    }
    assert sections["gomod"][0] == FocusEntry("github.com/Gin/Gin", "v1.9.1")


def test_parse_combined_empty_section_clears():
    sections = focus.parse_combined_focus_file("[pypi]\n")
    assert sections == {"pypi": []}


def test_parse_combined_rejects_unknown_section():
    with pytest.raises(ValueError):
        focus.parse_combined_focus_file("[rubygems]\nrails\n")


def test_parse_combined_rejects_content_before_header():
    with pytest.raises(ValueError):
        focus.parse_combined_focus_file("requests\n[pypi]\nflask\n")


def test_sync_focus_is_authoritative(db_session):
    focus.sync_focus(db_session, "pypi", [FocusEntry("a"), FocusEntry("b")])
    focus.sync_focus(db_session, "pypi", [FocusEntry("a")])  # drops b
    assert focus.load_focus_names(db_session, "pypi") == {"a"}


def test_apply_focus_file_syncs_present_sections_only(db_session):
    # Pre-existing gomod focus should be untouched (no [gomod] section).
    focus.upsert_focus(db_session, "gomod", [FocusEntry("github.com/x/y")])
    focus.apply_focus_file(db_session, "[pypi]\nrequests\n[crates]\nserde\n")
    assert focus.load_focus_names(db_session, "pypi") == {"requests"}
    assert focus.load_focus_names(db_session, "crates") == {"serde"}
    assert focus.load_focus_names(db_session, "gomod") == {"github.com/x/y"}  # untouched
