# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pkgsentry.cli import app

runner = CliRunner()


def _use_temp_db(tmp_path: Path, monkeypatch):
    from pkgsentry.store import session as sess
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'cli.db'}")
    sess.reset_engine()
    sess.init_db()
    return sess


def test_focus_load_list_clear(tmp_path, monkeypatch):
    sess = _use_temp_db(tmp_path, monkeypatch)
    focus_file = tmp_path / "deps.txt"
    focus_file.write_text("# my deps\nrequests==2.31.0\nflask\n", encoding="utf-8")

    r = runner.invoke(app, ["focus", "load", str(focus_file), "-e", "pypi"])
    assert r.exit_code == 0, r.output
    assert "loaded 2 focus entries (pypi)" in r.output
    assert "1 pinned versions enqueued" in r.output

    # The pinned version was enqueued for scanning.
    from sqlalchemy import select
    from pkgsentry.store.models import ScanQueue, FocusList
    with sess.session_scope() as s:
        q = s.scalars(select(ScanQueue).where(ScanQueue.name == "requests")).all()
        assert len(q) == 1 and q[0].version == "2.31.0" and q[0].priority == "high"
        assert {f.name for f in s.scalars(select(FocusList)).all()} == {"requests", "flask"}

    r = runner.invoke(app, ["focus", "list", "-e", "pypi"])
    assert r.exit_code == 0
    assert "requests\t2.31.0" in r.output
    assert "flask\t-" in r.output
    assert "# 2 entries" in r.output

    r = runner.invoke(app, ["focus", "clear", "-e", "pypi"])
    assert r.exit_code == 0 and "cleared 2 entries" in r.output


def test_focus_load_no_enqueue_pinned(tmp_path, monkeypatch):
    sess = _use_temp_db(tmp_path, monkeypatch)
    f = tmp_path / "d.txt"
    f.write_text("requests==2.31.0\n", encoding="utf-8")
    r = runner.invoke(app, ["focus", "load", str(f), "-e", "pypi", "--no-enqueue-pinned"])
    assert r.exit_code == 0 and "0 pinned versions enqueued" in r.output
    from sqlalchemy import select
    from pkgsentry.store.models import ScanQueue
    with sess.session_scope() as s:
        assert s.scalars(select(ScanQueue)).all() == []


def test_focus_load_rejects_bad_ecosystem(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    f = tmp_path / "d.txt"
    f.write_text("x\n", encoding="utf-8")
    r = runner.invoke(app, ["focus", "load", str(f), "-e", "rubygems"])
    assert r.exit_code != 0


def test_focus_list_warns_when_exclusive_empty(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    monkeypatch.setenv("PKGSENTRY_FOCUS_EXCLUSIVE", "1")
    r = runner.invoke(app, ["focus", "list"])
    assert r.exit_code == 0
    assert "WARNING" in r.output and "idle" in r.output


def test_focus_load_combined_file_all_ecosystems(tmp_path, monkeypatch):
    sess = _use_temp_db(tmp_path, monkeypatch)
    combined = tmp_path / "focus.txt"
    combined.write_text(
        "[pypi]\nrequests==2.31.0\nflask\n"
        "[crates]\nserde\n"
        "[gomod]\ngithub.com/gin-gonic/gin v1.9.1\n",
        encoding="utf-8",
    )
    r = runner.invoke(app, ["focus", "load", str(combined)])  # no -e
    assert r.exit_code == 0, r.output
    assert "crates, gomod, pypi" in r.output  # all three scopes loaded

    from sqlalchemy import select
    from pkgsentry.store.models import FocusList, ScanQueue
    with sess.session_scope() as s:
        by_eco = {}
        for f in s.scalars(select(FocusList)).all():
            by_eco.setdefault(f.ecosystem, set()).add(f.name)
        assert by_eco["pypi"] == {"requests", "flask"}
        assert by_eco["crates"] == {"serde"}
        assert by_eco["gomod"] == {"github.com/gin-gonic/gin"}
        # pinned pypi + gomod versions enqueued
        q = {(r.ecosystem, r.name): r.version for r in s.scalars(select(ScanQueue)).all()}
        assert q[("pypi", "requests")] == "2.31.0"
        assert q[("gomod", "github.com/gin-gonic/gin")] == "v1.9.1"


def test_focus_load_combined_is_authoritative(tmp_path, monkeypatch):
    sess = _use_temp_db(tmp_path, monkeypatch)
    f1 = tmp_path / "f1.txt"
    f1.write_text("[pypi]\nrequests\nflask\n", encoding="utf-8")
    runner.invoke(app, ["focus", "load", str(f1)])
    # Second load drops flask (authoritative sync).
    f2 = tmp_path / "f2.txt"
    f2.write_text("[pypi]\nrequests\n", encoding="utf-8")
    runner.invoke(app, ["focus", "load", str(f2)])
    from sqlalchemy import select
    from pkgsentry.store.models import FocusList
    with sess.session_scope() as s:
        names = {f.name for f in s.scalars(select(FocusList)).all()}
    assert names == {"requests"}


def test_focus_load_combined_rejects_content_before_header(tmp_path, monkeypatch):
    _use_temp_db(tmp_path, monkeypatch)
    bad = tmp_path / "bad.txt"
    bad.write_text("requests\n[pypi]\nflask\n", encoding="utf-8")
    r = runner.invoke(app, ["focus", "load", str(bad)])
    assert r.exit_code != 0
