# SPDX-License-Identifier: AGPL-3.0-or-later
"""`run -f <file>` focused-mode helper: authoritative sync + pinned enqueue."""
from sqlalchemy import select

from pkgsentry.store import session as sess
from pkgsentry.store.models import FocusList, ScanQueue


def _fresh(tmp_path, monkeypatch, name):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/name}")
    sess.reset_engine()
    sess.init_db()


def test_sync_focus_file_loads_all_sections_and_enqueues_pinned(tmp_path, monkeypatch):
    from pkgsentry import runtime
    _fresh(tmp_path, monkeypatch, "r.db")
    f = tmp_path / "focus.txt"
    f.write_text(
        "[pypi]\nrequests==2.31.0\nflask\n[gomod]\ngithub.com/gin-gonic/gin v1.9.1\n",
        encoding="utf-8",
    )
    runtime.sync_focus_file(str(f))

    with sess.session_scope() as s:
        eco = {}
        for r in s.scalars(select(FocusList)).all():
            eco.setdefault(r.ecosystem, set()).add(r.name)
        assert eco["pypi"] == {"requests", "flask"}
        assert eco["gomod"] == {"github.com/gin-gonic/gin"}
        q = {(r.ecosystem, r.name): r.version for r in s.scalars(select(ScanQueue)).all()}
        assert q[("pypi", "requests")] == "2.31.0"
        assert q[("gomod", "github.com/gin-gonic/gin")] == "v1.9.1"


def test_sync_focus_file_missing_is_graceful(tmp_path, monkeypatch):
    from pkgsentry import runtime
    _fresh(tmp_path, monkeypatch, "r2.db")
    runtime.sync_focus_file(str(tmp_path / "nope.txt"))  # no exception
    with sess.session_scope() as s:
        assert s.scalars(select(FocusList)).all() == []
