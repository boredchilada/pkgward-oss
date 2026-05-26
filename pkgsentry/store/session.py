# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from pkgsentry.store.models import Base
from pkgsentry.util.env import env_chain

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker[Session]] = None

DEFAULT_URL = "sqlite:///pkgsentry.db"


def _url() -> str:
    return env_chain(
        "PKGSENTRY_DB_URL",
        "PKGWATCH_DB_URL",
        "PYPI_SCANNER_DB_URL",
        "pkgsentry_DB_URL",
        default=DEFAULT_URL,
    ) or DEFAULT_URL


def _sqlite_tune(dbapi_conn, _conn_record):
    cur = dbapi_conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
    finally:
        cur.close()


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        url = _url()
        is_sqlite = url.startswith("sqlite")
        if is_sqlite:
            connect_args = {"check_same_thread": False, "timeout": 10}
            _engine = create_engine(
                url, future=True, pool_pre_ping=True,
                connect_args=connect_args,
            )
            event.listen(_engine, "connect", _sqlite_tune)
        else:
            _engine = create_engine(
                url, future=True, pool_pre_ping=True,
                pool_size=8, max_overflow=4,
                pool_timeout=30,
                connect_args={
                    "connect_timeout": 10,
                    "options": "-c statement_timeout=120000",  # 120s
                },
            )
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def reset_engine() -> None:
    """Test helper: drop cached engine/session factory."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def init_db() -> None:
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _SessionLocal is not None
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
