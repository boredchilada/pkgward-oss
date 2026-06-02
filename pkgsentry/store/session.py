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
    engine = get_engine()
    Base.metadata.create_all(engine)
    _ensure_columns(engine)


# Lightweight additive migrations: `create_all` creates missing TABLES but never
# adds a COLUMN to an existing one. Each entry is idempotent (Postgres ADD COLUMN
# IF NOT EXISTS; SQLite is covered by create_all on fresh DBs / PRAGMA check).
_ADDITIVE_COLUMNS = (
    ("file_hash", "tlsh", "VARCHAR(128)"),
    ("package", "downloads_weekly", "BIGINT"),
    ("package", "downloads_fetched_at", "TIMESTAMPTZ"),
)


def _ensure_columns(engine) -> None:
    from sqlalchemy import text
    dialect = engine.dialect.name
    try:
        with engine.begin() as conn:
            for table, column, coltype in _ADDITIVE_COLUMNS:
                if dialect == "postgresql":
                    conn.execute(text(
                        f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {coltype}'
                    ))
                elif dialect == "sqlite":
                    cols = {r[1] for r in conn.execute(text(f'PRAGMA table_info({table})'))}
                    if column not in cols:
                        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}'))
    except Exception:
        # best-effort: a missing column surfaces loudly at insert time anyway
        pass


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
