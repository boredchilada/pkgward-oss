# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Package(Base):
    __tablename__ = "package"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        UniqueConstraint("ecosystem", "name", name="uq_package_ecosystem_name"),
        Index("ix_package_name", "name"),
    )

    versions: Mapped[list["Version"]] = relationship(back_populates="package")


class Version(Base):
    __tablename__ = "version"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    package_id: Mapped[int] = mapped_column(ForeignKey("package.id", ondelete="CASCADE"))
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    maintainers: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    upload_user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Rich PyPI metadata captured at scan time (populated by pipeline._apply_metadata)
    author: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    author_email: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    home_page: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requires_python: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    keywords: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    license_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    upload_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    project_urls: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    requires_dist: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    classifiers: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    downloads_last_30d: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    metadata_fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package_id", "version",
            name="uq_version_ecosystem_pkg_version",
        ),
    )

    package: Mapped[Package] = relationship(back_populates="versions")
    scans: Mapped[list["Scan"]] = relationship(back_populates="version")


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("version.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verdict: Mapped[str] = mapped_column(String(16), default="clean")  # clean|suspicious|malicious|error
    score: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    alert_tag: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # LLM triage enrichment (best-effort, populated for suspicious/malicious verdicts)
    llm_model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    llm_verdict: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    llm_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    llm_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    llm_iocs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    llm_agrees_with_rules: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    llm_prompt_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    llm_completion_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    llm_cost_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    llm_latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    llm_raw_response: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    version: Mapped[Version] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # low|medium|high|critical
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    file: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")


class ScanQueue(Base):
    __tablename__ = "scan_queue"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="normal")  # high|normal|low
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")    # pending|claimed|done|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claim_token: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enqueued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "name", "version",
            name="uq_scanqueue_ecosystem_name_version",
        ),
        Index("ix_scanqueue_pull", "status", "priority", "enqueued_at"),
    )


class ScanCursor(Base):
    __tablename__ = "scan_cursor"
    ecosystem: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_serial: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Watchlist(Base):
    __tablename__ = "watchlist"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    downloads_last_30d: Mapped[int] = mapped_column(BigInteger, default=0)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("ecosystem", "name", name="uq_watchlist_ecosystem_name"),
        Index("ix_watchlist_rank", "ecosystem", "rank"),
    )


class FocusList(Base):
    """Operator-supplied per-ecosystem focus packages — a personal watchlist.

    Name-level: every new release of a focus package is enqueued at high
    priority. ``pinned_version`` (optional) is the version the operator is
    currently running, scanned once at load time. With
    ``PKGSENTRY_FOCUS_EXCLUSIVE=1`` the scanner ingests ONLY these packages.
    """

    __tablename__ = "focus_list"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    pinned_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("ecosystem", "name", name="uq_focuslist_ecosystem_name"),
        Index("ix_focuslist_ecosystem", "ecosystem"),
    )


class FileHash(Base):
    __tablename__ = "file_hash"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    archive_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ssdeep: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    entropy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_file_hash_scan_id", "scan_id"),
    )


class RuleHit(Base):
    __tablename__ = "rule_hit"
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


class Detonation(Base):
    __tablename__ = "detonation"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, default="pypi")
    sandbox_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    install_exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    install_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    install_timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    import_exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    import_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    import_timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    total_trace_events: Mapped[int] = mapped_column(Integer, default=0)
    filtered_trace_events: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_detonation_scan_id", "scan_id"),
    )


class ThreatIntelHash(Base):
    """Known-malicious file fingerprints from verified campaigns."""
    __tablename__ = "threat_intel_hash"
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ssdeep: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    tlsh: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    campaign: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False, default="malicious")
    file_pattern: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_threat_intel_sha256", "sha256"),
        Index("ix_threat_intel_campaign", "campaign"),
    )


class TraceEvent(Base):
    __tablename__ = "trace_event"
    id: Mapped[int] = mapped_column(primary_key=True)
    detonation_id: Mapped[int] = mapped_column(ForeignKey("detonation.id", ondelete="CASCADE"))
    phase: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    binary: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False)
    matched_rule: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_trace_event_detonation_id", "detonation_id"),
        Index("ix_trace_event_category", "category"),
    )
