# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import hashlib
import math
import shutil
import tarfile
import tempfile
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import structlog

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgsentry.adapter import (
    ArchivePath, Finding, IntegrityError, NoFilesError, adapter_registry,
)
from pkgsentry.analyze.binary import analyze_binary_artifacts
from pkgsentry.analyze.entropy import analyze_entropy, analyze_entropy_delta
from pkgsentry.analyze.imports import analyze_imports
from pkgsentry.analyze.iocs import analyze_iocs
from pkgsentry.analyze.malware_patterns import analyze_malware_patterns
from pkgsentry.analyze.metadata import MetadataContext, analyze_metadata
from pkgsentry.analyze.opengrep_scan import analyze_opengrep, replaces_install_analyzer_for
from pkgsentry.analyze.version_diff import PreviousVersion, analyze_version_diff
from pkgsentry.analyze.threat_intel import check_files_batch as check_threat_intel
from pkgsentry.analyze.yara_scan import analyze_yara
from pkgsentry.detect.score import score_and_verdict
from pkgsentry.util.extract import safe_extract
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import mark_done, mark_failed
from pkgsentry.store import session as sess
from pkgsentry.detonate.client import get_client as get_detonation_client
from pkgsentry.detonate.gate import should_detonate
from pkgsentry.store.models import (
    Detonation,
    FileHash,
    Finding as FindingRow,
    Package,
    RuleHit,
    Scan,
    ScanQueue,
    TraceEvent,
    Version,
    Watchlist,
)

log = get_logger("pipeline")


def _is_watchlist(session: Session, name: str, ecosystem: str) -> Optional[int]:
    """Check if package is on the watchlist. Returns rank or None."""
    row = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem, Watchlist.name == name)
    ).first()
    return row.rank if row else None


def _archive_members(arc: ArchivePath) -> list[str]:
    p = str(arc.path).lower()
    try:
        if p.endswith((".tar.gz", ".tgz", ".tar", ".crate")):
            with tarfile.open(arc.path, "r:*") as t:
                return [m.name for m in t.getmembers() if m.isfile()]
        if p.endswith((".whl", ".zip", ".egg")):
            with zipfile.ZipFile(arc.path, "r") as z:
                return [i.filename for i in z.infolist() if not i.is_dir()]
    except Exception:
        return []
    return []


def _watchlist_top_names(session: Session, ecosystem: str, limit: int = 5000) -> list[str]:
    rows = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem).order_by(Watchlist.rank.asc()).limit(limit)
    ).all()
    return [w.name for w in rows]


def _upsert_package_and_version(
    session: Session, ecosystem: str, name: str, version: str
) -> Version:
    from sqlalchemy.exc import IntegrityError as SAIntegrityError

    pkg = session.scalars(
        select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
    ).first()
    if pkg is None:
        try:
            pkg = Package(ecosystem=ecosystem, name=name)
            session.add(pkg)
            session.flush()
        except SAIntegrityError:
            session.rollback()
            pkg = session.scalars(
                select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
            ).first()
    ver = session.scalars(
        select(Version).where(
            Version.ecosystem == ecosystem,
            Version.package_id == pkg.id,
            Version.version == version,
        )
    ).first()
    if ver is None:
        try:
            ver = Version(ecosystem=ecosystem, package_id=pkg.id, version=version)
            session.add(ver)
            session.flush()
        except SAIntegrityError:
            session.rollback()
            ver = session.scalars(
                select(Version).where(
                    Version.ecosystem == ecosystem,
                    Version.package_id == pkg.id,
                    Version.version == version,
                )
            ).first()
    return ver


def _apply_metadata(
    session: Session,
    ver: Version,
    metadata: dict,
    watchlist_rank: Optional[int],
) -> None:
    if not metadata:
        return
    ver.author = metadata.get("author") or None
    ver.author_email = metadata.get("author_email") or None
    ver.home_page = metadata.get("home_page") or None
    summary = metadata.get("summary")
    if summary:
        ver.summary = str(summary)[:1024]
    ver.requires_python = metadata.get("requires_python") or None
    ver.keywords = metadata.get("keywords") or None
    license_val = metadata.get("license")
    if license_val:
        ver.license_text = str(license_val)[:256]
    project_urls = metadata.get("project_urls")
    if isinstance(project_urls, dict):
        ver.project_urls = project_urls
    requires_dist = metadata.get("requires_dist")
    if isinstance(requires_dist, list):
        ver.requires_dist = requires_dist
    classifiers = metadata.get("classifiers")
    if isinstance(classifiers, list):
        ver.classifiers = classifiers
    upload_time_iso = metadata.get("upload_time")
    if upload_time_iso:
        try:
            ver.upload_time = datetime.fromisoformat(
                str(upload_time_iso).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            pass
    maintainer = metadata.get("maintainer")
    if maintainer:
        ver.maintainers = [maintainer]
    if watchlist_rank is not None:
        pkg = session.get(Package, ver.package_id)
        if pkg is not None:
            wl_row = session.scalars(
                select(Watchlist).where(
                    Watchlist.ecosystem == pkg.ecosystem,
                    Watchlist.name == pkg.name,
                )
            ).first()
            if wl_row is not None:
                ver.downloads_last_30d = wl_row.downloads_last_30d
    audit = dict(metadata)
    audit.pop("description", None)
    audit.pop("description_content_type", None)
    ver.metadata_json = audit
    ver.metadata_fetched_at = datetime.now(timezone.utc)


def _get_previous_version(
    session: Session, ecosystem: str, package_id: int, exclude_version_id: int
) -> Optional[PreviousVersion]:
    prev_ver = session.scalars(
        select(Version)
        .where(
            Version.ecosystem == ecosystem,
            Version.package_id == package_id,
            Version.id != exclude_version_id,
        )
        .order_by(Version.first_seen_at.desc())
        .limit(1)
    ).first()
    if prev_ver is None:
        return None
    prev_scan = session.scalars(
        select(Scan)
        .where(Scan.version_id == prev_ver.id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).first()
    if prev_scan is None:
        return None
    prev_findings = session.scalars(
        select(FindingRow.rule_id).where(FindingRow.scan_id == prev_scan.id)
    ).all()
    return PreviousVersion(
        version=prev_ver.version,
        verdict=prev_scan.verdict,
        score=prev_scan.score,
        rule_ids=set(prev_findings),
        finding_count=len(prev_findings),
        author=prev_ver.author,
        author_email=prev_ver.author_email,
        upload_time=prev_ver.upload_time,
        requires_dist=prev_ver.requires_dist or [],
    )


def _bump_rulehits_deferred(findings: Iterable[Finding]) -> None:
    """Bump rule hit counts in a separate short transaction to avoid deadlocks."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1

    if not counts:
        return

    with sess.session_scope() as s:
        for rule_id, delta in counts.items():
            row = s.get(RuleHit, rule_id)
            if row is None:
                s.add(RuleHit(rule_id=rule_id, count=delta))
            else:
                row.count += delta


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


@dataclass
class FileInfo:
    sha256: str
    entropy: float
    ssdeep: str


def _compute_file_hashes(
    root: Path, archive_kind: str,
) -> tuple[dict[str, FileInfo], dict[str, str]]:
    """Walk *root*, SHA-256 + entropy + ssdeep every file.

    Returns ``(normalized_info, norm_to_real)`` where keys are normalized
    relative paths and values are FileInfo with sha256/entropy/ssdeep.
    """
    try:
        import ppdeep
        _ssdeep = ppdeep.hash
    except ImportError:
        _ssdeep = None

    normalized_info: dict[str, FileInfo] = {}
    norm_to_real: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        real = rel.as_posix()
        parts = rel.parts
        if archive_kind in ("sdist", "crate", "gomod_zip", "npm_tarball") and len(parts) > 1:
            normalized = "/".join(parts[1:])
        else:
            normalized = real
        try:
            data = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        ent = _shannon_entropy(data) if len(data) >= 64 else 0.0
        fuzzy = _ssdeep(data) if _ssdeep and len(data) >= 64 else ""
        normalized_info[normalized] = FileInfo(sha256=sha, entropy=ent, ssdeep=fuzzy)
        norm_to_real[normalized] = real
    return normalized_info, norm_to_real


def _get_prev_scan_hashes(
    session: Session, ecosystem: str, name: str, current_version: str,
) -> dict[str, dict[str, FileInfo]]:
    """Return ``{archive_kind: {normalized_path: FileInfo}}`` from the most
    recent scan of any *previous* version of the same package."""
    pkg = session.scalars(
        select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
    ).first()
    if pkg is None:
        return {}
    prev_ver = session.scalars(
        select(Version)
        .where(
            Version.ecosystem == ecosystem,
            Version.package_id == pkg.id,
            Version.version != current_version,
        )
        .order_by(Version.first_seen_at.desc())
        .limit(1)
    ).first()
    if prev_ver is None:
        return {}
    prev_scan = session.scalars(
        select(Scan)
        .where(Scan.version_id == prev_ver.id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).first()
    if prev_scan is None:
        return {}
    rows = session.scalars(
        select(FileHash).where(FileHash.scan_id == prev_scan.id)
    ).all()
    result: dict[str, dict[str, FileInfo]] = {}
    for row in rows:
        result.setdefault(row.archive_kind, {})[row.file_path] = FileInfo(
            sha256=row.sha256,
            entropy=row.entropy or 0.0,
            ssdeep=row.ssdeep or "",
        )
    return result


def _find_changed_files(
    current_info: dict[str, FileInfo],
    prev_info: dict[str, FileInfo],
    norm_to_real: dict[str, str],
) -> set[str]:
    """Return extraction-relative paths for files that are new or changed."""
    changed: set[str] = set()
    for norm_path, cur in current_info.items():
        prev = prev_info.get(norm_path)
        if prev is None or prev.sha256 != cur.sha256:
            changed.add(norm_to_real[norm_path])
    return changed


def _persist_file_hashes(
    session: Session,
    scan_id: int,
    hashes_by_kind: list[tuple[str, dict[str, FileInfo]]],
) -> None:
    for kind, infos in hashes_by_kind:
        for path, info in infos.items():
            session.add(FileHash(
                scan_id=scan_id, archive_kind=kind,
                file_path=path, sha256=info.sha256,
                ssdeep=info.ssdeep or None,
                entropy=info.entropy,
            ))


def _extract_and_hash(arc: ArchivePath, sub: Path) -> tuple[dict[str, FileInfo], dict[str, str], list[str]]:
    safe_extract(arc.path, sub)
    members = _archive_members(arc)
    current_info, norm_to_real = _compute_file_hashes(sub, arc.kind)
    return current_info, norm_to_real, members


def _run_analyzers(
    sub: Path,
    changed: set[str] | None,
    current_info: dict[str, FileInfo],
    prev_info: dict[str, FileInfo],
    norm_to_real: dict[str, str],
    ecosystem: str = "pypi",
) -> list[Finding]:
    findings: list[Finding] = []
    if ecosystem == "pypi":
        findings.extend(analyze_imports(sub, changed_files=changed))
        findings.extend(analyze_malware_patterns(sub, changed_files=changed))
    findings.extend(analyze_iocs(sub, changed_files=changed))
    findings.extend(analyze_entropy(sub, changed_files=changed))
    findings.extend(analyze_entropy_delta(current_info, prev_info, norm_to_real))
    findings.extend(analyze_binary_artifacts(sub, changed_files=changed))
    findings.extend(analyze_yara(sub, changed_files=changed))
    findings.extend(analyze_opengrep(sub, changed_files=changed, ecosystem=ecosystem))
    return findings


def _persist_findings(session: Session, scan: Scan, findings: list[Finding]) -> None:
    for f in findings:
        session.add(FindingRow(
            scan_id=scan.id,
            rule_id=f.rule_id, category=f.category, severity=f.severity,
            confidence=f.confidence, file=f.file or "", line=f.line, evidence=f.evidence or "",
        ))


def _persist_and_finalize(
    *,
    queue_id: int,
    claim_token: Optional[str],
    ecosystem: str,
    name: str,
    version: str,
    started_at: datetime,
    metadata: dict,
    archives: list[ArchivePath],
    tmp_extract: Path,
    all_findings: list[Finding],
    all_file_hashes: list[tuple[str, dict[str, FileInfo]]],
    fetch_error: Optional[Exception],
    fetch_error_type: Optional[str],
    sdist_files: list[str],
    wheel_files: list[str],
) -> None:
    """Scoring, persistence, detonation, LLM triage — all sync, runs in thread."""
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is None:
            return

        ver = _upsert_package_and_version(s, ecosystem, name, version)
        scan = Scan(version_id=ver.id, started_at=started_at, verdict="clean", score=0)
        s.add(scan)
        s.flush()

        if fetch_error is not None:
            rank = _is_watchlist(s, name, ecosystem)
            result = score_and_verdict(all_findings, watchlist_rank=rank)
            scan.verdict = result.verdict
            scan.score = result.score
            scan.alert_tag = result.alert_tag
            scan.finished_at = datetime.now(timezone.utc)
            _persist_findings(s, scan, all_findings)
            if fetch_error_type == "no_files":
                mark_failed(s, row, str(fetch_error), token=claim_token)
            else:
                mark_done(s, row, token=claim_token)
            # session commits on exit, then bump rulehits separately
            _bump_rulehits_deferred(all_findings)
            return

        prev = _get_previous_version(s, ecosystem, ver.package_id, ver.id)

        cur_author = metadata.get("maintainer") or metadata.get("author")
        prev_maintainers = []
        prev_release_at = None
        if prev is not None:
            prev_maintainers = [prev.author or ""] if prev.author else []
            prev_release_at = prev.upload_time

        ctx = MetadataContext(
            name=name,
            version=version,
            previous_release_at=prev_release_at,
            maintainers_now=[cur_author] if cur_author else [],
            maintainers_prev=prev_maintainers,
            watchlist_top_names=_watchlist_top_names(s, ecosystem),
            sdist_files=sdist_files,
            wheel_files=wheel_files,
        )
        all_findings.extend(analyze_metadata(ctx))

        if prev is not None:
            all_findings.extend(
                analyze_version_diff(all_findings, metadata, prev)
            )

        # Threat intel: check file hashes against known-malicious fingerprints
        for kind, infos in all_file_hashes:
            intel_batch = {
                path: {"sha256": fi.sha256, "ssdeep": fi.ssdeep}
                for path, fi in infos.items()
            }
            all_findings.extend(check_threat_intel(s, intel_batch))

        rank = _is_watchlist(s, name, ecosystem)
        result = score_and_verdict(all_findings, watchlist_rank=rank)
        scan.verdict = result.verdict
        scan.score = result.score
        scan.alert_tag = result.alert_tag
        scan.finished_at = datetime.now(timezone.utc)

        _apply_metadata(s, ver, metadata, watchlist_rank=rank)
        _persist_findings(s, scan, all_findings)
        _persist_file_hashes(s, scan.id, all_file_hashes)

        # --- Detonation (best-effort, sync) ---
        # npm detonation re-enabled: the detonation noise baseline now whitelists
        # .npmrc reads (npm_file_noise) and registry connections (npm_net_allow),
        # so normal `npm install` traffic no longer false-positives as malicious.
        _DETONATION_ECOSYSTEMS = {"pypi", "crates", "gomod", "npm"}
        _PREFERRED_ARCHIVE = {"pypi": "sdist", "crates": "crate", "gomod": "gomod_zip", "npm": "npm_tarball"}
        is_first_version = prev is None
        det_client = get_detonation_client()
        if ecosystem in _DETONATION_ECOSYSTEMS and det_client.is_enabled() and should_detonate(
            verdict=result.verdict,
            score=result.score,
            findings=all_findings,
            watchlist_rank=rank,
            is_new_package=is_first_version,
        ):
            det_archive = None
            preferred = _PREFERRED_ARCHIVE.get(ecosystem, "sdist")
            for arc in archives:
                if arc.kind == preferred:
                    det_archive = arc
                    break
            if det_archive is None and archives:
                det_archive = archives[0]

            if det_archive is not None:
                try:
                    log.info("detonation_start", archive=det_archive.kind)
                    det_result = det_client.detonate_sync(
                        ecosystem=ecosystem,
                        name=name,
                        version=version,
                        archive_path=str(det_archive.path),
                        archive_kind=det_archive.kind,
                    )
                    if det_result is not None:
                        det_row = Detonation(
                            scan_id=scan.id,
                            ecosystem=ecosystem,
                            sandbox_id=det_result.detonation_id,
                            status=det_result.status,
                            install_exit_code=det_result.install_phase.exit_code if det_result.install_phase else None,
                            install_duration_ms=det_result.install_phase.duration_ms if det_result.install_phase else None,
                            install_timed_out=det_result.install_phase.timed_out if det_result.install_phase else False,
                            import_exit_code=det_result.import_phase.exit_code if det_result.import_phase else None,
                            import_duration_ms=det_result.import_phase.duration_ms if det_result.import_phase else None,
                            import_timed_out=det_result.import_phase.timed_out if det_result.import_phase else False,
                            total_trace_events=det_result.total_trace_events,
                            filtered_trace_events=det_result.filtered_trace_events,
                            finished_at=datetime.now(timezone.utc),
                        )
                        s.add(det_row)
                        s.flush()

                        for evt in det_result.trace_events_json:
                            s.add(TraceEvent(
                                detonation_id=det_row.id,
                                phase=evt.get("phase", "install"),
                                category=evt.get("category", "unknown"),
                                operation=evt.get("operation", "unknown"),
                                pid=evt.get("pid"),
                                binary=evt.get("binary"),
                                detail=evt.get("detail") or {},
                                matched_rule=evt.get("matched_rule"),
                            ))

                        dyn_findings = det_result.to_findings()
                        if dyn_findings:
                            all_findings.extend(dyn_findings)
                            _persist_findings(s, scan, dyn_findings)
                            result = score_and_verdict(all_findings, watchlist_rank=rank)
                            scan.verdict = result.verdict
                            scan.score = result.score
                            scan.alert_tag = result.alert_tag
                            log.info(
                                "detonation_rescored",
                                dyn_findings=len(dyn_findings),
                                new_verdict=result.verdict, new_score=result.score,
                            )

                        log.info(
                            "detonation_done",
                            status=det_result.status,
                            trace_events=det_result.total_trace_events,
                            dyn_findings=len(dyn_findings) if det_result else 0,
                        )
                except Exception as e:
                    log.warning("detonation_skipped", error=str(e))

        # --- LLM triage (sync) ---
        llm_dominated = result.verdict == "malicious"
        if llm_dominated:
            from pkgsentry.llm import triage as llm_triage_mod
            if llm_triage_mod.is_enabled():
                try:
                    triage_root = None
                    _triage_adapter = adapter_registry.get(ecosystem)
                    _triage_kind = _triage_adapter.install_archive_kind if _triage_adapter else "sdist"
                    for arc in archives:
                        if arc.kind == _triage_kind:
                            triage_root = tmp_extract / arc.kind
                            break
                    if triage_root is None and archives:
                        triage_root = tmp_extract / archives[0].kind
                    if triage_root is not None:
                        log.info(
                            "llm_triage_start",
                            rule_verdict=result.verdict, score=result.score,
                            n_findings=len(all_findings),
                        )
                        tri = llm_triage_mod.triage(
                            pkg_name=name, pkg_version=version,
                            rule_verdict=result.verdict, findings=all_findings,
                            extracted_root=triage_root,
                            ecosystem=ecosystem,
                        )
                        scan.llm_model = tri.model
                        scan.llm_verdict = tri.verdict
                        scan.llm_confidence = tri.confidence
                        scan.llm_reasoning = tri.reasoning
                        scan.llm_iocs = tri.iocs
                        scan.llm_agrees_with_rules = tri.agrees_with_rules
                        scan.llm_prompt_tokens = tri.prompt_tokens
                        scan.llm_completion_tokens = tri.completion_tokens
                        scan.llm_cost_usd = tri.cost_usd
                        scan.llm_latency_ms = tri.latency_ms
                        scan.llm_raw_response = tri.raw_response
                        if tri.verdict in ("malicious", "suspicious", "benign"):
                            scan.verdict = tri.verdict
                        log.info(
                            "llm_triage_done",
                            rule_verdict=result.verdict, llm_verdict=tri.verdict,
                            cost=tri.cost_usd, latency_ms=tri.latency_ms,
                        )
                        if tri.verdict == "malicious":
                            from pkgsentry.notify import discord as discord_notify
                            if discord_notify.is_enabled():
                                discord_notify.send_alert(
                                    pkg_name=name, pkg_version=version,
                                    ecosystem=ecosystem,
                                    rule_verdict=result.verdict,
                                    rule_score=result.score,
                                    n_findings=len(all_findings),
                                    triage=tri, findings=all_findings,
                                )
                except Exception as e:
                    log.warning("llm_triage_skipped", error=str(e))

        mark_done(s, row, token=claim_token)
        final_verdict = scan.verdict
        final_score = result.score
        final_alert_tag = result.alert_tag

    # Rulehit counts in separate transaction — avoids row-lock deadlocks
    _bump_rulehits_deferred(all_findings)

    duration_s = round((datetime.now(timezone.utc) - started_at).total_seconds(), 1)
    log.info(
        "scan_done",
        verdict=final_verdict, score=final_score, n_findings=len(all_findings),
        alert_tag=final_alert_tag, duration_s=duration_s,
    )


async def process_one(queue_id: int, claim_token: Optional[str] = None) -> None:
    """Fetch, analyze, and persist scan results for a single queue item.

    Sessions are opened only for short DB bursts — never held across network I/O.
    """
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is None or row.status != "claimed":
            return
        if claim_token is not None and row.claim_token != claim_token:
            log.warning("claim_stolen", queue_id=queue_id)
            return
        ecosystem = row.ecosystem
        name = row.name
        version = row.version

    adapter = adapter_registry.get(ecosystem)
    if adapter is None:
        with sess.session_scope() as s:
            row = s.get(ScanQueue, queue_id)
            if row is not None:
                mark_failed(s, row, f"no_adapter_for_ecosystem:{ecosystem}", token=claim_token)
        return

    # Bind a short scan trace ID so every log line during this scan is
    # searchable with a single grep.  The worker already bound `w=<id>`.
    sid = uuid.uuid4().hex[:8]
    structlog.contextvars.bind_contextvars(
        sid=sid, ecosystem=ecosystem, pkg=f"{name}=={version}",
    )

    # --- Phase 1: Async I/O (no DB session open) ---
    safe_name = name.replace("/", "_")
    _staging = Path("/tmp/pkgsentry")
    _staging.mkdir(parents=True, exist_ok=True)
    tmp_extract = Path(tempfile.mkdtemp(prefix=f"x-{safe_name}-{version}-", dir=_staging))
    tmp_extract.chmod(0o755)
    archives: list[ArchivePath] = []
    metadata: dict = {}
    fetch_error: Optional[Exception] = None
    fetch_error_type: Optional[str] = None
    started_at = datetime.now(timezone.utc)
    log.info("scan_start")

    try:
        try:
            fetched = await adapter.fetch(name, version)
            if hasattr(fetched, "archives"):
                archives = fetched.archives
                metadata = fetched.metadata or {}
            else:
                archives = fetched
                metadata = {}
        except NoFilesError as e:
            fetch_error = e
            fetch_error_type = "no_files"
        except IntegrityError as e:
            fetch_error = e
            fetch_error_type = "sha256_mismatch"

        all_findings: list[Finding] = []
        all_file_hashes: list[tuple[str, dict[str, FileInfo]]] = []
        sdist_files: list[str] = []
        wheel_files: list[str] = []

        if fetch_error is not None:
            if fetch_error_type == "sha256_mismatch":
                all_findings.append(Finding(
                    rule_id="fetch.sha256_mismatch", category="fetch", severity="critical",
                    confidence="high", file="", line=None, evidence=str(fetch_error),
                ))
            else:
                all_findings.append(Finding(
                    rule_id="fetch.no_release_files", category="fetch", severity="medium",
                    confidence="high", file="", line=None, evidence=str(fetch_error),
                ))
        else:
            # --- Phase 1.5: Fetch baseline file hashes (short DB burst) ---
            prev_hashes_by_kind: dict[str, dict[str, FileInfo]] = {}
            with sess.session_scope() as s:
                prev_hashes_by_kind = _get_prev_scan_hashes(s, ecosystem, name, version)

            # --- Phase 2: Analysis (CPU-bound, offloaded to thread) ---
            for arc in archives:
                sub = tmp_extract / arc.kind
                arc_size = arc.path.stat().st_size

                t0 = time.monotonic()
                log.info("extracting", kind=arc.kind,
                         size_mb=round(arc_size / (1024 * 1024), 1))
                current_info, norm_to_real, members = await asyncio.to_thread(
                    _extract_and_hash, arc, sub,
                )
                t_extract = round(time.monotonic() - t0, 1)
                log.info("extracted", kind=arc.kind,
                         files=len(current_info), duration_s=t_extract)

                if arc.kind == "sdist":
                    sdist_files = members
                else:
                    wheel_files = members

                all_file_hashes.append((arc.kind, current_info))

                changed: set[str] | None = None
                prev_info = prev_hashes_by_kind.get(arc.kind, {})
                if prev_info:
                    changed = _find_changed_files(current_info, prev_info, norm_to_real)
                    if not changed:
                        log.info("no_code_changes", kind=arc.kind)
                        continue
                    log.info(
                        "code_diff", kind=arc.kind,
                        changed=len(changed), total=len(current_info),
                    )

                if arc.kind == adapter.install_archive_kind and not replaces_install_analyzer_for(ecosystem):
                    all_findings.extend(await adapter.analyze_install(sub, changed_files=changed))

                t1 = time.monotonic()
                log.info("analyzing", kind=arc.kind)
                analyzer_findings = await asyncio.to_thread(
                    _run_analyzers, sub, changed, current_info, prev_info, norm_to_real,
                    ecosystem=ecosystem,
                )
                t_analyze = round(time.monotonic() - t1, 1)
                all_findings.extend(analyzer_findings)
                log.info("analyzed", kind=arc.kind,
                         findings=len(analyzer_findings), duration_s=t_analyze)

        # --- Phase 3+4: Persist, detonate, triage (all sync, in thread) ---
        log.info("persisting", findings=len(all_findings),
                 hashes=sum(len(h) for _, h in all_file_hashes))
        await asyncio.to_thread(
            _persist_and_finalize,
            queue_id=queue_id,
            claim_token=claim_token,
            ecosystem=ecosystem,
            name=name,
            version=version,
            started_at=started_at,
            metadata=metadata,
            archives=archives,
            tmp_extract=tmp_extract,
            all_findings=all_findings,
            all_file_hashes=all_file_hashes,
            fetch_error=fetch_error,
            fetch_error_type=fetch_error_type,
            sdist_files=sdist_files,
            wheel_files=wheel_files,
        )
    except Exception as e:
        err_type = type(e).__name__
        err_msg = str(e).split("\n")[0][:200]
        log.warning("pipeline_failed", error_type=err_type, error=err_msg)
        try:
            with sess.session_scope() as s:
                row = s.get(ScanQueue, queue_id)
                if row is not None and row.status != "done":
                    mark_failed(s, row, str(e)[:4000], token=claim_token)
        except Exception:
            log.exception("pipeline_fail_handler_error")
    finally:
        shutil.rmtree(tmp_extract, ignore_errors=True)
        for arc in archives:
            try:
                parent = Path(arc.path).parent
                shutil.rmtree(parent, ignore_errors=True)
            except Exception:
                pass
