# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import hashlib
import math
import os
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
    ArchivePath, EcosystemAdapter, Finding, IntegrityError, NoFilesError, adapter_registry,
)
from pkgsentry.analyze.binary import analyze_binary_artifacts
from pkgsentry.analyze.entropy import analyze_entropy, analyze_entropy_delta
from pkgsentry.analyze.imports import analyze_imports
from pkgsentry.analyze.iocs import analyze_iocs
from pkgsentry.analyze.secret_access import analyze_secret_access
from pkgsentry.analyze.malware_patterns import analyze_malware_patterns
from pkgsentry.analyze.metadata import MetadataContext, analyze_metadata
from pkgsentry.analyze.obfuscation import analyze_obfuscation
from pkgsentry.analyze.opengrep_scan import analyze_opengrep, replaces_install_analyzer_for
from pkgsentry.analyze.version_diff import PreviousVersion, analyze_version_diff
from pkgsentry.analyze.threat_intel import check_files_batch as check_threat_intel
from pkgsentry.analyze.yara_scan import analyze_yara
from pkgsentry.detect.score import score_and_verdict, _is_shadow_finding
from pkgsentry import vault
from pkgsentry.util import capabilities as caps
from pkgsentry.util.extract import safe_extract
from pkgsentry.logging_setup import get_logger
from pkgsentry.queue import mark_done, mark_failed
from pkgsentry.store import session as sess
from pkgsentry.detonate.client import get_client as get_detonation_client
from pkgsentry.detonate.gate import should_detonate
from pkgsentry import detonation_queue
from pkgsentry.store.models import (
    FileHash,
    Finding as FindingRow,
    Package,
    RuleHit,
    Scan,
    ScanQueue,
    Version,
    Watchlist,
)

log = get_logger("pipeline")

_DETONATION_ECOSYSTEMS = {"pypi", "crates", "gomod", "npm"}
_PREFERRED_ARCHIVE = {"pypi": "sdist", "crates": "crate", "gomod": "gomod_zip", "npm": "npm_tarball"}


def _detonation_priority(*, verdict: str, watchlist_rank: Optional[int]) -> str:
    if verdict in ("suspicious", "malicious") or watchlist_rank is not None:
        return "high"
    return "low"


def _detonation_cluster_enabled(det_client) -> bool:
    """Whether to enqueue detonation jobs from this host.

    True if a detonation service is reachable locally, OR detonation is deployed
    elsewhere in the cluster (DETONATION_ENABLED=1) so a scan-only worker host
    still enqueues for a draining host to pick up. Default off keeps single-host
    no-detonation deployments from piling up undrained jobs.
    """
    return det_client.is_enabled() or os.environ.get("DETONATION_ENABLED", "0") != "0"


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
    except Exception as e:
        # A swallowed-empty here silently blinds the sdist/wheel-mismatch and
        # lure-file metadata checks (they see zero files and can't fire). Log so
        # the degradation is observable rather than a silent detection-loss.
        log.warning("archive_members_failed", path=str(arc.path), error=str(e))
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


# Files larger than this get SHA-256 only (streamed). Entropy/ssdeep/TLSH are
# O(n) in pure Python (or near it) and ruinously slow on big prebuilt native
# binaries (e.g. ~50-200MB platform packages: esbuild/turbo/swc/AI tools) while
# adding little signal — a compiled binary is always near-max entropy and rarely
# matches a fuzzy fingerprint. Exact SHA-256 (threat-intel) still covers them.
HASH_FULL_MAX_BYTES = int(os.environ.get("PKGSENTRY_HASH_FULL_MAX_MB", "20")) * 1024 * 1024

# Giant-package fast-path. A handful of huge packages (Go monorepos like gitea /
# go-ethereum, fat JS component libs) take 10s of seconds of pure-Python CPU to
# fuzzy-hash + analyze, and with many workers in one process sharing the GIL they
# blow the per-package timeout and burn a worker for 15 min. When a package is
# "giant" (file count or extracted size over the threshold) and the fast-path is
# ON, skip the heaviest per-file work — ssdeep/TLSH fuzzy hashing, entropy, and
# the obfuscation analyzer — keeping SHA-256 (exact threat-intel), opengrep, yara,
# iocs, imports, malware-patterns, binary, metadata. Detection-critical signatures
# stay; only fuzzy-hash + entropy/obfuscation heuristics are dropped on giants
# (low risk — giants are legitimate big projects, not lures). Toggle with
# PKGSENTRY_GIANT_FASTPATH=0.
GIANT_FASTPATH = os.environ.get("PKGSENTRY_GIANT_FASTPATH", "1") != "0"
GIANT_FILE_THRESHOLD = int(os.environ.get("PKGSENTRY_GIANT_FILE_THRESHOLD", "5000"))
GIANT_MAX_BYTES = int(os.environ.get("PKGSENTRY_GIANT_MAX_MB", "100")) * 1024 * 1024


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _sha256_stream(path: Path) -> str:
    """SHA-256 without loading the whole file into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class FileInfo:
    sha256: str
    entropy: float
    ssdeep: str
    tlsh: str = ""


def _compute_file_hashes(
    root: Path, archive_kind: str, lite: bool = False,
) -> tuple[dict[str, FileInfo], dict[str, str]]:
    """Walk *root*, SHA-256 + entropy + ssdeep + tlsh every file.

    Returns ``(normalized_info, norm_to_real)`` where keys are normalized
    relative paths and values are FileInfo with sha256/entropy/ssdeep/tlsh.
    With ``lite`` (giant-package fast-path) the per-file fuzzy hashing + entropy
    are skipped — SHA-256 only — to keep a huge package off the shared-GIL hot
    path.
    """
    _ssdeep = None if lite else (caps.ppdeep.hash if caps.HAS_PPDEEP else None)
    _tlsh = None if lite else (caps.tlsh.hash if caps.HAS_TLSH else None)

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
            size = p.stat().st_size
        except OSError:
            continue
        if size > HASH_FULL_MAX_BYTES:
            # Large file: stream SHA-256 only, skip the expensive metrics.
            try:
                sha = _sha256_stream(p)
            except OSError:
                continue
            normalized_info[normalized] = FileInfo(sha256=sha, entropy=0.0, ssdeep="", tlsh="")
            norm_to_real[normalized] = real
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        ent = 0.0 if lite else (_shannon_entropy(data) if len(data) >= 64 else 0.0)
        fuzzy = _ssdeep(data) if _ssdeep and len(data) >= 64 else ""
        tl = _tlsh(data) if _tlsh and len(data) >= 64 else ""
        normalized_info[normalized] = FileInfo(sha256=sha, entropy=ent, ssdeep=fuzzy, tlsh=tl)
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
                file_path=_strip_nul(path), sha256=info.sha256,
                ssdeep=info.ssdeep or None,
                tlsh=info.tlsh or None,
                entropy=info.entropy,
            ))


def _giant_lite(root: Path) -> bool:
    """Decide whether the extracted tree is 'giant' (skip the heaviest per-file
    work). Cheap single walk: dirent + stat, no file reads."""
    if not GIANT_FASTPATH:
        return False
    count = 0
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        count += 1
        try:
            total += p.stat().st_size
        except OSError:
            pass
        if count > GIANT_FILE_THRESHOLD or total > GIANT_MAX_BYTES:
            return True
    return False


def _extract_and_hash(
    arc: ArchivePath, sub: Path,
) -> tuple[dict[str, FileInfo], dict[str, str], list[str], bool]:
    safe_extract(arc.path, sub)
    # Recover UPX-packed payloads (decompress-only, never executed) before hashing
    # so the real payload is fingerprinted by threat-intel and seen by every
    # analyzer — packed binaries are otherwise a blind spot for static + LLM.
    try:
        from pkgsentry.analyze.unpack import unpack_packed_executables
        unpacked = unpack_packed_executables(sub)
        if unpacked:
            log.info("unpacked_payloads", kind=arc.kind,
                     n=len(unpacked), results=unpacked[:10])
    except Exception as e:
        log.warning("unpack_pass_failed", error=str(e))
    members = _archive_members(arc)
    lite = _giant_lite(sub)
    if lite:
        log.info("giant_fastpath", kind=arc.kind,
                 file_threshold=GIANT_FILE_THRESHOLD,
                 max_mb=GIANT_MAX_BYTES // (1024 * 1024))
    current_info, norm_to_real = _compute_file_hashes(sub, arc.kind, lite=lite)
    return current_info, norm_to_real, members, lite


def _run_analyzers(
    sub: Path,
    changed: set[str] | None,
    current_info: dict[str, FileInfo],
    prev_info: dict[str, FileInfo],
    norm_to_real: dict[str, str],
    ecosystem: str = "pypi",
    lite: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if ecosystem == "pypi":
        findings.extend(analyze_imports(sub, changed_files=changed))
        findings.extend(analyze_malware_patterns(sub, changed_files=changed))
    findings.extend(analyze_iocs(sub, changed_files=changed))
    findings.extend(analyze_secret_access(sub, changed_files=changed))
    # Giant fast-path: skip the heaviest per-file CPU analyzers (entropy +
    # obfuscation). entropy_delta is cheap (prev-vs-current FileInfo) — keep it.
    if not lite:
        findings.extend(analyze_entropy(sub, changed_files=changed))
        findings.extend(analyze_obfuscation(sub, changed_files=changed))
    findings.extend(analyze_entropy_delta(current_info, prev_info, norm_to_real))
    findings.extend(analyze_binary_artifacts(sub, changed_files=changed))
    findings.extend(analyze_yara(sub, changed_files=changed))
    findings.extend(analyze_opengrep(sub, changed_files=changed, ecosystem=ecosystem))
    return findings


async def run_static_analyzers(
    sub: Path,
    *,
    ecosystem: str,
    adapter: EcosystemAdapter,
    arc_kind: str,
    changed: set[str] | None = None,
    current_info: dict[str, FileInfo] | None = None,
    prev_info: dict[str, FileInfo] | None = None,
    norm_to_real: dict[str, str] | None = None,
    lite: bool = False,
) -> list[Finding]:
    """Compose all static analyzers for an extracted archive root.

    Single source of truth for "which static analyzers run for ecosystem X over
    this extracted dir" — the install-analyzer gate plus ``_run_analyzers``. Both
    ``process_one`` and the regression-corpus harness call this so they cannot
    drift. ``_run_analyzers`` is CPU-bound and offloaded to a thread (the install
    analyzer is awaited directly, matching the prod path)."""
    findings: list[Finding] = []
    if arc_kind == adapter.install_archive_kind and not replaces_install_analyzer_for(ecosystem):
        findings.extend(await adapter.analyze_install(sub, changed_files=changed))
    analyzer_findings = await asyncio.to_thread(
        _run_analyzers, sub, changed, current_info or {}, prev_info or {},
        norm_to_real or {}, ecosystem=ecosystem, lite=lite,
    )
    findings.extend(analyzer_findings)
    return findings


def _strip_nul(value):
    """Remove NUL (0x00) from strings before they hit Postgres. TEXT and JSONB
    columns reject ``\\u0000``, so a single NUL anywhere in metadata, a finding's
    evidence, a file path, or an LLM field would fail the whole scan's write and
    mark it failed (a package can ship UTF-16 / binary-ish content — or embed NUL
    deliberately — to evade scanning this way). Recurses into dict/list for JSON
    columns. NUL carries no meaning in our text fields, so stripping is safe."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    return value


def _persist_findings(session: Session, scan: Scan, findings: list[Finding]) -> None:
    for f in findings:
        session.add(FindingRow(
            scan_id=scan.id,
            rule_id=f.rule_id, category=f.category, severity=f.severity,
            confidence=f.confidence, file=_strip_nul(f.file or ""), line=f.line,
            evidence=_strip_nul(f.evidence or ""),
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
    """Scoring, persistence, LLM triage, detonation-enqueue — all sync, runs in thread.

    Detonation is enqueued (DetonationQueue) and run asynchronously by
    detonation_worker.py; the scan is finalized here with the static verdict.
    """
    # Some packages ship UTF-16 / binary-ish metadata (e.g. a summary with NUL
    # bytes). Strip NUL up front so neither the scalar columns, the metadata_json
    # audit blob, nor metadata-derived findings fail the Postgres write.
    metadata = _strip_nul(metadata)
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
                path: {"sha256": fi.sha256, "ssdeep": fi.ssdeep, "tlsh": fi.tlsh}
                for path, fi in infos.items()
            }
            all_findings.extend(check_threat_intel(s, intel_batch))

        # For confirmed-malicious (auto-watchlisted) names, carry forward
        # findings on SHA-unchanged files from the most-recent prior scan
        # within the TTL window. The attacker pattern is byte-identical
        # re-publishes; without this, our changed_files optimization would
        # surface only the deltas (3 of 11 findings) and thin the LLM's
        # evidence basis — even though the verdict held via the chain rule.
        try:
            from pkgsentry.watchlist_auto import is_watchlist_auto_only
            if is_watchlist_auto_only(s, ecosystem, name):
                from pkgsentry.finding_reuse import carry_forward_findings
                cur_hashes: dict[str, str] = {}
                for _kind, infos in all_file_hashes:
                    for path, fi in infos.items():
                        cur_hashes[path] = fi.sha256
                carried = carry_forward_findings(
                    s, ecosystem, name, scan.id, cur_hashes,
                    existing_findings=all_findings,
                )
                if carried:
                    all_findings.extend(carried)
                    log.info("findings_carried_forward",
                             ecosystem=ecosystem, pkg=f"{name}=={version}",
                             carried=len(carried))
        except Exception as e:
            log.warning("findings_carry_forward_skipped",
                        ecosystem=ecosystem, name=name, error=str(e))

        rank = _is_watchlist(s, name, ecosystem)
        result = score_and_verdict(all_findings, watchlist_rank=rank)
        scan.verdict = result.verdict
        scan.score = result.score
        scan.alert_tag = result.alert_tag
        scan.finished_at = datetime.now(timezone.utc)

        _apply_metadata(s, ver, metadata, watchlist_rank=rank)
        _persist_findings(s, scan, all_findings)
        _persist_file_hashes(s, scan.id, all_file_hashes)

        # --- Detonation: enqueue for async processing (decoupled from this scan) ---
        is_first_version = prev is None
        det_client = get_detonation_client()
        if (
            ecosystem in _DETONATION_ECOSYSTEMS
            and _detonation_cluster_enabled(det_client)
            and should_detonate(
                verdict=result.verdict,
                score=result.score,
                findings=all_findings,
                watchlist_rank=rank,
                is_new_package=is_first_version,
            )
        ):
            detonation_queue.enqueue(
                s,
                scan_id=scan.id,
                version_id=ver.id,
                ecosystem=ecosystem,
                name=name,
                version=version,
                archive_kind=_PREFERRED_ARCHIVE.get(ecosystem, "sdist"),
                priority=_detonation_priority(verdict=result.verdict, watchlist_rank=rank),
                static_verdict=result.verdict,
            )

        # Capture what the post-commit triage/alert needs, then let THIS
        # transaction close before the LLM HTTP call. Holding a session (its
        # pooled connection + the claimed-row locks) across ~180s of triage
        # latency exhausts the connection pool under a burst of malicious packages
        # and stalls every worker. Clean/suspicious scans finalize here in one
        # transaction; only malicious scans (which trigger triage) defer mark_done.
        scan_id = scan.id
        do_triage = result.verdict == "malicious"
        triage_root = None
        if do_triage:
            _triage_adapter = adapter_registry.get(ecosystem)
            _triage_kind = _triage_adapter.install_archive_kind if _triage_adapter else "sdist"
            for arc in archives:
                if arc.kind == _triage_kind:
                    triage_root = tmp_extract / arc.kind
                    break
            if triage_root is None and archives:
                triage_root = tmp_extract / archives[0].kind
        else:
            mark_done(s, row, token=claim_token)
    # ---- transaction 1 committed; no DB session is held past here ----

    final_verdict = result.verdict
    final_alert_tag = result.alert_tag

    if do_triage:
        # Frozen-sample vault: preserve the malicious archive before the registry
        # yanks it. Disk I/O only — no DB session held.
        if vault.is_enabled() and archives:
            try:
                preferred = _PREFERRED_ARCHIVE.get(ecosystem, "sdist")
                vault_arc = next((a for a in archives if a.kind == preferred), archives[0])
                scored_rules = [f.rule_id for f in all_findings if not _is_shadow_finding(f)]
                vault.archive_to_vault(
                    ecosystem=ecosystem, name=name, version=version,
                    archive_path=Path(vault_arc.path), archive_kind=vault_arc.kind,
                    verdict=result.verdict, score=result.score,
                    expect_rules=scored_rules,
                )
            except Exception as e:
                log.warning("vault_archive_skipped", error=str(e))

        from pkgsentry.llm import triage as llm_triage_mod
        from pkgsentry.notify import discord as discord_notify

        # LLM triage — the blocking HTTP call, run with NO session open.
        tri = None  # None => disabled or crashed (could not adjudicate)
        if llm_triage_mod.is_enabled() and triage_root is not None:
            try:
                log.info("llm_triage_start", rule_verdict=result.verdict,
                         score=result.score, n_findings=len(all_findings))
                tri = llm_triage_mod.triage(
                    pkg_name=name, pkg_version=version,
                    rule_verdict=result.verdict, findings=all_findings,
                    extracted_root=triage_root, ecosystem=ecosystem,
                )
                log.info("llm_triage_done", rule_verdict=result.verdict,
                         llm_verdict=tri.verdict, cost=tri.cost_usd,
                         latency_ms=tri.latency_ms)
            except Exception as e:
                log.warning("llm_triage_skipped", error=str(e))
                tri = None

        # Short transaction: persist LLM fields + verdict override + auto-watchlist.
        with sess.session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan is not None and tri is not None:
                scan.llm_model = tri.model
                scan.llm_verdict = tri.verdict
                scan.llm_confidence = tri.confidence
                scan.llm_reasoning = _strip_nul(tri.reasoning)
                scan.llm_iocs = _strip_nul(tri.iocs)
                scan.llm_agrees_with_rules = tri.agrees_with_rules
                scan.llm_prompt_tokens = tri.prompt_tokens
                scan.llm_completion_tokens = tri.completion_tokens
                scan.llm_cost_usd = tri.cost_usd
                scan.llm_latency_ms = tri.latency_ms
                scan.llm_raw_response = _strip_nul(tri.raw_response)
                if tri.verdict in ("malicious", "suspicious", "benign"):
                    scan.verdict = tri.verdict
                    final_verdict = tri.verdict
            # Auto-watchlist on double-confirmed malicious (rules + LLM agree):
            # the next release of this name is then scanned at high priority.
            if tri is not None and tri.verdict == "malicious":
                try:
                    from pkgsentry import watchlist_auto
                    status = watchlist_auto.add_confirmed_malicious(
                        s, ecosystem, name, scan_id=scan_id,
                    )
                    if status:
                        log.info("watchlist_auto_outcome", ecosystem=ecosystem,
                                 name=name, status=status)
                except Exception as e:
                    log.warning("watchlist_auto_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
                # Sibling-worm defense: watch the whole org scope so a worm's
                # spread to the org's *other* packages is caught within the wave.
                try:
                    from pkgsentry import scope_watchlist
                    sc = scope_watchlist.auto_watch_on_malicious(s, ecosystem, name)
                    if sc:
                        log.info("scope_watchlist_auto_outcome", ecosystem=ecosystem,
                                 name=name, scope=sc)
                except Exception as e:
                    log.warning("scope_watchlist_auto_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
                # Campaign recognition: seed the implicated files' fingerprints so a
                # future package reusing the same/similar payload matches via
                # threat_intel (SHA-256 / ssdeep / TLSH) — even before the LLM.
                try:
                    from pkgsentry import threat_intel_auto
                    seeded = threat_intel_auto.seed_from_scan(s, scan_id, ecosystem, name)
                    if seeded:
                        log.info("threat_intel_autoseed_outcome", ecosystem=ecosystem,
                                 name=name, seeded=seeded)
                except Exception as e:
                    log.warning("threat_intel_autoseed_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
            # Tag llm_unverified when the LLM couldn't clear or confirm.
            if not (tri is not None and tri.verdict in ("benign", "suspicious")):
                if ((tri is None or tri.verdict != "malicious")
                        and scan is not None and not scan.alert_tag):
                    scan.alert_tag = "llm_unverified"
                    final_alert_tag = "llm_unverified"

        # Fail OPEN: alert unless the LLM explicitly cleared it. Sent BEFORE the
        # final mark_done so a crash in this window re-scans (and re-alerts)
        # rather than losing the alert — the outcome this scanner must never have.
        llm_cleared = tri is not None and tri.verdict in ("benign", "suspicious")
        if not llm_cleared and discord_notify.is_enabled():
            if tri is None or tri.verdict != "malicious":
                log.warning("alert_llm_unverified", rule_verdict=result.verdict,
                            score=result.score,
                            llm_verdict=(tri.verdict if tri is not None else "unavailable"))
            if tri is None:
                tri = llm_triage_mod.LLMTriageResult(
                    verdict="unverified", confidence=0.0,
                    reasoning="LLM triage unavailable (disabled or skipped)",
                    iocs=[], agrees_with_rules=None, model="n/a",
                    prompt_tokens=0, completion_tokens=0, cost_usd=0.0,
                    latency_ms=0, raw_response={},
                )
            try:
                from pkgsentry.enrich import downloads as _downloads
                _dl = _downloads.enrich(ecosystem, name)
            except Exception:
                _dl = None
            discord_notify.send_alert(
                pkg_name=name, pkg_version=version, ecosystem=ecosystem,
                rule_verdict=result.verdict, rule_score=result.score,
                n_findings=len(all_findings), triage=tri, findings=all_findings,
                downloads_weekly=_dl,
            )

        # Finalize the queue row now that the alert has been handled.
        with sess.session_scope() as s:
            row = s.get(ScanQueue, queue_id)
            if row is not None:
                mark_done(s, row, token=claim_token)

    final_score = result.score

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
                current_info, norm_to_real, members, lite = await asyncio.to_thread(
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

                t1 = time.monotonic()
                log.info("analyzing", kind=arc.kind)
                analyzer_findings = await run_static_analyzers(
                    sub, ecosystem=ecosystem, adapter=adapter, arc_kind=arc.kind,
                    changed=changed, current_info=current_info, prev_info=prev_info,
                    norm_to_real=norm_to_real, lite=lite,
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
