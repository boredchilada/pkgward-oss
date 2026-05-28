# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression-corpus harness.

A corpus *sample* is a labeled known-bad or known-good package: a directory of
source files laid out as the *extracted* archive root for its ecosystem, plus a
``manifest.toml`` describing the expected verdict (the core gate) and, optionally,
which scored rules must / must not fire.

Three tiers are auto-discovered:
  - PUBLIC  — synthetic samples shipped in-tree under ``tests/corpus/``. Pinned to
              the baseline intel pack so expectations are deterministic regardless
              of any operator overlay.
  - PRIVATE — loose samples under ``$PKGSENTRY_CORPUS_PATH`` (same layout). Run
              against baseline + the operator's private overlay.
  - VAULT   — frozen *real* catches under ``$PKGSENTRY_VAULT_PATH``: the original
              archive preserved inside a password-protected zip (pw ``infected``)
              + a plaintext ``<stem>.manifest.toml`` sidecar. The harness decrypts,
              extracts the archive, and statically analyzes it — never detonates.

Every sample is run through the SAME static-analysis seam production uses
(``pipeline.run_static_analyzers``) plus metadata / version-diff analyzers when the
manifest supplies the needed context, then scored with ``score_and_verdict``.
"""
from __future__ import annotations

import os
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VAULT_ZIP_PASSWORD = b"infected"  # malware-zoo convention; inert-at-rest only

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PUBLIC_CORPUS = _REPO_ROOT / "tests" / "corpus"
# In-repo private corpus — committed to the private dev repo, excluded from the
# public OSS tarball (see tools/build-oss-tarball.sh). Absent on a public checkout.
_PRIVATE_CORPUS = _REPO_ROOT / "tests" / "corpus_private"
_VALID_ECOSYSTEMS = ("pypi", "crates", "gomod", "npm")


@dataclass
class Sample:
    tier: str                       # public | private | vault
    manifest_path: Path
    ecosystem: str
    name: str
    version: str
    label: str                      # bad | good
    expected_verdict: str           # clean | suspicious | malicious
    expect_rules: list[str] = field(default_factory=list)
    forbid_rules: list[str] = field(default_factory=list)
    watchlist_rank: Optional[int] = None
    metadata: Optional[dict] = None
    prev: Optional[dict] = None
    provenance: str = "synthetic"
    # Exactly one of these is set:
    source_dir: Optional[Path] = None   # loose: dir IS the extracted root
    vault_archive: Optional[Path] = None  # vault: password-zip holding the archive

    @property
    def sample_id(self) -> str:
        return f"{self.tier}:{self.ecosystem}/{self.manifest_path.parent.name}/{self.name}"


def _load_manifest(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _sample_from_manifest(path: Path, tier: str, *, source_dir: Optional[Path] = None,
                          vault_archive: Optional[Path] = None) -> Sample:
    m = _load_manifest(path)
    eco = m["ecosystem"]
    if eco not in _VALID_ECOSYSTEMS:
        raise ValueError(f"{path}: invalid ecosystem {eco!r}")
    label = m.get("label", "bad" if m.get("expected_verdict") != "clean" else "good")
    return Sample(
        tier=tier,
        manifest_path=path,
        ecosystem=eco,
        name=m["name"],
        version=str(m.get("version", "0")),
        label=label,
        expected_verdict=m["expected_verdict"],
        expect_rules=list(m.get("expect_rules", [])),
        forbid_rules=list(m.get("forbid_rules", [])),
        watchlist_rank=m.get("watchlist_rank"),
        metadata=m.get("metadata"),
        prev=m.get("prev"),
        provenance=m.get("provenance", "synthetic"),
        source_dir=source_dir,
        vault_archive=vault_archive,
    )


def _discover_dir(root: Path, tier: str) -> list[Sample]:
    out: list[Sample] = []
    if not root.is_dir():
        return out
    for manifest in sorted(root.rglob("manifest.toml")):
        out.append(_sample_from_manifest(manifest, tier, source_dir=manifest.parent))
    return out


def _discover_vault(root: Path) -> list[Sample]:
    """Vault entries: ``<stem>.zip`` (password-protected, holds the original
    archive) + ``<stem>.manifest.toml`` sidecar."""
    out: list[Sample] = []
    if not root.is_dir():
        return out
    for manifest in sorted(root.rglob("*.manifest.toml")):
        stem = manifest.name[: -len(".manifest.toml")]
        archive_zip = manifest.parent / f"{stem}.zip"
        if not archive_zip.exists():
            continue
        out.append(_sample_from_manifest(manifest, "vault", vault_archive=archive_zip))
    return out


def discover_samples() -> list[Sample]:
    samples = _discover_dir(_PUBLIC_CORPUS, "public")
    # In-repo private samples (present only on the dev checkout).
    samples += _discover_dir(_PRIVATE_CORPUS, "private")
    # External private corpus + vault, pointed to by env vars.
    corpus_path = os.environ.get("PKGSENTRY_CORPUS_PATH", "").strip()
    if corpus_path:
        samples += _discover_dir(Path(corpus_path), "private")
    vault_path = os.environ.get("PKGSENTRY_VAULT_PATH", "").strip()
    if vault_path:
        samples += _discover_vault(Path(vault_path))
    return samples


def materialize(sample: Sample, work_dir: Path) -> Path:
    """Return the extracted package root for analysis.

    Loose samples ARE the extracted root. Vault samples are decrypted from the
    password-zip and the inner archive is safely extracted to match the real
    prod layout for the ecosystem.
    """
    if sample.source_dir is not None:
        return sample.source_dir

    assert sample.vault_archive is not None
    import pkgsentry.ecosystems  # noqa: F401  (populates adapter_registry)
    from pkgsentry.adapter import adapter_registry
    from pkgsentry.util.extract import safe_extract

    inner_dir = work_dir / "inner"
    inner_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(sample.vault_archive) as zf:
        zf.extractall(inner_dir, pwd=VAULT_ZIP_PASSWORD)
    archives = [p for p in inner_dir.iterdir() if p.is_file()]
    if not archives:
        raise FileNotFoundError(f"{sample.vault_archive}: no archive inside vault zip")
    archive = archives[0]
    kind = adapter_registry[sample.ecosystem].install_archive_kind
    extract_root = work_dir / kind
    safe_extract(archive, extract_root)
    return extract_root


def _pin_intel(tier: str) -> None:
    from pkgsentry import intel
    intel.reset()
    if tier == "public":
        intel.load(use_env=False)        # baseline-only, deterministic
    else:
        intel.load(use_env=True)         # baseline + operator overlay


async def run_sample(sample: Sample, work_dir: Path):
    """Run the sample through the real static analyze→score path.

    Returns (ScoreResult, fired_scored_rule_ids)."""
    import pkgsentry.ecosystems  # noqa: F401  (populates adapter_registry)
    from pkgsentry.adapter import adapter_registry
    from pkgsentry.analyze.metadata import MetadataContext, analyze_metadata
    from pkgsentry.analyze.version_diff import PreviousVersion, analyze_version_diff
    from pkgsentry.detect.score import _is_shadow_finding, score_and_verdict
    from pkgsentry.pipeline import run_static_analyzers

    _pin_intel(sample.tier)

    root = materialize(sample, work_dir)
    adapter = adapter_registry[sample.ecosystem]

    findings = await run_static_analyzers(
        root, ecosystem=sample.ecosystem, adapter=adapter,
        arc_kind=adapter.install_archive_kind, changed=None,
    )

    meta_dict: dict = {}
    if sample.metadata is not None:
        md = sample.metadata
        ctx = MetadataContext(
            name=sample.name,
            version=sample.version,
            previous_release_at=md.get("previous_release_at"),
            maintainers_now=list(md.get("maintainers_now", [])),
            maintainers_prev=list(md.get("maintainers_prev", [])),
            watchlist_top_names=list(md.get("watchlist_top_names", [])),
            sdist_files=list(md.get("sdist_files", [])),
            wheel_files=list(md.get("wheel_files", [])),
        )
        findings.extend(analyze_metadata(ctx))
        meta_dict = dict(md.get("current_metadata", {}))

    if sample.prev is not None:
        p = sample.prev
        prev = PreviousVersion(
            version=str(p.get("version", "0")),
            verdict=p.get("verdict", "clean"),
            score=int(p.get("score", 0)),
            rule_ids=set(p.get("rule_ids", [])),
            finding_count=int(p.get("finding_count", 0)),
            author=p.get("author"),
            author_email=p.get("author_email"),
            upload_time=p.get("upload_time"),
            requires_dist=list(p.get("requires_dist", [])),
        )
        findings.extend(analyze_version_diff(findings, meta_dict, prev))

    result = score_and_verdict(findings, watchlist_rank=sample.watchlist_rank)
    fired = {f.rule_id for f in findings if not _is_shadow_finding(f)}
    return result, fired
