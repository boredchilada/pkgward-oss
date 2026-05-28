"""Intel pack — data-driven detection content (YARA, hashes, prompts, thresholds, keywords).

The engine is open-source. The detection *data* loaded by the analyzers lives
in an "intel pack" — a directory of TOML / JSONL / YARA files. A minimal
baseline pack ships in-tree at `pkgsentry/intel/baseline/`. Operators with
their own tuned threat intel can layer a private overlay via the
`PKGSENTRY_INTEL_PATH` env var.

Resolution at startup:
  1. Load baseline (always).
  2. If PKGSENTRY_INTEL_PATH is set + validates, load overlay.
  3. Merge per IntelPack.merge() — UNION for additive content, REPLACE for scalars.

Use:
    from pkgsentry import intel
    intel.load()                  # call once at startup
    pack = intel.current()        # access merged pack anywhere
    pack.scoring_weights["high"]  # -> 25
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pkgsentry.intel.pack import IntelPack, load_pack
from pkgsentry.logging_setup import get_logger

log = get_logger("intel")

_BASELINE_DIR = Path(__file__).parent / "baseline"
_current: Optional[IntelPack] = None


def baseline_dir() -> Path:
    return _BASELINE_DIR


def load(overlay_path: Optional[Path] = None, *, use_env: bool = True) -> IntelPack:
    """Load baseline + optional overlay, merge, set as the module-level current.

    `overlay_path` overrides the PKGSENTRY_INTEL_PATH env var when provided
    (mainly for tests). Pass `use_env=False` to force a deterministic
    baseline-only load that ignores PKGSENTRY_INTEL_PATH (used by the public
    regression corpus, whose golden expectations are pinned to the baseline pack).
    """
    global _current

    if overlay_path is None and use_env:
        env_path = os.environ.get("PKGSENTRY_INTEL_PATH", "").strip()
        if env_path:
            overlay_path = Path(env_path)

    baseline = load_pack(_BASELINE_DIR, source_label="baseline")

    if overlay_path is not None and overlay_path.exists():
        overlay = load_pack(overlay_path, source_label=str(overlay_path))
        merged = baseline.merge(overlay)
        log.info(
            "intel_loaded",
            source="baseline+overlay",
            overlay=str(overlay_path),
            yara_n=len(merged.yara_dirs),
            hash_seeds_n=len(merged.hash_seeds),
            behavioral_chains_n=len(merged.behavioral_chain_ids),
            ioc_whitelist_n=len(merged.ioc_whitelist),
            lure_categories=sorted(merged.lure_keywords.keys()),
            scoring_weights=dict(merged.scoring_weights),
            thresholds=dict(merged.thresholds),
            det_noise_lists=sorted(merged.detonation_noise.keys()),
            det_rules_lists=sorted(merged.detonation_rules_data.keys()),
        )
        _current = merged
    elif overlay_path is not None:
        log.warning("intel_overlay_missing", path=str(overlay_path))
        _current = baseline
        log.info(
            "intel_loaded",
            source="baseline",
            yara_n=len(baseline.yara_dirs),
            hash_seeds_n=len(baseline.hash_seeds),
        )
    else:
        _current = baseline
        log.info(
            "intel_loaded",
            source="baseline",
            yara_n=len(baseline.yara_dirs),
            hash_seeds_n=len(baseline.hash_seeds),
        )

    return _current


def current() -> IntelPack:
    """Return the merged intel pack. Lazily loads baseline if not yet loaded."""
    if _current is None:
        return load()
    return _current


def reset() -> None:
    """Test-only: clear the module-level singleton."""
    global _current
    _current = None
