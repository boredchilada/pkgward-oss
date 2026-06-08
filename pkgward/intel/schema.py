"""Permissive schema validation for intel pack manifests.

The pack format is intentionally loose — missing files are fine, unknown
keys are ignored. This module only enforces the contract that *if* a file
exists, *if* it declares a known field, the field's value type is correct.

Called explicitly by tools/lint_intel_pack.py; not on every startup load.
"""
from __future__ import annotations

import tomllib
from pathlib import Path


class IntelPackError(ValueError):
    pass


_KNOWN_TOML_FILES: dict[str, dict[str, type]] = {
    "thresholds.toml": {"suspicious_min": int, "malicious_min": int, "category_cap": int},
    "scoring_weights.toml": {"low": int, "medium": int, "high": int, "critical": int},
    "behavioral_chains.toml": {},  # chain_ids: list[str], validated below
    "lure_keywords.toml": {},      # [categories] table
    "ioc_whitelist.toml": {},      # benign_domains: list[str]
    "malware_patterns.toml": {},   # [patterns] table
    "gomod_benign_tools.toml": {}, # tools: list[str]
    "detonation/rules_data.toml": {},  # arbitrary lists
    "detonation/noise_baseline.toml": {},
}


def validate(root: Path) -> list[str]:
    """Return list of human-readable warnings/errors; empty list = clean."""
    root = Path(root)
    issues: list[str] = []

    if not root.is_dir():
        return [f"intel pack root does not exist: {root}"]

    manifest = root / "intel_pack.toml"
    if manifest.is_file():
        try:
            with manifest.open("rb") as f:
                tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            issues.append(f"intel_pack.toml: {e}")

    for rel_path, scalar_types in _KNOWN_TOML_FILES.items():
        path = root / rel_path
        if not path.is_file():
            continue
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            issues.append(f"{rel_path}: parse error: {e}")
            continue
        for key, expected_type in scalar_types.items():
            if key in data and not isinstance(data[key], expected_type):
                issues.append(
                    f"{rel_path}: {key!r} expected {expected_type.__name__}, "
                    f"got {type(data[key]).__name__}"
                )

    # behavioral_chains.toml: chain_ids must be list[str] if present
    chains_path = root / "behavioral_chains.toml"
    if chains_path.is_file():
        try:
            with chains_path.open("rb") as f:
                data = tomllib.load(f)
            if "chain_ids" in data:
                v = data["chain_ids"]
                if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                    issues.append("behavioral_chains.toml: chain_ids must be list[str]")
        except tomllib.TOMLDecodeError:
            pass

    yara_dir = root / "yara"
    if yara_dir.is_dir():
        yar_files = list(yara_dir.glob("*.yar")) + list(yara_dir.glob("*.yara"))
        if not yar_files:
            issues.append(f"yara/ exists but contains no .yar / .yara files")

    return issues
