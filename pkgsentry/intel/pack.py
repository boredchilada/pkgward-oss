"""IntelPack dataclass + load + merge logic.

A pack is a directory laid out like:

    intel_pack.toml                 # manifest (name, version, extends)
    yara/*.yar                      # YARA rule files
    hashes/known_malicious.jsonl    # one threat-intel hash per line
    prompts/triage_system.txt       # LLM prompt text (one file per slot)
    prompts/truncation_warning.txt
    thresholds.toml                 # suspicious_min, malicious_min, category_cap
    scoring_weights.toml            # severity points
    behavioral_chains.toml          # chain_ids = [...]
    lure_keywords.toml              # [categories] crypto=[...] security_theater=[...]
    ioc_whitelist.toml              # benign_domains = [...]
    malware_patterns.toml           # [patterns] webhook=[...] pth_injection=[...]
    gomod_benign_tools.toml         # tools = [...]
    detonation/rules_data.toml      # sensitive_path_prefixes, sensitive_env_prefixes, shell_binaries
    detonation/noise_baseline.toml  # filter rules

Any file is optional — missing files leave the corresponding IntelPack field
empty (or whatever the previous merge layer set). The schema is permissive
on read; analyzers fall back to safe defaults if a field is empty.
"""
from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class IntelPack:
    source: str = "unset"

    yara_dirs: list[Path] = field(default_factory=list)
    opengrep_dirs: list[Path] = field(default_factory=list)
    hash_seeds: list[dict[str, Any]] = field(default_factory=list)
    prompts: dict[str, str] = field(default_factory=dict)

    thresholds: dict[str, int] = field(default_factory=dict)
    scoring_weights: dict[str, int] = field(default_factory=dict)

    behavioral_chain_ids: set[str] = field(default_factory=set)
    lure_keywords: dict[str, list[str]] = field(default_factory=dict)
    ioc_whitelist: set[bytes] = field(default_factory=set)
    malware_pattern_strings: dict[str, list[str]] = field(default_factory=dict)
    gomod_benign_tools: list[str] = field(default_factory=list)

    detonation_rules_data: dict[str, list[str]] = field(default_factory=dict)
    detonation_noise: dict[str, list[str]] = field(default_factory=dict)

    def merge(self, overlay: "IntelPack") -> "IntelPack":
        """Per-field merge. UNION for additive content, REPLACE for scalars.

        See docs/intel-pack.md for the merge table.
        """
        merged_yara = list(self.yara_dirs)
        for d in overlay.yara_dirs:
            if d not in merged_yara:
                merged_yara.append(d)

        merged_opengrep = list(self.opengrep_dirs)
        for d in overlay.opengrep_dirs:
            if d not in merged_opengrep:
                merged_opengrep.append(d)

        seen_sha = {h.get("sha256") for h in self.hash_seeds if h.get("sha256")}
        merged_hashes = list(self.hash_seeds)
        for h in overlay.hash_seeds:
            sha = h.get("sha256")
            if sha and sha in seen_sha:
                continue
            if sha:
                seen_sha.add(sha)
            merged_hashes.append(h)

        merged_prompts = dict(self.prompts)
        for k, v in overlay.prompts.items():
            if v:
                merged_prompts[k] = v

        merged_thresholds = dict(self.thresholds)
        merged_thresholds.update(overlay.thresholds)

        merged_weights = dict(self.scoring_weights)
        merged_weights.update(overlay.scoring_weights)

        merged_chains = self.behavioral_chain_ids | overlay.behavioral_chain_ids

        merged_lure: dict[str, list[str]] = {}
        for cat, kws in self.lure_keywords.items():
            merged_lure[cat] = list(kws)
        for cat, kws in overlay.lure_keywords.items():
            existing = merged_lure.setdefault(cat, [])
            for kw in kws:
                if kw not in existing:
                    existing.append(kw)

        merged_iocs = self.ioc_whitelist | overlay.ioc_whitelist

        merged_malware: dict[str, list[str]] = {}
        for cat, pats in self.malware_pattern_strings.items():
            merged_malware[cat] = list(pats)
        for cat, pats in overlay.malware_pattern_strings.items():
            existing = merged_malware.setdefault(cat, [])
            for p in pats:
                if p not in existing:
                    existing.append(p)

        merged_gomod = list(self.gomod_benign_tools)
        for t in overlay.gomod_benign_tools:
            if t not in merged_gomod:
                merged_gomod.append(t)

        merged_det_rules: dict[str, list[str]] = {}
        for k, lst in self.detonation_rules_data.items():
            merged_det_rules[k] = list(lst)
        for k, lst in overlay.detonation_rules_data.items():
            existing = merged_det_rules.setdefault(k, [])
            for item in lst:
                if item not in existing:
                    existing.append(item)

        merged_det_noise: dict[str, list[str]] = {}
        for k, lst in self.detonation_noise.items():
            merged_det_noise[k] = list(lst)
        for k, lst in overlay.detonation_noise.items():
            existing = merged_det_noise.setdefault(k, [])
            for item in lst:
                if item not in existing:
                    existing.append(item)

        return IntelPack(
            source=f"{self.source}+{overlay.source}",
            yara_dirs=merged_yara,
            opengrep_dirs=merged_opengrep,
            hash_seeds=merged_hashes,
            prompts=merged_prompts,
            thresholds=merged_thresholds,
            scoring_weights=merged_weights,
            behavioral_chain_ids=merged_chains,
            lure_keywords=merged_lure,
            ioc_whitelist=merged_iocs,
            malware_pattern_strings=merged_malware,
            gomod_benign_tools=merged_gomod,
            detonation_rules_data=merged_det_rules,
            detonation_noise=merged_det_noise,
        )


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def _load_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def load_pack(root: Path, *, source_label: Optional[str] = None) -> IntelPack:
    """Load a single pack (no merging) from a directory."""
    root = Path(root)
    label = source_label or root.name

    yara_dirs: list[Path] = []
    yara_root = root / "yara"
    if yara_root.is_dir():
        yara_dirs.append(yara_root)

    opengrep_dirs: list[Path] = []
    opengrep_root = root / "opengrep"
    if opengrep_root.is_dir():
        opengrep_dirs.append(opengrep_root)

    hash_seeds = _load_jsonl(root / "hashes" / "known_malicious.jsonl")

    prompts: dict[str, str] = {}
    prompts_dir = root / "prompts"
    if prompts_dir.is_dir():
        for p in prompts_dir.glob("*.txt"):
            prompts[p.stem] = _load_text(p)

    thresholds_raw = _load_toml(root / "thresholds.toml")
    thresholds = {k: int(v) for k, v in thresholds_raw.items() if isinstance(v, (int, float))}

    scoring_raw = _load_toml(root / "scoring_weights.toml")
    scoring_weights = {k: int(v) for k, v in scoring_raw.items() if isinstance(v, (int, float))}

    chains_raw = _load_toml(root / "behavioral_chains.toml")
    behavioral_chain_ids: set[str] = set(chains_raw.get("chain_ids", []) or [])

    lure_raw = _load_toml(root / "lure_keywords.toml")
    lure_keywords: dict[str, list[str]] = {}
    for cat, kws in (lure_raw.get("categories") or {}).items():
        if isinstance(kws, list):
            lure_keywords[cat] = [str(k) for k in kws]

    ioc_raw = _load_toml(root / "ioc_whitelist.toml")
    ioc_domains_list = ioc_raw.get("benign_domains") or []
    ioc_whitelist: set[bytes] = {str(d).encode("utf-8") for d in ioc_domains_list if d}

    malware_raw = _load_toml(root / "malware_patterns.toml")
    malware_pattern_strings: dict[str, list[str]] = {}
    for cat, pats in (malware_raw.get("patterns") or {}).items():
        if isinstance(pats, list):
            malware_pattern_strings[cat] = [str(p) for p in pats]

    gomod_raw = _load_toml(root / "gomod_benign_tools.toml")
    gomod_benign_tools = [str(t) for t in (gomod_raw.get("tools") or [])]

    det_rules_raw = _load_toml(root / "detonation" / "rules_data.toml")
    detonation_rules_data: dict[str, list[str]] = {}
    for k, v in det_rules_raw.items():
        if isinstance(v, list):
            detonation_rules_data[k] = [str(x) for x in v]

    det_noise_raw = _load_toml(root / "detonation" / "noise_baseline.toml")
    detonation_noise: dict[str, list[str]] = {}
    for k, v in det_noise_raw.items():
        if isinstance(v, list):
            detonation_noise[k] = [str(x) for x in v]

    return IntelPack(
        source=label,
        yara_dirs=yara_dirs,
        opengrep_dirs=opengrep_dirs,
        hash_seeds=hash_seeds,
        prompts=prompts,
        thresholds=thresholds,
        scoring_weights=scoring_weights,
        behavioral_chain_ids=behavioral_chain_ids,
        lure_keywords=lure_keywords,
        ioc_whitelist=ioc_whitelist,
        malware_pattern_strings=malware_pattern_strings,
        gomod_benign_tools=gomod_benign_tools,
        detonation_rules_data=detonation_rules_data,
        detonation_noise=detonation_noise,
    )
