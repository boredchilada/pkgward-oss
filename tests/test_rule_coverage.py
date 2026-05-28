# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rule-coverage meta-test.

Guards the corpus against two silent failure modes:

  1. A manifest references a rule_id that no longer exists (a rename/removal in
     the analyzers leaves a stale `expect_rules`/`forbid_rules` entry).
  2. A NEW scored rule ships without any corpus sample — it would go untested.

The canonical rule_id set is enumerated from the source of truth (the analyzer
literals + the loaded baseline intel pack), not from docs. Every static scored
rule must either be pinned in some sample's `expect_rules` or be listed in the
explicit `ALLOW_UNCOVERED` backlog below — so adding a rule forces a conscious
choice: write a sample, or waive it on purpose.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests import corpus_harness as ch

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG = _REPO_ROOT / "pkgsentry"

# Rules that are real but intentionally not (yet) exercised by a public,
# baseline-only synthetic sample. Whittle this down by adding samples. Adding a
# NEW rule_id to an analyzer without either a sample or an entry here fails the
# coverage assertion below — by design.
ALLOW_UNCOVERED = frozenset({
    # Low-signal IOC sub-rules — only meaningful alongside other findings, not
    # verdict-driving on their own, so they appear incidentally rather than pinned.
    "iocs.ipv4",
    "iocs.onion",
    "iocs.base64_blob",
    # Entropy / binary heuristics — need crafted high-entropy / embedded-binary
    # fixtures; deferred to the private corpus.
    "entropy.obfuscated_payload",
    "entropy.high_entropy_script",
    "entropy.suspicious_jump",
    # malware_patterns not yet sampled publicly.
    "malware.telegram_bot_exfil",
    "malware.slack_webhook",
    "malware.pth_import_injection",
    "malware.pyc_bytecode_hidden",
    "malware.env_sensitive_exfil",
    "malware.whitespace_hidden_payload",
    # metadata variants not yet sampled (need prev-version / file-list context).
    "metadata.rapid_release",
    "metadata.maintainer_change",
    "metadata.sdist_wheel_mismatch",
    "metadata.lure_name",
    "metadata.typosquat_separator",
    "metadata.typosquat_prefix",
    "metadata.typosquat_suffix",
    # version_diff variants beyond clean_to_critical.
    "version_diff.new_rules_fired",
    "version_diff.author_changed",
    "version_diff.dependency_spike",
    # crates build.rs variants not yet sampled.
    "crates.build_rs_env_harvest",
    "crates.build_rs_outdir_escape",
    "crates.build_rs_suspicious_include",
    "crates.build_rs_encoded_payload",
    # gomod variants beyond the init net+exec chain.
    "gomod.go_generate",
    "gomod.go_generate_exec",
    "gomod.init_exec_coexist",
    "gomod.init_net_coexist",
    "gomod.init_env_harvest",
    "gomod.cgo_import",
    "gomod.cgo_exec_chain",
    "gomod.unsafe_import",
    "gomod.replace_directive",
    "gomod.replace_local_path",
    "gomod.encoded_payload",
    # npm installer variants beyond the lifecycle net+exec chain.
    "installer.npm_lifecycle_network",
    "installer.npm_lifecycle_subprocess",
    "installer.npm_install_script_network",
    "installer.npm_install_script_net_exec",
    "installer.npm_install_script_decode_exec",
    "installer.npm_install_script_encoded_payload",
    "installer.npm_suspicious_bin",
    # pypi installer variant beyond urlopen_exec_chain / os_system.
    "installer.subprocess_at_install",
})

# Dynamic / detonation rules are covered by tests/detect/test_dynamic_rules.py,
# not by the static corpus.
_DYNAMIC_RULE_IDS = frozenset({
    "dyn_install_exfil", "dyn_reverse_shell", "dyn_proc_inject",
})


def _static_rule_ids() -> set[str]:
    """Scan analyzer source for `rule_id="..."` string literals."""
    out: set[str] = set()
    pat = re.compile(r'rule_id\s*=\s*"([a-zA-Z0-9_.]+)"')
    for base in ("analyze", "ecosystems"):
        for py in (_PKG / base).rglob("*.py"):
            out |= set(pat.findall(py.read_text(encoding="utf-8", errors="ignore")))
    return out


def _opengrep_rule_ids() -> set[str]:
    """`opengrep.<id>` (+ shadow variant) for every baseline opengrep rule id."""
    from pkgsentry import intel
    intel.reset()
    pack = intel.load(use_env=False)
    out: set[str] = set()
    pat = re.compile(r'^\s*-?\s*id:\s*([A-Za-z0-9_.\-]+)', re.MULTILINE)
    for d in getattr(pack, "opengrep_dirs", []) or []:
        for yml in Path(d).rglob("*.y*ml"):
            for rid in pat.findall(yml.read_text(encoding="utf-8", errors="ignore")):
                out.add(f"opengrep.{rid}")
                out.add(f"opengrep.shadow_{rid}")
    return out


def _yara_rule_ids() -> set[str]:
    """`yara.<name>` for every baseline YARA rule."""
    from pkgsentry import intel
    intel.reset()
    pack = intel.load(use_env=False)
    out: set[str] = set()
    pat = re.compile(r'^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)', re.MULTILINE)
    for d in getattr(pack, "yara_dirs", []) or []:
        for ext in ("*.yar", "*.yara"):
            for yf in Path(d).rglob(ext):
                for name in pat.findall(yf.read_text(encoding="utf-8", errors="ignore")):
                    out.add(f"yara.{name}")
    return out


def _known_rule_ids() -> set[str]:
    return (
        _static_rule_ids()
        | _opengrep_rule_ids()
        | _yara_rule_ids()
        | set(_DYNAMIC_RULE_IDS)
    )


def _pinned_rule_ids() -> set[str]:
    pinned: set[str] = set()
    for s in ch.discover_samples():
        pinned |= set(s.expect_rules)
    return pinned


def test_manifest_rules_exist():
    """Every expect_rules / forbid_rules entry must be a real, known rule_id.

    Catches typos and rules renamed/removed out from under a manifest."""
    known = _known_rule_ids()
    bad: dict[str, list[str]] = {}
    for s in ch.discover_samples():
        for rid in set(s.expect_rules) | set(s.forbid_rules):
            if rid not in known:
                bad.setdefault(s.sample_id, []).append(rid)
    assert not bad, f"manifests reference unknown rule_ids (renamed/removed?): {bad}"


def test_allow_uncovered_has_no_stale_entries():
    """ALLOW_UNCOVERED must not list rule_ids that no longer exist, or ones that
    are now actually covered (keep the backlog honest)."""
    static = _static_rule_ids()
    stale = ALLOW_UNCOVERED - static
    assert not stale, f"ALLOW_UNCOVERED references non-existent rule_ids: {sorted(stale)}"
    now_covered = ALLOW_UNCOVERED & _pinned_rule_ids()
    assert not now_covered, (
        f"these are now pinned by a sample — remove from ALLOW_UNCOVERED: {sorted(now_covered)}"
    )


def test_every_static_rule_is_covered_or_waived():
    """Every static scored rule must be pinned by a sample or explicitly waived.

    A new rule_id added to an analyzer fails here until someone adds a sample or
    appends it to ALLOW_UNCOVERED — so detection rules can't ship untested by
    accident."""
    static = _static_rule_ids()
    pinned = _pinned_rule_ids()
    uncovered = static - pinned - ALLOW_UNCOVERED
    assert not uncovered, (
        f"new/uncovered scored rule_ids with no sample and no waiver: {sorted(uncovered)}\n"
        f"Add a corpus sample pinning each, or add it to ALLOW_UNCOVERED."
    )
