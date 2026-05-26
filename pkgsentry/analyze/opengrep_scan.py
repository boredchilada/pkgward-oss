# SPDX-License-Identifier: AGPL-3.0-or-later
"""opengrep static-analysis layer.

Runs the [opengrep](https://github.com/opengrep/opengrep) binary against the
extracted package tree, parses its JSON output, and emits Findings. The rule
content is loaded from the intel pack's `opengrep_dirs` (baseline+overlay
UNION merge — same pattern as `yara_dirs`).

Modes
-----
* OPENGREP_SHADOW=1 (default): findings emit as ``opengrep.shadow_<id>`` and
  are excluded from scoring by ``pkgsentry/detect/score.py``. Findings still
  persist for offline parity comparison against the legacy regex/AST layers.
* OPENGREP_SHADOW=0: findings emit as ``opengrep.<id>`` and enter scoring.
  This mode is only flipped after the soak window proves parity.

Fail-soft on every error path: missing binary, missing rules, subprocess
failure, timeout, malformed JSON — all return ``[]`` and log a warning.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from pkgsentry import intel
from pkgsentry.adapter import Finding
from pkgsentry.logging_setup import get_logger

CATEGORY = "opengrep"

log = get_logger("analyze.opengrep")

# Cached state — recomputed when rule dirs change.
_binary_ok: Optional[bool] = None
_binary_checked_for: str = ""


def _reset_caches_for_tests() -> None:
    """Clear module-level caches. Tests call this between cases."""
    global _binary_ok, _binary_checked_for
    _binary_ok = None
    _binary_checked_for = ""


# ---------------------------------------------------------------------------
# Env-var helpers
# ---------------------------------------------------------------------------


def _enabled() -> bool:
    return os.environ.get("OPENGREP_ENABLED", "1") != "0"


def _shadow_mode() -> bool:
    return os.environ.get("OPENGREP_SHADOW", "1") != "0"


def _timeout_sec() -> int:
    try:
        return max(1, int(os.environ.get("OPENGREP_TIMEOUT_SEC", "60")))
    except ValueError:
        return 60


def _binary_path() -> str:
    return os.environ.get("OPENGREP_BIN", "opengrep")


# Ecosystems whose legacy install-time analyzers are slated for replacement
# by opengrep. When ``replaces_install_analyzer_for(ecosystem)`` is True the
# pipeline skips ``adapter.analyze_install`` for that ecosystem — the
# corresponding opengrep rules are now the authoritative source.
_MIGRATED_INSTALL_ECOSYSTEMS = frozenset({"pypi", "crates"})


def replaces_install_analyzer_for(ecosystem: str) -> bool:
    """Predicate used by pipeline.py to decide whether to skip a legacy
    install-time analyzer. True only when:

    * the opengrep analyzer is enabled,
    * shadow mode is OFF (cutover live),
    * the ecosystem is in the migrated set.

    Shadow mode is the default, so this returns False unless the operator
    has explicitly flipped ``OPENGREP_SHADOW=0``.
    """
    if not _enabled():
        return False
    if _shadow_mode():
        return False
    return ecosystem in _MIGRATED_INSTALL_ECOSYSTEMS


# ---------------------------------------------------------------------------
# Binary probe (cached)
# ---------------------------------------------------------------------------


def _check_binary() -> bool:
    """Probe ``opengrep --version`` once per binary path. Cached.

    Returns True if the binary is callable. On failure, logs a single
    ``opengrep_unavailable`` warning and returns False; all subsequent
    calls hit the cache.
    """
    global _binary_ok, _binary_checked_for
    bin_path = _binary_path()
    if _binary_ok is not None and _binary_checked_for == bin_path:
        return _binary_ok

    _binary_checked_for = bin_path
    # Fast pre-check: shutil.which handles PATH lookups and absolute paths
    # alike, and avoids spawning a subprocess just to print "command not found".
    resolved = shutil.which(bin_path) if "/" not in bin_path and "\\" not in bin_path else bin_path
    if not resolved or not Path(resolved).is_file():
        log.warning("opengrep_unavailable", reason="not_found", bin=bin_path)
        _binary_ok = False
        return False

    try:
        result = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            log.warning(
                "opengrep_unavailable", reason="bad_exit",
                bin=bin_path, returncode=result.returncode,
            )
            _binary_ok = False
            return False
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("opengrep_unavailable", reason=type(e).__name__, bin=bin_path)
        _binary_ok = False
        return False

    _binary_ok = True
    log.info("opengrep_ready", bin=bin_path, version=result.stdout.strip())
    return True


# ---------------------------------------------------------------------------
# Rule dirs
# ---------------------------------------------------------------------------


def _get_rule_dirs() -> list[Path]:
    """Return the merged opengrep rule directories from the current intel pack."""
    pack = intel.current()
    return [d for d in pack.opengrep_dirs if d.is_dir()]


# ---------------------------------------------------------------------------
# Severity / confidence normalization
# ---------------------------------------------------------------------------


_VALID_SEV = {"low", "medium", "high", "critical"}
_VALID_CONF = {"low", "medium", "high"}

# opengrep top-level severity → our scale (used when a rule omits metadata.severity)
_TOP_SEV_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def _normalize_severity(meta: dict, top_level: str) -> str:
    meta_sev = str(meta.get("severity", "")).lower()
    if meta_sev in _VALID_SEV:
        return meta_sev
    mapped = _TOP_SEV_MAP.get(str(top_level).upper())
    if mapped in _VALID_SEV:
        return mapped
    return "medium"


def _normalize_confidence(meta: dict) -> str:
    conf = str(meta.get("confidence", "")).lower()
    return conf if conf in _VALID_CONF else "medium"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_opengrep(
    extracted_root: Path,
    changed_files: set[str] | None = None,
    ecosystem: str = "pypi",
) -> list[Finding]:
    if not _enabled():
        return []
    rule_dirs = _get_rule_dirs()
    if not rule_dirs:
        return []
    if not _check_binary():
        return []

    cmd: list[str] = [_binary_path(), "scan", "--json", "--quiet"]
    for d in rule_dirs:
        cmd.extend(["-f", str(d)])
    cmd.append(str(extracted_root))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout_sec(),
        )
    except subprocess.TimeoutExpired:
        log.warning("opengrep_timeout", timeout_s=_timeout_sec(), ecosystem=ecosystem)
        return []
    except OSError as e:
        log.warning("opengrep_subprocess_error", error=type(e).__name__, ecosystem=ecosystem)
        return []

    # opengrep exits non-zero when it emits parse/internal errors. Treat the
    # whole run as untrusted in that case.
    if result.returncode != 0:
        log.warning(
            "opengrep_bad_exit",
            returncode=result.returncode,
            stderr_head=(result.stderr or "")[:200],
            ecosystem=ecosystem,
        )
        return []

    try:
        payload: dict[str, Any] = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        log.warning("opengrep_malformed_json", ecosystem=ecosystem)
        return []

    shadow = _shadow_mode()
    findings: list[Finding] = []
    for item in payload.get("results", []) or []:
        try:
            f = _result_to_finding(item, extracted_root, shadow=shadow)
        except Exception:
            log.debug("opengrep_result_parse_error", item=item)
            continue
        if f is None:
            continue
        if changed_files is not None and f.file not in changed_files:
            continue
        findings.append(f)

    return findings


def _result_to_finding(
    item: dict[str, Any], extracted_root: Path, *, shadow: bool,
) -> Optional[Finding]:
    check_id = str(item.get("check_id", "")).strip()
    if not check_id:
        return None
    # opengrep returns the rule's `id` as check_id. If the YAML rule lives
    # under a directory, opengrep may prefix the id with the path; take the
    # final component for stability.
    short_id = check_id.split(".")[-1] if "." in check_id else check_id

    raw_path = str(item.get("path", ""))
    try:
        rel = Path(raw_path).resolve().relative_to(extracted_root.resolve()).as_posix()
    except ValueError:
        # Path outside extracted_root — fall back to filename only.
        rel = Path(raw_path).name

    start = item.get("start") or {}
    line: Optional[int] = None
    if isinstance(start.get("line"), int):
        line = int(start["line"])

    extra = item.get("extra") or {}
    metadata = extra.get("metadata") or {}

    severity = _normalize_severity(metadata, extra.get("severity", ""))
    confidence = _normalize_confidence(metadata)

    category_meta = metadata.get("category")
    category = str(category_meta) if category_meta else CATEGORY

    message = str(extra.get("message", "")).strip()
    evidence = message or short_id

    final_id = f"opengrep.{'shadow_' if shadow else ''}{short_id}"

    return Finding(
        rule_id=final_id,
        category=category,
        severity=severity,
        confidence=confidence,
        file=rel,
        line=line,
        evidence=evidence,
    )
