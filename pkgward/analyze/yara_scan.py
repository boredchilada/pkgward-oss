# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from pkgward import intel
from pkgward.adapter import Finding
from pkgward.logging_setup import get_logger
from pkgward.util import capabilities as caps

CATEGORY = "yara"

log = get_logger("analyze.yara")

_compiled_rules = None
_compiled_from: tuple[str, ...] = ()


def _get_rules():
    """Compile YARA rules from every directory the intel pack exposes.

    UNION semantics: baseline `pkgward/intel/baseline/yara/` is always
    included; any overlay directory under `$PKGWARD_INTEL_PATH/yara/`
    is added on top. Rule stems are namespaced with the parent directory
    name to prevent collisions when baseline and overlay both define a
    `python_malware` file.
    """
    global _compiled_rules, _compiled_from
    pack = intel.current()
    dirs = tuple(str(d) for d in pack.yara_dirs)
    if _compiled_rules is not None and dirs == _compiled_from:
        return _compiled_rules

    yara = caps.yara
    if yara is None:
        return None

    rule_files: list[Path] = []
    for yara_dir in pack.yara_dirs:
        if not yara_dir.is_dir():
            continue
        rule_files.extend(yara_dir.glob("*.yar"))
        rule_files.extend(yara_dir.glob("*.yara"))

    if not rule_files:
        return None

    filepaths: dict[str, str] = {}
    for f in rule_files:
        ns = f"{f.parent.name}__{f.stem}" if f.parent.name != "yara" else f.stem
        filepaths[ns] = str(f)

    # Pre-validate each rule file on its own so a single malformed file — most often
    # a typo in an operator's private overlay, the exact place high-fidelity campaign
    # rules are added — doesn't take down the ENTIRE yara layer (layer 8) for the
    # whole process. Bad files are dropped + logged; the rest still compile.
    good: dict[str, str] = {}
    for ns, fp in filepaths.items():
        try:
            yara.compile(filepath=fp, externals={"filename": ""})
            good[ns] = fp
        except yara.Error as e:
            log.warning("yara_rule_file_skipped", file=fp, ns=ns, error=str(e))
    if not good:
        log.warning("yara_no_valid_rule_files", tried=len(filepaths))
        return None

    try:
        _compiled_rules = yara.compile(
            filepaths=good,
            externals={"filename": ""},
        )
        _compiled_from = dirs
    except yara.Error as e:
        log.warning("yara_compile_failed", error=str(e), files=list(good.keys()))
        return None
    if len(good) < len(filepaths):
        log.warning("yara_loaded_partial", loaded=len(good), total=len(filepaths))
    return _compiled_rules


_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".bz2", ".xz", ".tar", ".whl",
    ".pyc", ".pyo",
}

_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


def analyze_yara(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    rules = _get_rules()
    if rules is None:
        return []

    out: list[Finding] = []
    skipped_large = 0

    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        rel = p.relative_to(extracted_root).as_posix()
        if changed_files is not None and rel not in changed_files:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_SIZE:
                skipped_large += 1
                continue
            data = p.read_bytes()
        except OSError:
            continue

        try:
            matches = rules.match(data=data, externals={"filename": rel})
        except Exception:
            continue

        for match in matches:
            meta = match.meta or {}
            severity = meta.get("severity", "medium")
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"
            confidence = meta.get("confidence", "medium")
            if confidence not in ("low", "medium", "high"):
                confidence = "medium"

            matched_strings = []
            try:
                for s in match.strings[:3]:
                    if hasattr(s, "identifier"):
                        matched_strings.append(s.identifier)
                    else:
                        matched_strings.append(str(s[1]) if len(s) > 1 else str(s))
            except Exception:
                pass

            desc = meta.get("description", match.rule)
            out.append(Finding(
                rule_id=f"yara.{match.rule}",
                category=CATEGORY,
                severity=severity,
                confidence=confidence,
                file=rel,
                line=None,
                evidence=f"{desc} [{', '.join(matched_strings)}]" if matched_strings else desc,
            ))

    if skipped_large:
        # Large files (multi-MB bundled/packed installers) are exactly where install
        # malware increasingly hides — surface the skip instead of dropping silently.
        log.info("yara_skipped_large_files", count=skipped_large,
                 max_mb=_MAX_FILE_SIZE // (1024 * 1024))
    return out
