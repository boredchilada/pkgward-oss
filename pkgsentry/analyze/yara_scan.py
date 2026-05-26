# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from pkgsentry import intel
from pkgsentry.adapter import Finding
from pkgsentry.logging_setup import get_logger

CATEGORY = "yara"

log = get_logger("analyze.yara")

_compiled_rules = None
_compiled_from: tuple[str, ...] = ()


def _get_rules():
    """Compile YARA rules from every directory the intel pack exposes.

    UNION semantics: baseline `pkgsentry/intel/baseline/yara/` is always
    included; any overlay directory under `$PKGSENTRY_INTEL_PATH/yara/`
    is added on top. Rule stems are namespaced with the parent directory
    name to prevent collisions when baseline and overlay both define a
    `python_malware` file.
    """
    global _compiled_rules, _compiled_from
    pack = intel.current()
    dirs = tuple(str(d) for d in pack.yara_dirs)
    if _compiled_rules is not None and dirs == _compiled_from:
        return _compiled_rules

    try:
        import yara
    except ImportError:
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

    try:
        _compiled_rules = yara.compile(
            filepaths=filepaths,
            externals={"filename": ""},
        )
        _compiled_from = dirs
    except yara.Error as e:
        log.warning("yara_compile_failed", error=str(e), files=list(filepaths.keys()))
        return None
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

    return out
