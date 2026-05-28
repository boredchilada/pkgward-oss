# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import fnmatch
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pkgsentry import intel
from pkgsentry.adapter import Finding
from pkgsentry.detect.rules import BEHAVIORAL_CHAIN_RULES
from pkgsentry.logging_setup import get_logger
from pkgsentry.util.env import env_chain

log = get_logger("llm.triage")


# Config — env-overridable so the model is swappable without code changes.
DEFAULT_MODEL = env_chain(
    "PKGSENTRY_LLM_MODEL", "PKGWATCH_LLM_MODEL", "PYPI_SCANNER_LLM_MODEL",
    default="z-ai/glm-5.1",
)
DEFAULT_BASE_URL = env_chain(
    "PKGSENTRY_LLM_BASE_URL", "PKGWATCH_LLM_BASE_URL", "PYPI_SCANNER_LLM_BASE_URL",
    default="https://openrouter.ai/api/v1",
)
API_KEY_ENV = "OPENROUTER_API_KEY"
MAX_CODE_BYTES = 32 * 1024  # ~12K tokens, GLM 5.1 handles this fine
LINES_AROUND_FINDING = 20
REQUEST_TIMEOUT = 60.0
# Retry the call+parse when the model returns truncated/invalid JSON. Cap the
# response so the JSON verdict object isn't cut off mid-stream (the usual cause).
MAX_RETRIES = int(env_chain("PKGSENTRY_LLM_MAX_RETRIES", default="2"))
MAX_RESPONSE_TOKENS = int(env_chain("PKGSENTRY_LLM_MAX_RESPONSE_TOKENS", default="5000"))
# Hard ceiling when escalating max_tokens on finish_reason=length retries —
# beyond this we assume the model is just rambling and bail.
MAX_RESPONSE_TOKENS_CEILING = int(env_chain("PKGSENTRY_LLM_MAX_RESPONSE_TOKENS_CEILING", default="8000"))
# Upper bound on files visited by the source-stats recon walk. Large gomod
# monorepos (scanned as pseudo-versions) hold 100K+ files; we only need an
# estimate for the truncation %, not an exact count.
MAX_RECON_FILES = 20000


# --- In-process budget guardrail ----------------------------------------------
# Defense-in-depth against runaway cost during long unattended runs. Not
# persisted — process restart resets. Configure via env vars.
MAX_USD = float(env_chain(
    "PKGSENTRY_LLM_MAX_USD", "PKGWATCH_LLM_MAX_USD", "PYPI_SCANNER_LLM_MAX_USD",
    default="20.0",
))
MAX_CALLS_PER_HOUR = int(env_chain(
    "PKGSENTRY_LLM_MAX_CALLS_PER_HOUR", "PKGWATCH_LLM_MAX_CALLS_PER_HOUR",
    "PYPI_SCANNER_LLM_MAX_CALLS_PER_HOUR",
    default="1000",
))

_budget_lock = threading.Lock()
_spent_usd: float = 0.0
_call_times: "deque[float]" = deque()


def _check_budget() -> Optional[str]:
    """Return None if budget allows another call, otherwise a reason string."""
    now = time.time()
    with _budget_lock:
        if _spent_usd >= MAX_USD:
            return f"max_usd_reached:{_spent_usd:.4f}>={MAX_USD}"
        cutoff = now - 3600
        while _call_times and _call_times[0] < cutoff:
            _call_times.popleft()
        if len(_call_times) >= MAX_CALLS_PER_HOUR:
            return f"max_calls_per_hour_reached:{len(_call_times)}>={MAX_CALLS_PER_HOUR}"
    return None


def _record_call(cost_usd: float) -> None:
    global _spent_usd
    with _budget_lock:
        _spent_usd += cost_usd
        _call_times.append(time.time())


def get_budget_status() -> dict:
    """Snapshot of the in-process LLM budget — for CLI/stats and tests."""
    with _budget_lock:
        return {
            "spent_usd": _spent_usd,
            "max_usd": MAX_USD,
            "calls_last_hour": len(_call_times),
            "max_calls_per_hour": MAX_CALLS_PER_HOUR,
        }


def _reset_budget_for_tests() -> None:
    """Test-only helper — clears the in-process budget counters."""
    global _spent_usd
    with _budget_lock:
        _spent_usd = 0.0
        _call_times.clear()


# --- Ecosystem-specific configuration ----------------------------------------
_ECOSYSTEM_CONFIG = {
    "pypi": {
        "priority_files": ("setup.py", "__init__.py"),
        "prompt_ecosystem": "PyPI",
        "prompt_language": "Python",
        "prompt_source_desc": "Python source code from a third-party PyPI package",
        "prompt_install_time_focus": (
            "setup.py, setup.cfg, pyproject.toml build hooks, "
            "__init__.py top-level statements, conftest.py"
        ),
        "source_exts": ("*.py",),
    },
    "crates": {
        "priority_files": ("build.rs", "Cargo.toml"),
        "prompt_ecosystem": "crates.io",
        "prompt_language": "Rust",
        "prompt_source_desc": "Rust source code from a third-party crate",
        "prompt_install_time_focus": (
            "build.rs, Cargo.toml build/proc-macro deps, "
            "lib.rs top-level + proc-macro expansion"
        ),
        "source_exts": ("*.rs", "*.toml"),
    },
    "gomod": {
        "priority_files": (),
        "prompt_ecosystem": "Go modules",
        "prompt_language": "Go",
        "prompt_source_desc": "Go source code from a third-party module",
        "prompt_install_time_focus": (
            "//go:generate directives, init() bodies, CGO blocks, "
            "replace/unsafe usage, top-level var initializers"
        ),
        "source_exts": ("*.go",),
    },
    "npm": {
        "priority_files": ("package.json",),
        "prompt_ecosystem": "npm",
        "prompt_language": "JavaScript",
        "prompt_source_desc": "JavaScript/TypeScript source from a third-party npm package",
        "prompt_install_time_focus": (
            "package.json lifecycle scripts (preinstall/install/postinstall/prepare), "
            "the bin entry and referenced install scripts, and top-level module code that "
            "runs on require()"
        ),
        "source_exts": ("*.js", "*.mjs", "*.cjs", "*.ts"),
    },
}

_DEFAULT_ECOSYSTEM_CONFIG = {
    "priority_files": (),
    "prompt_ecosystem": "package registry",
    "prompt_language": "",
    "prompt_source_desc": "source code from a third-party package",
    "prompt_install_time_focus": (
        "any code that runs at install, build, or import time "
        "(as opposed to code that only runs when a consumer explicitly calls it)"
    ),
    "source_exts": ("*.py",),
}


@dataclass
class LLMTriageResult:
    verdict: str             # malicious|suspicious|benign|error|skipped
    confidence: float
    reasoning: str
    iocs: list[dict]         # [{"type":"url","value":"..."}], post-validated against source
    agrees_with_rules: Optional[bool]
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_ms: int
    raw_response: dict


def is_enabled() -> bool:
    return bool(os.environ.get(API_KEY_ENV))


# .pth files often chain statements on one line, e.g.
#   "import sys, sysconfig; sys.path.insert(...); import pkg._auto"
# so match every `import X` regardless of line position.
_PTH_IMPORT_RE = re.compile(r"(?:^|[;\s])import\s+([\w][\w.]*)")


def _safe_rglob(root: Path, pattern: str, *, limit: Optional[int] = None):
    """Recursively yield files under `root` whose name matches `pattern`,
    tolerant of the extraction tree changing under the walk.

    The per-scan temp dir can be torn down while triage is still walking a
    large tree, so `pathlib.rglob`'s directory scan can raise FileNotFoundError
    out of the generator and abort the whole triage (observed on giant gomod
    monorepos). `os.walk` skips vanished/unreadable directories via `onerror`
    and does not follow symlinks, so a dangling symlinked dir can't crash it.
    `limit` caps how many matching files are yielded so we never crawl an
    entire monorepo when an estimate suffices. Mirrors `Path.rglob`: a
    multi-component pattern (e.g. "mod/gen.go") matches on the path tail.
    """
    pat_parts = pattern.split("/")
    n = 0
    for dirpath, _dirs, files in os.walk(root, onerror=lambda _e: None):
        for fn in files:
            full = Path(dirpath) / fn
            rel_parts = full.relative_to(root).parts
            if len(pat_parts) <= len(rel_parts) and all(
                fnmatch.fnmatch(seg, pp)
                for seg, pp in zip(rel_parts[-len(pat_parts):], pat_parts)
            ):
                yield full
                n += 1
                if limit is not None and n >= limit:
                    return


def _resolve_pth_module(extracted_root: Path, dotted: str) -> Optional[Path]:
    """Map a dotted module name to a .py file inside the extracted tree.

    Tries <root>/<a>/<b>.py and <root>/<a>/<b>/__init__.py for the given
    dotted path, falling back to any matching file under rglob.
    """
    parts = dotted.split(".")
    direct = extracted_root / Path(*parts).with_suffix(".py")
    if direct.is_file():
        return direct
    pkg_init = extracted_root / Path(*parts) / "__init__.py"
    if pkg_init.is_file():
        return pkg_init
    # The sdist is usually wrapped in a top-level <pkgname>-<ver>/ directory,
    # so the dotted path won't anchor at root. Search by basename.
    leaf = parts[-1] + ".py"
    if len(parts) > 1:
        parent_name = parts[-2]
        for cand in _safe_rglob(extracted_root, leaf):
            if cand.is_file() and cand.parent.name == parent_name:
                return cand
    for cand in _safe_rglob(extracted_root, leaf):
        if cand.is_file():
            return cand
    return None


def _pth_companion_files(extracted_root: Path) -> list[Path]:
    """For every .pth file in the tree, return both the .pth and any modules
    it imports — these are install-time-equivalent because .pth files execute
    at every Python interpreter startup once the package is installed."""
    out: list[Path] = []
    for pth in _safe_rglob(extracted_root, "*.pth"):
        if not pth.is_file():
            continue
        out.append(pth)
        try:
            content = pth.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _PTH_IMPORT_RE.finditer(content):
            mod = _resolve_pth_module(extracted_root, m.group(1))
            if mod is not None and mod not in out:
                out.append(mod)
    return out


def _gather_source(
    extracted_root: Path, findings: list[Finding], *, ecosystem: str = "pypi",
) -> str:
    """Pick the most-relevant code regions around each finding.
    Caps total bytes at MAX_CODE_BYTES."""
    eco_cfg = _ECOSYSTEM_CONFIG.get(ecosystem, _DEFAULT_ECOSYSTEM_CONFIG)
    snippets: list[str] = []
    total = 0
    seen: set[str] = set()

    def _include(p: Path) -> bool:
        nonlocal total
        rel = str(p.relative_to(extracted_root))
        if rel in seen:
            return True
        seen.add(rel)
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return True
        block = f"--- FILE: {rel} ---\n{src}\n"
        if total + len(block) > MAX_CODE_BYTES:
            remaining = MAX_CODE_BYTES - total
            if remaining > 200:
                block = block[:remaining] + "\n... [truncated] ...\n"
            else:
                return False
        snippets.append(block)
        total += len(block)
        return total < MAX_CODE_BYTES

    # .pth files + the modules they import. .pth executes at every interpreter
    # startup, so its companion module is an install-time persistence vector
    # that the LLM cannot evaluate without seeing the imported module body.
    if ecosystem == "pypi":
        for companion in _pth_companion_files(extracted_root):
            if not _include(companion):
                break

    # First, the actual install/import entry files (most often malicious).
    priority_names = eco_cfg["priority_files"]
    for priority_name in priority_names:
        if total >= MAX_CODE_BYTES:
            break
        for p in _safe_rglob(extracted_root, priority_name):
            rel = str(p.relative_to(extracted_root))
            if rel in seen:
                continue
            seen.add(rel)
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            block = f"--- FILE: {rel} ---\n{src}\n"
            if total + len(block) > MAX_CODE_BYTES:
                remaining = MAX_CODE_BYTES - total
                if remaining > 200:
                    block = block[:remaining] + "\n... [truncated] ...\n"
                else:
                    break
            snippets.append(block)
            total += len(block)
            if total >= MAX_CODE_BYTES:
                break
        if total >= MAX_CODE_BYTES:
            break
    # File-level findings (a file is flagged but with no specific line, e.g. gomod
    # init()/cgo chains aggregate all init bodies) — include the whole file so the
    # model can see the flagged code instead of nothing.
    if total < MAX_CODE_BYTES:
        for f in findings:
            if total >= MAX_CODE_BYTES:
                break
            if not f.file or f.line is not None:
                continue
            cand = extracted_root / f.file
            if not cand.is_file():
                m = list(_safe_rglob(extracted_root, Path(f.file).name))
                cand = m[0] if m else None
            if cand is not None and cand.is_file() and not _include(cand):
                break

    # Then any other files with line-anchored findings, ±LINES_AROUND_FINDING.
    if total < MAX_CODE_BYTES:
        by_file: dict[str, set[int]] = {}
        for f in findings:
            if not f.file or f.line is None:
                continue
            by_file.setdefault(f.file, set()).add(f.line)
        for fname, lines in by_file.items():
            if total >= MAX_CODE_BYTES:
                break
            matches = list(_safe_rglob(extracted_root, fname))
            if not matches:
                continue
            p = matches[0]
            rel = str(p.relative_to(extracted_root))
            if rel in seen:
                continue
            seen.add(rel)
            try:
                src_lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            ranges = sorted(
                (max(1, ln - LINES_AROUND_FINDING), min(len(src_lines), ln + LINES_AROUND_FINDING))
                for ln in lines
            )
            block_lines: list[str] = [f"--- FILE: {rel} (regions around findings) ---"]
            last_end = 0
            for start, end in ranges:
                if start > last_end + 1:
                    block_lines.append("... [skip] ...")
                for i in range(start, end + 1):
                    block_lines.append(f"{i:>5}: {src_lines[i-1]}")
                last_end = max(last_end, end)
            block = "\n".join(block_lines) + "\n"
            if total + len(block) > MAX_CODE_BYTES:
                break
            snippets.append(block)
            total += len(block)
    return "\n".join(snippets) if snippets else "(no source extracted)"


def _build_messages(
    pkg_name: str, pkg_version: str, findings: list[Finding], source: str,
    *, ecosystem: str = "pypi",
    source_files_total: int = 0, truncation_pct: int = 0,
) -> tuple[list[dict], str]:
    """Returns (messages, delimiter) — delimiter is the random token wrapping
    untrusted code (Spotlighting pattern).

    The system prompt template and the truncation-warning insert are loaded
    from the intel pack (`prompts/triage_system.txt` +
    `prompts/truncation_warning.txt`). Ecosystem-specific framing
    (`eco_name`, `source_desc`) comes from `_ECOSYSTEM_CONFIG` in code —
    those are product behaviour, not tuning data.
    """
    eco_cfg = _ECOSYSTEM_CONFIG.get(ecosystem, _DEFAULT_ECOSYSTEM_CONFIG)
    eco_name = eco_cfg["prompt_ecosystem"]
    source_desc = eco_cfg["prompt_source_desc"]

    delim = secrets.token_hex(8)
    findings_json = json.dumps([
        {
            "rule_id": f.rule_id, "severity": f.severity, "confidence": f.confidence,
            "file": f.file, "line": f.line, "evidence": f.evidence[:200],
        }
        for f in findings[:50]
    ], indent=2)

    pack = intel.current()
    truncation_warning = ""
    if truncation_pct >= 50:
        warning_template = pack.prompts.get("truncation_warning", "")
        if warning_template:
            truncation_warning = warning_template.format(
                visible_pct=100 - truncation_pct,
                source_files_total=source_files_total,
            )

    system_template = pack.prompts.get("triage_system", "")
    if not system_template:
        raise RuntimeError(
            "intel pack does not provide a triage_system prompt; "
            "ensure pkgsentry/intel/baseline/prompts/triage_system.txt exists "
            "or set PKGSENTRY_INTEL_PATH to a pack that provides one."
        )
    # The template uses str.format-style {eco_name}/{source_desc}/{delim}/
    # {truncation_warning} placeholders. JSON braces in the template are
    # escaped as {{ / }} per str.format convention.
    install_time_focus = eco_cfg.get(
        "prompt_install_time_focus",
        _DEFAULT_ECOSYSTEM_CONFIG["prompt_install_time_focus"],
    )
    system = system_template.format(
        eco_name=eco_name,
        source_desc=source_desc,
        delim=delim,
        truncation_warning=truncation_warning,
        install_time_focus=install_time_focus,
    )

    user = f"""Package: {pkg_name}=={pkg_version}

Rule findings:
{findings_json}

<<<{delim}>>>
{source}
<<<{delim}>>>"""

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], delim


_IOC_TYPES = {"url", "ip", "domain", "hash", "email", "path"}


def _validate_iocs(claimed: list, source: str) -> list[dict]:
    """Drop any IOC the LLM returned that does NOT appear verbatim in the source.
    Models hallucinate IOCs; this is the post-validation step."""
    out: list[dict] = []
    if not isinstance(claimed, list):
        return out
    for entry in claimed:
        if not isinstance(entry, dict):
            continue
        t = entry.get("type")
        v = entry.get("value")
        if not isinstance(t, str) or not isinstance(v, str):
            continue
        if t not in _IOC_TYPES:
            continue
        if v in source:
            out.append({"type": t, "value": v})
    return out


def _enforce_no_downgrade(
    llm_verdict: str, rule_verdict: str, findings: list[Finding],
    llm_confidence: float = 0.0,
) -> str:
    """Behavioral-chain rule fires => verdict stays malicious UNLESS the LLM
    explicitly disagrees with high confidence (>= 0.80).  The LLM exists to
    catch false positives from pattern-matching rules; overriding it defeats
    its purpose.
    """
    if rule_verdict == "malicious":
        has_chain = any(f.rule_id in BEHAVIORAL_CHAIN_RULES for f in findings)
        if has_chain and llm_verdict in ("benign", "suspicious") and llm_confidence >= 0.80:
            log.warning(
                "llm_overrides_chain_rule",
                llm_verdict=llm_verdict, llm_confidence=llm_confidence,
                chain_rules=[f.rule_id for f in findings if f.rule_id in BEHAVIORAL_CHAIN_RULES],
            )
            return llm_verdict
        if has_chain:
            return "malicious"
    return llm_verdict


def triage(
    *, pkg_name: str, pkg_version: str, rule_verdict: str,
    findings: list[Finding], extracted_root: Path,
    model: str = DEFAULT_MODEL, ecosystem: str = "pypi",
) -> LLMTriageResult:
    """Run LLM triage. Raises RuntimeError if API key missing — callers should
    check is_enabled() first."""
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"{API_KEY_ENV} not set")

    blocked = _check_budget()
    if blocked:
        log.warning("llm_budget_blocked", reason=blocked)
        return LLMTriageResult(
            verdict="skipped", confidence=0.0, reasoning=f"budget: {blocked}",
            iocs=[], agrees_with_rules=None, model=model,
            prompt_tokens=0, completion_tokens=0, cost_usd=0.0,
            latency_ms=0, raw_response={"skipped": blocked},
        )

    # Late import so the dep is optional at import time.
    from openai import OpenAI

    client = OpenAI(
        base_url=DEFAULT_BASE_URL,
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "https://github.com/local/pkgsentry",
            "X-Title": "pkgsentry",
        },
        timeout=REQUEST_TIMEOUT,
    )

    source = _gather_source(extracted_root, findings, ecosystem=ecosystem)
    # Compute truncation stats for the LLM prompt
    eco_cfg = _ECOSYSTEM_CONFIG.get(ecosystem, _DEFAULT_ECOSYSTEM_CONFIG)
    _src_exts = eco_cfg.get("source_exts", ("*.py",))
    source_files_total = 0
    source_bytes_total = 0
    for ext in _src_exts:
        for p in _safe_rglob(extracted_root, ext, limit=MAX_RECON_FILES):
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            source_files_total += 1
            if sz < 10 * 1024 * 1024:
                source_bytes_total += sz
    truncation_pct = max(0, 100 - int(len(source) / max(source_bytes_total, 1) * 100))
    if source == "(no source extracted)" and source_files_total > 0:
        log.warning(
            "llm_triage_no_source",
            ecosystem=ecosystem, pkg=f"{pkg_name}=={pkg_version}",
            source_files_total=source_files_total,
            findings_with_file=sum(1 for f in findings if f.file),
        )
    messages, _delim = _build_messages(
        pkg_name, pkg_version, findings, source, ecosystem=ecosystem,
        source_files_total=source_files_total, truncation_pct=truncation_pct,
    )

    # Retry the call+parse: the model occasionally returns truncated/invalid
    # JSON (often finish_reason=length), which previously errored the whole
    # triage and — because the alert path requires a clean LLM verdict — let a
    # real malicious package pass un-adjudicated and un-alerted. Cost/tokens
    # accumulate across attempts.
    #
    # On finish_reason=length we escalate `max_tokens` for the next attempt
    # (1.5×, capped at MAX_RESPONSE_TOKENS_CEILING). Retrying with the same cap
    # against the same prompt just burns cost for guaranteed-identical
    # truncation — observed 3x4500-tok failures on finding-heavy packages.
    started = time.monotonic()
    total_cost = 0.0
    total_prompt = 0
    total_completion = 0
    last_raw: dict = {}
    parsed: Optional[dict] = None
    last_err = ""
    current_max_tokens = MAX_RESPONSE_TOKENS

    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=current_max_tokens,
                extra_body={"usage": {"include": True}},
            )
        except Exception as e:
            last_err = f"LLM call failed: {e}"
            log.warning("llm_triage_retry", attempt=attempt + 1, attempts=MAX_RETRIES + 1,
                        reason="call_failed", error=str(e))
            continue

        last_raw = resp.model_dump() if hasattr(resp, "model_dump") else resp.dict()
        choice = (last_raw.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content", "")
        finish_reason = choice.get("finish_reason")
        usage = last_raw.get("usage") or {}
        total_prompt += usage.get("prompt_tokens", 0) or 0
        total_completion += usage.get("completion_tokens", 0) or 0
        total_cost += float(usage.get("cost") or 0.0)

        cleaned = (content or "").strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
        try:
            candidate = json.loads(cleaned)
        except json.JSONDecodeError:
            last_err = "invalid JSON from model"
            log.warning("llm_triage_retry", attempt=attempt + 1, attempts=MAX_RETRIES + 1,
                        reason="invalid_json", finish_reason=finish_reason,
                        max_tokens=current_max_tokens,
                        content=(content or "")[:500])
            if finish_reason == "length" and current_max_tokens < MAX_RESPONSE_TOKENS_CEILING:
                current_max_tokens = min(int(current_max_tokens * 1.5), MAX_RESPONSE_TOKENS_CEILING)
            continue

        cand_verdict = str(candidate.get("verdict", "")).lower()
        if cand_verdict not in {"malicious", "suspicious", "benign"}:
            last_err = f"invalid verdict: {cand_verdict!r}"
            log.warning("llm_triage_retry", attempt=attempt + 1, attempts=MAX_RETRIES + 1,
                        reason="invalid_verdict", verdict=cand_verdict, finish_reason=finish_reason)
            continue

        parsed = candidate
        break

    latency_ms = int((time.monotonic() - started) * 1000)
    _record_call(total_cost)

    if parsed is None:
        log.warning("llm_triage_error", pkg=f"{pkg_name}=={pkg_version}",
                    attempts=MAX_RETRIES + 1, error=last_err,
                    content=str((last_raw.get("choices") or [{}])[0].get("message", {}).get("content", ""))[:500])
        return LLMTriageResult(
            verdict="error", confidence=0.0, reasoning=last_err or "LLM triage failed",
            iocs=[], agrees_with_rules=None, model=model,
            prompt_tokens=total_prompt, completion_tokens=total_completion,
            cost_usd=total_cost, latency_ms=latency_ms,
            raw_response=last_raw or {"error": last_err},
        )

    llm_verdict = str(parsed.get("verdict", "")).lower()
    llm_confidence = float(parsed.get("confidence", 0.0) or 0.0)
    final_verdict = _enforce_no_downgrade(llm_verdict, rule_verdict, findings, llm_confidence)

    return LLMTriageResult(
        verdict=final_verdict,
        confidence=llm_confidence,
        reasoning=str(parsed.get("reasoning", ""))[:2000],
        iocs=_validate_iocs(parsed.get("iocs", []), source),
        agrees_with_rules=bool(parsed["agrees_with_rules"]) if isinstance(parsed.get("agrees_with_rules"), (bool, int)) else (parsed.get("agrees_with_rules") == "true" if isinstance(parsed.get("agrees_with_rules"), str) else None),
        model=model,
        prompt_tokens=total_prompt,
        completion_tokens=total_completion,
        cost_usd=total_cost,
        latency_ms=latency_ms,
        raw_response=last_raw,
    )
