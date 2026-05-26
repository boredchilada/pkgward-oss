# SPDX-License-Identifier: AGPL-3.0-or-later
"""Analyze package.json lifecycle scripts for supply-chain attack patterns.

npm runs ``preinstall``/``install``/``postinstall`` (and ``prepare`` for local
installs) automatically on ``npm install`` — the JavaScript equivalent of
PyPI's setup.py and Rust's build.rs. ``postinstall`` is the most-abused vector.

This analyzer parses the *root* package.json (never bundled ``node_modules``
manifests), inspects the lifecycle script command strings, and follows local
script files they invoke (e.g. ``node scripts/postinstall.js``) to scan the JS.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Optional

from pkgsentry.adapter import Finding
from pkgsentry import intel

CATEGORY = "installer"

# Lifecycle scripts that execute automatically on a consumer's `npm install`.
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# --- Shell-command (script string) patterns ---

# Network fetchers commonly chained in install scripts.
_SHELL_NET = re.compile(
    r"\b(?:curl|wget|fetch|nc|ncat|certutil|bitsadmin|Invoke-WebRequest|iwr|"
    r"scp|rsync)\b|https?://|ftp://",
    re.IGNORECASE,
)

# Shell/interpreter execution and code-eval entry points.
_SHELL_EXEC = re.compile(
    r"\b(?:sh|bash|zsh|cmd|powershell|pwsh)\b\s+-\w*c|"
    r"\beval\b|\bexec\b|"
    r"\bnode\b\s+-e|\bpython3?\b\s+-c|\bperl\b\s+-e|\bruby\b\s+-e",
    re.IGNORECASE,
)

# base64/hex decode-and-run shapes inside a shell command.
_SHELL_DECODE = re.compile(
    r"base64\s+(?:-d|--decode)|\batob\b|\bxxd\b\s+-r|"
    r"Buffer\.from\([^)]*['\"]base64['\"]",
    re.IGNORECASE,
)

# --- JS source patterns (for followed script files) ---

_JS_NET = re.compile(
    r"require\(\s*['\"](?:https?|net|dns|tls|dgram)['\"]\s*\)|"
    r"\b(?:fetch|axios|node-fetch|got|undici|superagent)\b|"
    r"\bhttps?\.(?:get|request)\b|\bXMLHttpRequest\b",
    re.IGNORECASE,
)

_JS_EXEC = re.compile(
    r"require\(\s*['\"]child_process['\"]\s*\)|"
    r"\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|process\.binding\s*\(",
)

_JS_DECODE = re.compile(
    r"Buffer\.from\([^)]*['\"]base64['\"]|\batob\s*\(",
)

# Large encoded blob (base64 run or \xNN escape run).
_ENCODED_PAYLOAD = re.compile(
    r"[A-Za-z0-9+/]{200,}={0,2}|(?:\\x[0-9a-fA-F]{2}){50,}",
)

# Reference to a local script file in a command, e.g. `node ./scripts/x.js`.
_LOCAL_SCRIPT_REF = re.compile(r"(?:^|\s)(?:\./)?([\w./-]+\.[cm]?js)\b")

_SUSPICIOUS_BIN_EXT = {".sh", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".so", ".bin"}


def _benign_tools() -> frozenset[str]:
    """Allowlist of benign build/setup tool basenames from the intel pack.

    Falls back to a built-in baseline if the pack does not ship an npm list.
    """
    try:
        pack = intel.current()
        tools = getattr(pack, "npm_benign_tools", None)
        if tools:
            return frozenset(str(t).lower() for t in tools)
    except Exception:
        pass
    return _BUILTIN_BENIGN


_BUILTIN_BENIGN = frozenset({
    "node-gyp", "node-gyp-build", "prebuild-install", "prebuildify",
    "tsc", "tsup", "webpack", "rollup", "vite", "esbuild", "babel",
    "gulp", "grunt", "parcel", "rimraf", "mkdirp", "cpy", "copyfiles",
    "eslint", "prettier", "jest", "mocha", "husky", "patch-package",
    "npm", "yarn", "pnpm", "echo", "true", "exit", "cd", "node",
    "is-ci", "cross-env", "shx", "ncc", "tscw", "nest", "ng",
})


def _is_benign_script(script: str) -> bool:
    """True when every command token chain resolves to a benign tool.

    Splits on shell operators and checks the leading token of each segment
    against the benign-tool allowlist; any unknown leading token makes the
    whole script non-benign (conservative).
    """
    benign = _benign_tools()
    # Split into command segments on &&, ||, ;, |.
    segments = re.split(r"&&|\|\||;|\|", script)
    saw_cmd = False
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            return False
        if not tokens:
            continue
        head = Path(tokens[0]).name.lower()
        # `node ./scripts/x.js` is only benign if it runs no followed payload;
        # treat bare `node <file>` as non-benign so the file gets scanned.
        if head == "node" and len(tokens) > 1 and not tokens[1].startswith("-"):
            return False
        if head not in benign:
            return False
        saw_cmd = True
    return saw_cmd


def _root_package_json_paths(extracted_root: Path) -> list[Path]:
    """Return the install-time package.json(s): the archive root manifest only.

    npm tarballs extract under a single ``package/`` dir, so the real manifest
    lives at depth 1 or 2. Bundled ``node_modules`` manifests are dependencies,
    not this package's install hooks, and are skipped.
    """
    candidates: list[Path] = []
    direct = extracted_root / "package.json"
    if direct.is_file():
        candidates.append(direct)
    for child in extracted_root.iterdir():
        if child.is_dir() and child.name != "node_modules":
            nested = child / "package.json"
            if nested.is_file():
                candidates.append(nested)
    return candidates


def _analyze_script(name: str, script: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if _is_benign_script(script):
        return findings

    has_net = bool(_SHELL_NET.search(script))
    has_exec = bool(_SHELL_EXEC.search(script))
    has_decode = bool(_SHELL_DECODE.search(script))

    if has_net and (has_exec or has_decode):
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_net_exec",
            category=CATEGORY, severity="critical", confidence="high",
            file=rel,
            evidence=f"{name} script chains network fetch + exec/decode: {script[:160]}",
        ))
    elif has_net:
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_network",
            category=CATEGORY, severity="high", confidence="medium",
            file=rel,
            evidence=f"{name} script makes a network call: {script[:160]}",
        ))
    elif has_exec or has_decode:
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_subprocess",
            category=CATEGORY, severity="medium", confidence="medium",
            file=rel,
            evidence=f"{name} script runs a shell/eval: {script[:160]}",
        ))
    return findings


def _analyze_referenced_js(script: str, pkg_dir: Path, rel_prefix: str) -> list[Finding]:
    """Scan local .js files invoked by a lifecycle script."""
    findings: list[Finding] = []
    for m in _LOCAL_SCRIPT_REF.finditer(script):
        ref = m.group(1)
        target = (pkg_dir / ref).resolve()
        try:
            target.relative_to(pkg_dir.resolve())  # stay inside the package
        except ValueError:
            continue
        if not target.is_file():
            continue
        try:
            content = target.read_text(errors="replace")
        except Exception:
            continue
        rel = f"{rel_prefix}{ref}"
        has_net = bool(_JS_NET.search(content))
        has_exec = bool(_JS_EXEC.search(content))
        if has_net and has_exec:
            findings.append(Finding(
                rule_id="installer.npm_install_script_net_exec",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel,
                evidence="install script JS contains both network and child_process/eval",
            ))
        elif has_net:
            findings.append(Finding(
                rule_id="installer.npm_install_script_network",
                category=CATEGORY, severity="high", confidence="medium",
                file=rel, evidence="install script JS makes a network call",
            ))
        if _JS_DECODE.search(content) and has_exec:
            findings.append(Finding(
                rule_id="installer.npm_install_script_decode_exec",
                category=CATEGORY, severity="high", confidence="medium",
                file=rel, evidence="install script JS decodes base64 then executes",
            ))
        if _ENCODED_PAYLOAD.search(content):
            findings.append(Finding(
                rule_id="installer.npm_install_script_encoded_payload",
                category=CATEGORY, severity="medium", confidence="medium",
                file=rel, evidence="large encoded payload in install script JS",
            ))
    return findings


def _analyze_bin(bin_field, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    targets: list[str] = []
    if isinstance(bin_field, str):
        targets = [bin_field]
    elif isinstance(bin_field, dict):
        targets = [str(v) for v in bin_field.values()]
    for t in targets:
        if Path(t).suffix.lower() in _SUSPICIOUS_BIN_EXT:
            findings.append(Finding(
                rule_id="installer.npm_suspicious_bin",
                category=CATEGORY, severity="low", confidence="low",
                file=rel, evidence=f"bin entry points to a script/binary: {t}",
            ))
    return findings


def _analyze_manifest(path: Path, extracted_root: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    rel = str(path.relative_to(extracted_root))
    pkg_dir = path.parent
    rel_prefix = (str(pkg_dir.relative_to(extracted_root)) + "/") if pkg_dir != extracted_root else ""

    findings: list[Finding] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in _INSTALL_HOOKS:
            script = scripts.get(hook)
            if not isinstance(script, str) or not script.strip():
                continue
            findings.extend(_analyze_script(hook, script, rel))
            findings.extend(_analyze_referenced_js(script, pkg_dir, rel_prefix))

    findings.extend(_analyze_bin(data.get("bin"), rel))
    return findings


def analyze_install_scripts(
    extracted_root: Path,
    changed_files: Optional[set[str]] = None,
) -> list[Finding]:
    """Analyze the package's lifecycle scripts for install-time attack patterns."""
    findings: list[Finding] = []
    for manifest in _root_package_json_paths(extracted_root):
        findings.extend(_analyze_manifest(manifest, extracted_root))
    return findings
