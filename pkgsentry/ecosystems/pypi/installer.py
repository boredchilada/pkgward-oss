# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import ast
from pathlib import Path

from pkgsentry.adapter import Finding

CATEGORY = "installer"

_NET_READ_FUNCS = {"urlopen", "urlretrieve", "get", "post", "request"}
_EXEC_FUNCS = {"exec", "compile", "eval"}


def _call_name(node: ast.Call) -> str:
    """Return a dotted name for the function being called, or ''. """
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _walk_module_level(tree: ast.Module):
    """Yield (node, parent_stmt) for calls at module top level (import-time)."""
    for stmt in tree.body:
        for node in ast.walk(stmt):
            yield node, stmt


def _has_net_read(tree: ast.Module) -> list[ast.Call]:
    hits = []
    for stmt in tree.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                name = _call_name(node).split(".")[-1]
                if name in _NET_READ_FUNCS:
                    hits.append(node)
    return hits


def _exec_eats_call(tree: ast.Module) -> list[ast.Call]:
    """exec/compile/eval taking a Call (e.g. exec(urlopen(...).read()))."""
    hits = []
    for stmt in tree.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                name = _call_name(node).split(".")[-1]
                if name in _EXEC_FUNCS:
                    for arg in node.args:
                        if isinstance(arg, ast.Call):
                            hits.append(node)
                            break
                        if isinstance(arg, ast.Attribute):
                            # exec(x.read()) shape via Attribute -> may be a method chain
                            hits.append(node)
                            break
    return hits


def _subprocess_calls(tree: ast.Module) -> list[ast.Call]:
    hits = []
    for stmt in tree.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                full = _call_name(node)
                tail = full.split(".")[-1]
                if full.startswith("subprocess.") or tail in {"Popen", "run", "call", "check_call", "check_output"}:
                    if full.startswith("subprocess.") or "subprocess" in full:
                        hits.append(node)
                        continue
                    if tail == "Popen":
                        hits.append(node)
    return hits


def _os_system_calls(tree: ast.Module) -> list[ast.Call]:
    hits = []
    for stmt in tree.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                if _call_name(node) in {"os.system", "os.popen"}:
                    hits.append(node)
    return hits


def _analyze_setup_py(path: Path) -> list[Finding]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except (OSError, SyntaxError):
        return []

    findings: list[Finding] = []
    net_hits = _has_net_read(tree)
    exec_hits = _exec_eats_call(tree)

    if net_hits and exec_hits:
        n = exec_hits[0]
        findings.append(Finding(
            rule_id="installer.urlopen_exec_chain",
            category=CATEGORY,
            severity="critical",
            confidence="high",
            file=str(path.name),
            line=getattr(n, "lineno", None),
            evidence="network-read result passed to exec/compile/eval at install time",
        ))

    for n in _subprocess_calls(tree):
        findings.append(Finding(
            rule_id="installer.subprocess_at_install",
            category=CATEGORY,
            severity="high",
            confidence="medium",
            file=str(path.name),
            line=getattr(n, "lineno", None),
            evidence=f"subprocess call at install time: {_call_name(n)}",
        ))

    for n in _os_system_calls(tree):
        findings.append(Finding(
            rule_id="installer.os_system_at_install",
            category=CATEGORY,
            severity="high",
            confidence="high",
            file=str(path.name),
            line=getattr(n, "lineno", None),
            evidence=f"os.system/os.popen at install time: {_call_name(n)}",
        ))

    return findings


def _install_setup_py_paths(extracted_root: Path) -> list[Path]:
    """Return paths that are the actual install-time setup.py — never nested
    package modules that happen to be named 'setup.py'.

    Real install-time setup.py lives at:
      - extracted_root/setup.py            (when extracted to a flat dir)
      - extracted_root/<name-version>/setup.py  (typical sdist layout)
    Nested files like extracted_root/<name-version>/<name>/<sub>/setup.py are
    helper modules and are skipped.
    """
    candidates: list[Path] = []
    # Depth 1 — direct child of the extracted root.
    direct = extracted_root / "setup.py"
    if direct.is_file():
        candidates.append(direct)
    # Depth 2 — child of the single top-level archive directory (typical sdist).
    for child in extracted_root.iterdir():
        if child.is_dir():
            nested = child / "setup.py"
            if nested.is_file():
                candidates.append(nested)
    return candidates


def analyze_install_scripts(extracted_root: Path) -> list[Finding]:
    """Walk extracted package, analyze the actual install-time setup.py for
    behavioral chains. Nested package modules named setup.py are not installers
    and are skipped.

    pyproject.toml / setup.cfg are inspected for presence only - declarative
    formats cannot run code by themselves.
    """
    findings: list[Finding] = []
    for setup_py in _install_setup_py_paths(extracted_root):
        findings.extend(_analyze_setup_py(setup_py))
    # Future: parse pyproject.toml for custom build backends and follow their hooks.
    return findings
