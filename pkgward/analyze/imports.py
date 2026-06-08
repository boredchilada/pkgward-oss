# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import ast
from pathlib import Path

from pkgward.adapter import Finding

CATEGORY = "imports"

# Narrow set — generic verbs like .get/.post/.Session match dict.get(), requests.Session()
# definitions, decorators, etc. and produce overwhelming false positives. Stick to the
# unambiguous-network functions whose presence at module-import time is genuinely suspicious.
_NET_NAMES = {"urlopen", "urlretrieve"}
_EXEC_NAMES = {"exec", "compile", "eval"}
_SUBPROCESS_NAMES = {"Popen", "run", "call", "check_call", "check_output", "system", "popen"}


def _is_subprocess_call(node: ast.Call) -> bool:
    """True if call is subprocess.{Popen,run,call,...} or os.{system,popen}."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    attr = func.attr
    # Module name must be 'subprocess' or 'os' (for system/popen only)
    base = func.value
    if not isinstance(base, ast.Name):
        return False
    if base.id == "subprocess" and attr in {"Popen", "run", "call", "check_call", "check_output"}:
        return True
    if base.id == "os" and attr in {"system", "popen"}:
        return True
    return False


def _subprocess_suspicion(node: ast.Call) -> list[str]:
    """Return list of suspicion reasons; empty list means plain (not suspicious)."""
    reasons: list[str] = []
    # keyword args
    for kw in node.keywords:
        if kw.arg == "start_new_session" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            reasons.append("start_new_session=True")
        elif kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            reasons.append("shell=True")
    # walk arg string-literals (including list/tuple elements)
    def _iter_strs(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n.value
        elif isinstance(n, (ast.List, ast.Tuple)):
            for elt in n.elts:
                yield from _iter_strs(elt)
    first_positional_strs: list[str] = []
    if node.args:
        first_positional_strs = list(_iter_strs(node.args[0]))
    all_strs: list[str] = []
    for a in node.args:
        all_strs.extend(_iter_strs(a))
    for s in all_strs:
        if "/tmp/" in s:
            reasons.append(f"/tmp path: {s!r}")
            break
    for s in first_positional_strs:
        if "python" in s.lower():
            reasons.append(f"python re-invoke: {s!r}")
            break
    return reasons


def _marshal_aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Names that refer to the `marshal` module / its load functions, tracking
    aliases. Returns (module_aliases, bare_load_names).

      import marshal            -> ({'marshal'}, set())
      import marshal as _m      -> ({'_m'}, set())
      from marshal import load  -> (set(), {'load'})
      from marshal import loads as _l -> (set(), {'_l'})
    """
    mods: set[str] = set()
    funcs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "marshal":
                    mods.add(a.asname or "marshal")
        elif isinstance(node, ast.ImportFrom) and node.module == "marshal":
            for a in node.names:
                if a.name in ("load", "loads"):
                    funcs.add(a.asname or a.name)
    return mods, funcs


def _is_marshal_load(node: ast.Call, mods: set[str], funcs: set[str]) -> bool:
    """True if `node` is a marshal.load/loads call (honoring import aliases)."""
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in ("load", "loads"):
        base = func.value
        return isinstance(base, ast.Name) and base.id in mods
    if isinstance(func, ast.Name):
        return func.id in funcs
    return False


def _walk_top_level(node):
    """Walk only statements executed at module import — do NOT descend into
    function / async-function / class / lambda bodies (those only run when called)."""
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_top_level(child)


def _call_name(node: ast.Call) -> str:
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _analyze_module(path: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []
    out: list[Finding] = []
    marshal_mods, marshal_funcs = _marshal_aliases(tree)
    marshal_load_line: int | None = None
    exec_eval_line: int | None = None
    for stmt in tree.body:
        for node in _walk_top_level(stmt):
            if not isinstance(node, ast.Call):
                continue
            full = _call_name(node)
            tail = full.split(".")[-1]
            if (marshal_mods or marshal_funcs) and marshal_load_line is None \
                    and _is_marshal_load(node, marshal_mods, marshal_funcs):
                marshal_load_line = node.lineno
            if tail in ("exec", "eval") and tail == full and exec_eval_line is None:
                exec_eval_line = node.lineno
            if tail in _NET_NAMES:
                out.append(Finding(
                    rule_id="imports.network_at_import",
                    category=CATEGORY,
                    severity="high",
                    confidence="medium",
                    file=str(path.name),
                    line=node.lineno,
                    evidence=f"network call at module import: {full}",
                ))
            # exec/eval/compile only counts when called as a BARE BUILTIN — i.e.
            # `exec(...)` not `foo.exec(...)`. Tail matching catches `re.compile`,
            # `tabulate.compile`, `sympy.compile`, all of which are legitimate and
            # absolutely dominate real PyPI packages.
            elif tail in _EXEC_NAMES and tail == full:
                out.append(Finding(
                    rule_id="imports.exec_at_import",
                    category=CATEGORY,
                    severity="high",
                    confidence="high",
                    file=str(path.name),
                    line=node.lineno,
                    evidence=f"exec/eval/compile at module import: {full}",
                ))
            if _is_subprocess_call(node):
                full = _call_name(node)
                out.append(Finding(
                    rule_id="imports.subprocess_at_import",
                    category=CATEGORY,
                    severity="medium",
                    confidence="low",
                    file=str(path.name),
                    line=node.lineno,
                    evidence=f"subprocess/os call at module import: {full}",
                ))
                reasons = _subprocess_suspicion(node)
                if reasons:
                    out.append(Finding(
                        rule_id="imports.subprocess_at_import_suspicious",
                        category=CATEGORY,
                        severity="high",
                        confidence="high",
                        file=str(path.name),
                        line=node.lineno,
                        evidence=f"suspicious subprocess at import ({full}): {'; '.join(reasons)}",
                    ))

    # Compiled-bytecode loader: a module that marshal.load()s and exec()s at import
    # is a compiled-payload dropper (the mps-xtrap "compiled for IP protection" stub —
    # every module loads a hidden .pyc and execs it; the .pyc is often not even shipped,
    # i.e. staged/fetched at runtime). marshal-load feeding exec/eval is near-zero in
    # legit packages, so this is a high-precision critical on its own.
    if marshal_load_line is not None and exec_eval_line is not None:
        out.append(Finding(
            rule_id="imports.marshalled_bytecode_loader",
            category=CATEGORY,
            severity="critical",
            confidence="high",
            file=str(path.name),
            line=marshal_load_line,
            evidence="compiled-bytecode loader: marshal.load() feeds exec/eval at import "
                     f"(load L{marshal_load_line}, exec L{exec_eval_line})",
        ))

    # Chain rule (C): one finding per file if both halves present.
    has_net = any(f.rule_id == "imports.network_at_import" for f in out)
    suspicious = [f for f in out if f.rule_id == "imports.subprocess_at_import_suspicious"]
    if has_net and suspicious:
        sp = suspicious[0]
        out.append(Finding(
            rule_id="imports.network_subprocess_chain",
            category=CATEGORY,
            severity="critical",
            confidence="high",
            file=str(path.name),
            line=sp.line,
            evidence="behavioral chain: network_at_import + subprocess_at_import_suspicious in same module",
        ))
    return out


def analyze_imports(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    for init in extracted_root.rglob("__init__.py"):
        if changed_files is not None and init.relative_to(extracted_root).as_posix() not in changed_files:
            continue
        out.extend(_analyze_module(init))
    # also check top-level single-file modules
    for py in extracted_root.glob("*.py"):
        if py.name == "setup.py":
            continue
        if changed_files is not None and py.relative_to(extracted_root).as_posix() not in changed_files:
            continue
        out.extend(_analyze_module(py))
    return out
