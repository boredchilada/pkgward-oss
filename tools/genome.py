#!/usr/bin/env python3
"""genome.py — MANUAL malware function/section fingerprinting for the threat-intel pack.

You decide what's malicious; this just computes the hashes. For a file (and for the
specific function or line-range you point it at) it emits SHA256 + ssdeep + TLSH so you
can hand-pick "genes" and paste them into the intel pack. Nothing here is automated and
nothing runs the sample — it only reads and hashes bytes.

  # 1) pull a vaulted sample to a temp dir (decrypt is internal; never executed)
  python tools/genome.py pull npm forge-jsxy 1.0.0            -> prints the extract dir + files

  # 2) look at a file: its own hashes + the functions it contains (so you can choose)
  python tools/genome.py inspect /tmp/.../suspicious.py
  python tools/genome.py inspect /tmp/.../index.js

  # 3) emit a gene for the part YOU say is malicious
  python tools/genome.py gene /tmp/.../suspicious.py --func exfil      --campaign forge-jsxy
  python tools/genome.py gene /tmp/.../index.js       --lines 40:75    --campaign veteran
  #   --func  : extract by name (Python = real AST; other langs = best-effort brace match)
  #   --lines : extract an inclusive 1-based line range (works for ANY language/format)
  #   add --append intel/private/.../function_genes.jsonl to write the record straight in.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


# ---- hashing -------------------------------------------------------------

def _multihash(data: bytes) -> dict:
    out = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
           "ssdeep": None, "tlsh": None}
    try:
        import ppdeep  # pure-Python ssdeep-compatible (what the scanner uses)
        out["ssdeep"] = ppdeep.hash(data)
    except Exception:  # noqa: BLE001
        try:
            import ssdeep
            out["ssdeep"] = ssdeep.hash(data)
        except Exception as e:  # noqa: BLE001
            out["ssdeep"] = f"<unavailable: {e}>"
    try:
        import tlsh
        # TLSH needs >=50 bytes and enough entropy, else it returns "TNULL"/raises.
        h = tlsh.hash(data)
        out["tlsh"] = h if h and h != "TNULL" else None
    except Exception as e:  # noqa: BLE001
        out["tlsh"] = f"<unavailable: {e}>"
    return out


# ---- function extraction -------------------------------------------------

def _py_functions(src: str) -> list[dict]:
    """Real AST extraction for Python: every def/async def/class with its source."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [{"error": f"python parse failed: {e}"}]
    funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            seg = ast.get_source_segment(src, node)
            if seg is None:
                continue
            funcs.append({"name": node.name, "kind": type(node).__name__,
                          "line": node.lineno, "end": getattr(node, "end_lineno", node.lineno),
                          "segment": seg})
    return funcs


_BRACE_DECL = re.compile(
    r'(?m)^[ \t]*(?:export\s+|async\s+|pub\s+|public\s+|private\s+|static\s+)*'
    r'(?:function\s+(?P<f>\w+)|func\s+(?:\([^)]*\)\s*)?(?P<g>\w+)|fn\s+(?P<r>\w+)'
    r'|(?P<j>\w+)\s*(?:=\s*(?:async\s*)?\([^)]*\)\s*=>|\([^)]*\)\s*\{))'
)


def _brace_functions(text: str) -> list[dict]:
    """Best-effort brace-matched extraction for JS/TS/Go/Rust/C-like sources."""
    funcs = []
    for m in _BRACE_DECL.finditer(text):
        name = m.group("f") or m.group("g") or m.group("r") or m.group("j")
        if not name:
            continue
        # find the first '{' at/after the match and brace-match to its close
        i = text.find("{", m.start())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        seg = text[m.start():j + 1]
        line = text.count("\n", 0, m.start()) + 1
        end = text.count("\n", 0, j) + 1
        funcs.append({"name": name, "kind": "func", "line": line, "end": end, "segment": seg})
    return funcs


def _functions(path: Path, text: str) -> list[dict]:
    if path.suffix == ".py":
        return _py_functions(text)
    return _brace_functions(text)


def _select(funcs: list[dict], name: str) -> dict | None:
    for f in funcs:
        if f.get("name") == name:
            return f
    return None


# ---- commands ------------------------------------------------------------

def cmd_pull(args) -> int:
    sys.path.insert(0, "/app")
    from pkgward import vault
    res = vault.read_archive(args.ecosystem, args.name, args.version)
    if res is None:
        print(f"not vaulted: {args.ecosystem}/{args.name}@{args.version}", file=sys.stderr)
        return 1
    data, inner = res
    out = Path(tempfile.mkdtemp(prefix=f"genome-{args.name}-"))
    arc = out / inner
    arc.write_bytes(data)
    # static extract only (never executed)
    try:
        if inner.endswith((".tgz", ".tar.gz", ".tar")):
            with tarfile.open(arc) as t:
                t.extractall(out / "x")
        elif inner.endswith((".zip", ".crate", ".whl")):
            with zipfile.ZipFile(arc) as z:
                z.extractall(out / "x")
    except Exception as e:  # noqa: BLE001
        print(f"(archive extracted partially / unsupported: {e})", file=sys.stderr)
    print(f"pulled -> {out}")
    root = out / "x"
    if root.exists():
        files = sorted(p for p in root.rglob("*") if p.is_file())
        print(f"{len(files)} files; candidates:")
        for p in files[:40]:
            print("  ", p)
    return 0


def cmd_inspect(args) -> int:
    path = Path(args.file)
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    fh = _multihash(data)
    print(f"FILE  {path}")
    print(f"  sha256 {fh['sha256']}")
    print(f"  ssdeep {fh['ssdeep']}")
    print(f"  tlsh   {fh['tlsh']}   ({fh['size']} bytes)")
    funcs = _functions(path, text)
    print(f"FUNCTIONS ({len(funcs)}):")
    for f in funcs:
        if "error" in f:
            print("  ", f["error"]); continue
        seg = f["segment"].encode("utf-8", "replace")
        print(f"  {f['line']:>5}-{f['end']:<5} {f['kind']:<14} {f['name']:<30} ({len(seg)}b)")
    return 0


def cmd_gene(args) -> int:
    path = Path(args.file)
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    file_h = _multihash(data)

    # Optional malicious section (for your records / a future function-matcher).
    section = None
    label = None
    if args.lines:
        a, b = (int(x) for x in args.lines.split(":"))
        section = "".join(text.splitlines(keepends=True)[a - 1:b]).encode("utf-8", "replace")
        label = f"lines:{a}-{b}"
    elif args.func:
        f = _select(_functions(path, text), args.func)
        if not f:
            print(f"function {args.func!r} not found; run `inspect` to list them", file=sys.stderr)
            return 1
        section = f["segment"].encode("utf-8", "replace")
        label = f"func:{args.func}"

    # PACK-READY file-level record — exactly the known_malicious.jsonl schema. This is
    # what threat_intel.check_file matches at scan time (sha256 / ssdeep / tlsh).
    desc = args.description or f"{args.campaign} — {path.name}"
    if section is not None and not args.description:
        desc += f" (malicious {label})"
    rec = {
        "sha256": file_h["sha256"],
        "ssdeep": file_h["ssdeep"] if isinstance(file_h["ssdeep"], str) and not file_h["ssdeep"].startswith("<") else "",
        "tlsh": file_h["tlsh"] or "TNULL",
        "file_pattern": args.file_pattern or path.name,
        "campaign": args.campaign,
        "label": args.label,
        "description": desc,
        "source": args.source,
    }
    line = json.dumps(rec)
    print(line)  # stdout: paste/append straight into hashes/known_malicious.jsonl
    if args.append:
        with open(args.append, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(f"(appended file-level gene to {args.append})", file=sys.stderr)

    # Function-level hashes — NOT matched by the pack yet (file-level only). Kept here
    # for your records and the eventual function-matcher; goes to stderr so stdout stays
    # a clean pack line.
    if section is not None:
        fn = _multihash(section)
        print(f"# function-gene [{label}] (records only — not pack-matched yet):", file=sys.stderr)
        print(f"#   sha256={fn['sha256']}", file=sys.stderr)
        print(f"#   ssdeep={fn['ssdeep']}", file=sys.stderr)
        print(f"#   tlsh={fn['tlsh']}  ({fn['size']} bytes)", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("pull", help="extract a vaulted sample to a temp dir (static)")
    pp.add_argument("ecosystem"); pp.add_argument("name"); pp.add_argument("version")
    pp.set_defaults(fn=cmd_pull)

    pi = sub.add_parser("inspect", help="show a file's hashes + its functions")
    pi.add_argument("file")
    pi.set_defaults(fn=cmd_inspect)

    pg = sub.add_parser("gene", help="emit a pack-ready file-level gene (+ function hashes on stderr)")
    pg.add_argument("file")
    pg.add_argument("--func", help="malicious function name (Python = AST; others = best-effort)")
    pg.add_argument("--lines", help="malicious section as an inclusive 1-based range A:B (any language)")
    pg.add_argument("--campaign", required=True, help="campaign tag (e.g. forge-jsxy, ironworm)")
    pg.add_argument("--file-pattern", dest="file_pattern",
                    help="basename/glob the seed applies to (default: this file's name)")
    pg.add_argument("--label", default="malicious", help="default: malicious")
    pg.add_argument("--description", help="free-text note (default: auto from campaign + file)")
    pg.add_argument("--source", default="pkgward-genome",
                    help="provenance string (default: pkgward-genome)")
    pg.add_argument("--append", help="append the pack line to this known_malicious.jsonl")
    pg.set_defaults(fn=cmd_gene)

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
