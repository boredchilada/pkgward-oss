# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm-only JS deobfuscation pre-pass via webcrack (https://github.com/j4k0xb/webcrack).

webcrack statically reverses obfuscator.io output, unminifies, decodes string arrays
and unpacks webpack/browserify bundles — turning a minified/obfuscated blob into
readable modules. We run it BEFORE the static analyzers and write the result into a
``.webcrack/`` subdir of the extracted tree, so YARA / opengrep / iocs / obfuscation
all run on the deobfuscated code (decoded URLs, real call sites) instead of an opaque
bundle. Modeled on ``analyze/unpack.py`` (the UPX transform→re-analyze pass).

webcrack is mostly AST-based but evaluates some decoder snippets in ``isolated-vm`` (a
hardened V8 isolate, no fs/net), so it executes bits of untrusted code. We bound it
hard: a per-file timeout, file-count + size caps, and we only run it on files that
actually look obfuscated/minified. Fail-soft — never raises, never blocks a scan."""
from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from pkgward.logging_setup import get_logger

log = get_logger("webcrack")

_BIN = os.environ.get("PKGWARD_WEBCRACK_BIN", "webcrack")
_TIMEOUT = int(os.environ.get("PKGWARD_WEBCRACK_TIMEOUT", "120"))
# Total wall-clock budget for the whole pass — caps the worst case (max_files ×
# per-file timeout) well under the 15-min worker timeout so a package full of
# slow-to-deobfuscate bundles can't starve the rest of the scan.
_TOTAL_TIMEOUT = int(os.environ.get("PKGWARD_WEBCRACK_TOTAL_TIMEOUT", "240"))
_MAX_FILES = int(os.environ.get("PKGWARD_WEBCRACK_MAX_FILES", "25"))
_MAX_FILE_BYTES = int(os.environ.get("PKGWARD_WEBCRACK_MAX_MB", "8")) * 1024 * 1024
_OUT_DIR = ".webcrack"
_JS_EXT = {".js", ".cjs", ".mjs"}

# Markers that make a JS file worth deobfuscating: obfuscator.io hex identifiers,
# webpack/browserify bundle plumbing, a packer's eval(function(){...}) wrapper, long
# \xNN escape runs, or a char-code string builder. (Minified-line check below covers
# the rest.) Scanned over a bounded prefix so a huge file doesn't cost a full regex.
_OBFUSCATED = re.compile(
    rb"_0x[0-9a-fA-F]{4,}|__webpack_require__|webpackJsonp|webpackChunk|"
    rb"\beval\s*\(\s*function\b|String\.fromCharCode\s*\(|"
    rb"(?:\\x[0-9a-fA-F]{2}){6,}"
)
_SNIFF_BYTES = 200_000


def is_enabled() -> bool:
    return os.environ.get("PKGWARD_WEBCRACK_ENABLED", "1").lower() not in (
        "0", "false", "off", "no",
    )


# webcrack needs Node 22 or 24 (its isolated-vm dep doesn't support odd majors). Even
# minors of those work. Tunable for forward-compat as new even LTS lines land.
_SUPPORTED_NODE_MAJORS = {
    int(x) for x in os.environ.get("PKGWARD_WEBCRACK_NODE_MAJORS", "22,24").split(",") if x.strip()
}


def _probe_version(argv: list[str]) -> str | None:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else None
    except Exception:
        return None


@functools.lru_cache(maxsize=1)
def _runtime_ok() -> bool:
    """Identify node + webcrack once and confirm they can run. Logs the versions
    (``webcrack_ready``) so the runtime is observable; disables the pass (fail-soft,
    ``webcrack_unavailable``) if webcrack is missing or node is absent / an unsupported
    major — webcrack silently misbehaves on odd-numbered Node, so we gate on it."""
    if not shutil.which(_BIN):
        log.warning("webcrack_unavailable", reason="webcrack binary not found", bin=_BIN)
        return False
    node_ver = _probe_version(["node", "--version"]) if shutil.which("node") else None
    wc_ver = _probe_version([_BIN, "--version"])
    major = None
    if node_ver and node_ver.lstrip("v")[:1].isdigit():
        try:
            major = int(node_ver.lstrip("v").split(".")[0])
        except ValueError:
            major = None
    ok = bool(wc_ver) and major in _SUPPORTED_NODE_MAJORS
    if ok:
        log.info("webcrack_ready", node=node_ver, webcrack=wc_ver)
    else:
        log.warning("webcrack_unavailable", node=node_ver, webcrack=wc_ver,
                    supported_node_majors=sorted(_SUPPORTED_NODE_MAJORS),
                    reason="missing webcrack or unsupported/absent node major")
    return ok


def _looks_obfuscated(data: bytes) -> bool:
    head = data[:_SNIFF_BYTES]
    if _OBFUSCATED.search(head):
        return True
    # minified: a single very long line (no hand-written source wraps at 2000+ cols)
    return max((len(line) for line in head.split(b"\n")), default=0) > 2000


def deobfuscate_npm(root: Path) -> set[str]:
    """Deobfuscate obfuscated/minified JS under ``root`` into ``root/.webcrack/``.
    Returns the posix extraction-relative paths of the produced files (to fold into
    the analyzers' ``changed_files`` set). Empty on disabled / missing binary / no hits."""
    if not is_enabled() or not _runtime_ok():
        return set()
    binary = shutil.which(_BIN)  # _runtime_ok confirmed it resolves + the node major fits

    out_root = root / _OUT_DIR
    produced: set[str] = set()
    n = 0
    deadline = time.monotonic() + _TOTAL_TIMEOUT
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES or time.monotonic() >= deadline:
            break
        if not p.is_file() or p.suffix.lower() not in _JS_EXT or _OUT_DIR in p.parts:
            continue
        try:
            if not (0 < p.stat().st_size <= _MAX_FILE_BYTES):
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if not _looks_obfuscated(data):
            continue
        rel = p.relative_to(root).as_posix()
        dest = out_root / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                [binary, str(p), "-o", str(dest), "-f"],   # -f: overwrite the output dir
                capture_output=True,
                timeout=max(5, min(_TIMEOUT, int(deadline - time.monotonic()))),
                env={**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0"},
            )
            if r.returncode != 0:
                # webcrack couldn't deobfuscate this file. We DON'T skip the file: the
                # original is on disk and analyzed by every downstream analyzer — we only
                # lose the deobfuscated COPY of this one file. Just record that it failed.
                log.warning("webcrack_failed", file=rel, rc=r.returncode,
                            error=r.stderr.decode("utf-8", "replace").strip()[:200])
        except (subprocess.TimeoutExpired, OSError) as e:
            # Same: the original file is still analyzed; only its deobfuscated copy is lost.
            log.warning("webcrack_failed", file=rel, error=str(e)[:200])
            n += 1
            continue
        for q in dest.rglob("*"):
            if q.is_file() and q.suffix.lower() in _JS_EXT:
                produced.add(q.relative_to(root).as_posix())
        n += 1
    if produced:
        log.info("webcrack_deobfuscated", inputs=n, output_files=len(produced))
    return produced
