# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version-update anomaly detection for the npm ingest gate.

The ingest gate normally SKIPS a new version of an established (known, non-
watchlisted) package — which is exactly how the asteroiddao "IronWorm" campaign
slipped past: `weavedb-sdk@0.45.3` was a version bump of a niche-but-known package,
so we never even downloaded the malicious ELF. This module closes that gap by
diffing the just-published version against its predecessor — entirely from the
registry **packument** (no tarball fetch) — and flagging the compromise tells:

  weavedb-sdk  0.45.2: preinstall=None        size=38,431
               0.45.3: preinstall=./tools/setup  size=1,015,053  ← hook added + 26x size + bundled-exec

An anomaly does NOT convict — it only earns the package a real SCAN (the 4 flags
are FP-prone baseline signals; legit packages add hooks and refactor). The full
detection pipeline + scoring decides the verdict. Only `install_hook_bundled_exec`
(a hook that directly runs a bundled native path — the dropper signature) is strong
enough to warrant *high*-priority scanning so it doesn't sit in the npm backlog.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# A bundled native binary is ~hundreds of KB; require BOTH a multiplier and an
# absolute floor so a tiny package growing 3x (a few KB) doesn't false-fire.
_SIZE_JUMP_FACTOR = float(os.environ.get("NPM_ANOMALY_SIZE_FACTOR", "3.0"))
_SIZE_JUMP_MIN_BYTES = int(os.environ.get("NPM_ANOMALY_SIZE_MIN_KB", "256")) * 1024
# A package with at least this many published versions is "established" — a size-jump on
# one is high-blast-radius and jumps the queue (the binding.gyp/Miasma class).
_ESTABLISHED_MIN_VERSIONS = int(os.environ.get("NPM_ANOMALY_ESTABLISHED_MIN_VERSIONS", "5"))

# Interpreters/tools that run a SCRIPT (benign), vs a path that is executed directly
# (a bundled binary/shell — the dropper shape). Mirrors installer._SHELL_INTERPS +
# the npm benign-tool set so the manifest-only check agrees with the file-level rule.
_BENIGN_HOOK_LEADS = frozenset({
    "node", "npm", "npx", "yarn", "pnpm", "tsc", "tsx", "ts-node", "node-gyp",
    "node-gyp-build", "prebuild-install", "prebuildify", "is-ci", "cross-env",
    "shx", "rimraf", "mkdirp", "cpy", "copyfiles", "echo", "true", "exit", "cd",
    "test", "husky", "patch-package", "electron-builder", "gulp", "webpack",
    "rollup", "vite", "esbuild", "babel", "nest", "ng", "prisma", "next",
})
_SHELL_INTERPS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "env"})


@dataclass(frozen=True)
class Anomaly:
    version: str
    flags: tuple[str, ...]
    priority: str = "normal"  # enqueue priority, decided at detection (blast-radius aware)

    @property
    def high_priority(self) -> bool:
        return self.priority == "high"


def _anomaly_priority(flags: set, n_versions: int) -> str:
    """Decide enqueue priority for an anomalous version-update.

    A version-update anomaly on an ESTABLISHED package is high-blast-radius and MUST jump
    the backlog: a normal-priority hit dies in the npm queue (tens of thousands deep) for
    days, by which time the malicious version is yanked and a re-fetch gets a clean release
    or 404 — so the detection misses despite firing. 'Established' = a real version history
    (this worm family hits long-lived packages like `@vapi-ai/server-sdk`, not new ones)."""
    established = n_versions >= _ESTABLISHED_MIN_VERSIONS
    hook_change = bool(flags & {"install_hook_added", "install_hook_changed"})
    # Dropper signature (hook → bundled path) — IronWorm class. Always high.
    if "install_hook_bundled_exec" in flags:
        return "high"
    # Established package that suddenly balloons in size — the only metadata lever for the
    # binding.gyp/node-gyp class, whose package.json scripts stay clean.
    if "size_jump" in flags and established:
        return "high"
    # Publisher change (possible account takeover) paired with a real content change.
    if "publisher_change" in flags and ("size_jump" in flags or hook_change):
        return "high"
    return "normal"


def _install_hooks(manifest: dict) -> dict[str, str]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {h: scripts[h] for h in _INSTALL_HOOKS if isinstance(scripts.get(h), str) and scripts[h].strip()}


def hook_runs_bundled_path(scripts: object) -> bool:
    """True if any install-hook command directly executes a BUNDLED relative path
    (./tools/setup, .github/scripts/precheck) rather than a known interpreter/tool.
    Detectable from the manifest alone — the IronWorm dropper signature."""
    if not isinstance(scripts, dict):
        return False
    for hook in _INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        for seg in re.split(r"&&|\|\||;|\|", cmd):
            seg = seg.strip()
            if not seg:
                continue
            try:
                toks = shlex.split(seg)
            except ValueError:
                continue
            if not toks:
                continue
            lead = toks[0]
            base = Path(lead).name.lower()
            if base in _SHELL_INTERPS and len(toks) > 1:
                lead = next((t for t in toks[1:] if not t.startswith("-")), lead)
                base = Path(lead).name.lower()
            if ("/" in lead or lead.startswith(".")) and base not in _BENIGN_HOOK_LEADS:
                return True
    return False


def _publisher(manifest: dict) -> Optional[str]:
    u = manifest.get("_npmUser")
    return u.get("name") if isinstance(u, dict) else None


def _declared_deps(manifest: dict) -> set[str]:
    out: set[str] = set()
    for key in ("dependencies", "optionalDependencies", "peerDependencies"):
        d = manifest.get(key)
        if isinstance(d, dict):
            out.update(k for k in d if isinstance(k, str))
    return out


def new_known_bad_dep_edge(
    packument: dict, known_bad: frozenset,
) -> Optional[tuple[str, str]]:
    """If the newest version NEWLY declares a dependency on a confirmed-malicious
    npm name, return ``(version, dep_name)``. Pure: the caller supplies the
    known-bad set. 'New' = not declared by the predecessor version — the inject
    moment — which is exactly the edge a version-update ingest gate should catch
    (a pre-existing bad edge is handled at scan time)."""
    if not known_bad:
        return None
    from pkgward.known_bad_deps import normalize
    ordered = _versions_newest_first(packument)
    if not ordered:
        return None
    new_v, new_m = ordered[0]
    new_deps = _declared_deps(new_m)
    if not new_deps:
        return None
    prev_deps = {normalize("npm", d) for d in _declared_deps(ordered[1][1])} if len(ordered) >= 2 else set()
    for dep in sorted(new_deps):
        if normalize("npm", dep) in known_bad and normalize("npm", dep) not in prev_deps:
            return (new_v, dep)
    return None


def _dist_int(manifest: dict, key: str) -> Optional[int]:
    dist = manifest.get("dist")
    if isinstance(dist, dict) and isinstance(dist.get(key), int):
        return dist[key]
    return None


def _versions_newest_first(packument: dict) -> list[tuple[str, dict]]:
    versions = packument.get("versions")
    times = packument.get("time")
    if not isinstance(versions, dict) or not isinstance(times, dict):
        return []
    dated = [
        (v, times[v], m) for v, m in versions.items()
        if isinstance(m, dict) and isinstance(times.get(v), str)
    ]
    dated.sort(key=lambda x: x[1], reverse=True)
    return [(v, m) for v, _t, m in dated]


def detect_update_anomaly(packument: dict) -> Optional[Anomaly]:
    """Diff the newest-by-publish-time version against its predecessor. Returns an
    Anomaly (the flags that fired) or None. Pure: no I/O."""
    ordered = _versions_newest_first(packument)
    if len(ordered) < 2:
        return None  # nothing to compare against — not an "update vs prior"
    new_v, new_m = ordered[0]
    _prev_v, prev_m = ordered[1]

    flags: list[str] = []

    new_hooks, prev_hooks = _install_hooks(new_m), _install_hooks(prev_m)
    if new_hooks and new_hooks != prev_hooks:
        # only flag a hook that is genuinely new or changed (not identical carryover)
        if any(new_hooks.get(h) != prev_hooks.get(h) for h in new_hooks):
            flags.append("install_hook_added" if not prev_hooks else "install_hook_changed")
    if new_hooks and hook_runs_bundled_path(new_m.get("scripts")) and \
            not hook_runs_bundled_path(prev_m.get("scripts")):
        flags.append("install_hook_bundled_exec")

    ns, ps = _dist_int(new_m, "unpackedSize"), _dist_int(prev_m, "unpackedSize")
    if ns and ps and ns >= ps * _SIZE_JUMP_FACTOR and (ns - ps) >= _SIZE_JUMP_MIN_BYTES:
        flags.append("size_jump")
    nf, pf = _dist_int(new_m, "fileCount"), _dist_int(prev_m, "fileCount")
    if nf and pf and nf > pf:
        flags.append("file_count_jump")

    nu, pu = _publisher(new_m), _publisher(prev_m)
    if nu and pu and nu != pu:
        flags.append("publisher_change")

    if not flags:
        return None
    # file_count_jump alone is too weak to be worth a scan (a +1 file is noise);
    # require it to co-occur with something else.
    if flags == ["file_count_jump"]:
        return None
    n_versions = len(packument.get("versions") or {})
    return Anomaly(version=new_v, flags=tuple(flags),
                   priority=_anomaly_priority(set(flags), n_versions))
