# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable, Optional

from pkgsentry.adapter import Finding
from pkgsentry.analyze.lure_names import analyze_lure_name

CATEGORY = "metadata"


@dataclass
class MetadataContext:
    name: str
    version: str
    previous_release_at: Optional[datetime] = None
    maintainers_now: list[str] = field(default_factory=list)
    maintainers_prev: list[str] = field(default_factory=list)
    watchlist_top_names: list[str] = field(default_factory=list)
    sdist_files: list[str] = field(default_factory=list)
    wheel_files: list[str] = field(default_factory=list)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


_CONFUSABLES = {
    "l": "1", "1": "l",
    "o": "0", "0": "o",
    "i": "1",
    "s": "5", "5": "s",
    "rn": "m",
}

_WRAPPER_PREFIXES = ("python-", "py-", "python3-", "py3-", "lib")
_WRAPPER_SUFFIXES = ("-python", "-py", "-python3", "-py3", "-lib", "-sdk", "-api", "-client")


def _normalize_pkg_name(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def typosquat_distance(
    name: str, watchlist_top_names: Iterable[str], *, max_distance: int = 1
) -> list[Finding]:
    out: list[Finding] = []
    name_l = name.lower()
    name_norm = _normalize_pkg_name(name_l)

    top_list = list(watchlist_top_names)
    top_norms = {_normalize_pkg_name(t): t for t in top_list}

    for top in top_list:
        if top.lower() == name_l:
            return []

    # 1. Levenshtein on normalized names (catches l/1, -/_ swaps)
    for top in top_list:
        top_l = top.lower()
        if top_l == name_l:
            continue
        d = _levenshtein(name_l, top_l)
        if 0 < d <= max_distance:
            out.append(Finding(
                rule_id="metadata.typosquat_candidate",
                category=CATEGORY,
                severity="high",
                confidence="medium",
                file="",
                line=None,
                evidence=f"name {name!r} within {d} edit(s) of top package {top!r}",
            ))
            return out

    # 2. Separator confusion: name matches after stripping -/_/.
    if name_norm in top_norms and top_norms[name_norm].lower() != name_l:
        out.append(Finding(
            rule_id="metadata.typosquat_separator",
            category=CATEGORY,
            severity="high",
            confidence="high",
            file="",
            line=None,
            evidence=f"{name!r} matches {top_norms[name_norm]!r} after normalizing separators",
        ))
        return out

    # 3. Prefix/suffix squatting: python-requests vs requests
    for prefix in _WRAPPER_PREFIXES:
        if name_l.startswith(prefix):
            stripped = name_l[len(prefix):]
            if stripped and stripped in {t.lower() for t in top_list}:
                out.append(Finding(
                    rule_id="metadata.typosquat_prefix",
                    category=CATEGORY,
                    severity="medium",
                    confidence="medium",
                    file="",
                    line=None,
                    evidence=f"{name!r} wraps popular package {stripped!r} with prefix {prefix!r}",
                ))
                return out

    for suffix in _WRAPPER_SUFFIXES:
        if name_l.endswith(suffix):
            stripped = name_l[:-len(suffix)]
            if stripped and stripped in {t.lower() for t in top_list}:
                out.append(Finding(
                    rule_id="metadata.typosquat_suffix",
                    category=CATEGORY,
                    severity="medium",
                    confidence="medium",
                    file="",
                    line=None,
                    evidence=f"{name!r} wraps popular package {stripped!r} with suffix {suffix!r}",
                ))
                return out

    return out


def file_list_mismatch(sdist_files: list[str], wheel_files: list[str]) -> list[Finding]:
    out: list[Finding] = []

    # Skip wheel metadata dirs — those are PEP 427 housekeeping, never present in sdists.
    _WHEEL_META_SUFFIXES = (".dist-info", ".data")

    def _strip_wheel_meta(files: list[str]) -> list[str]:
        kept: list[str] = []
        for f in files:
            head = f.split("/", 1)[0]
            if head.endswith(_WHEEL_META_SUFFIXES):
                continue
            kept.append(f)
        return kept

    def _common_prefix(files: list[str]) -> str:
        """If every file shares the same first path segment, return it (with trailing /)."""
        segs = {f.split("/", 1)[0] for f in files if "/" in f}
        if len(segs) == 1:
            return segs.pop() + "/"
        return ""

    def _normalize(files: list[str], strip_prefix: str) -> set[str]:
        result: set[str] = set()
        for f in files:
            if not f.endswith((".py", ".so", ".pyd", ".pyz")):
                continue
            if strip_prefix and f.startswith(strip_prefix):
                f = f[len(strip_prefix):]
            result.add(f)
        return result

    # Real sdists carry a "<name>-<version>/" common prefix; wheels are flat under
    # the package dir but ALSO carry a sibling "<name>-<version>.dist-info/" (and
    # sometimes ".data/") metadata dir. Drop those wheel-only metadata dirs first.
    # We then compare on BASENAME only — path-structure normalization between sdist
    # and wheel is brittle (the sdist nests an extra <name>/ inside the version dir
    # that the wheel doesn't), and we'd rather under-fire than false-positive on
    # every legit package. True content diff is the deferred Plan-B diff module's job.
    sdist_clean = _strip_wheel_meta(sdist_files)
    wheel_clean = _strip_wheel_meta(wheel_files)
    sd_basenames = {Path(f).name for f in sdist_clean if f.endswith((".py", ".so", ".pyd", ".pyz"))}
    wh_basenames = {Path(f).name for f in wheel_clean if f.endswith((".py", ".so", ".pyd", ".pyz"))}
    # Common build-tool generated/metadata files that are wheel-only by design.
    _WHEEL_ONLY_OK = {"_version.py", "setup.py"}
    wheel_only = {f for f in (wh_basenames - sd_basenames) if f not in _WHEEL_ONLY_OK}
    if wheel_only:
        out.append(Finding(
            # Heuristic-only until the deferred diff module does proper content compare.
            # Sdist/wheel filename mismatch is unreliable on its own — many legit packages
            # ship generated wrappers or stubs only in the wheel.
            rule_id="metadata.sdist_wheel_mismatch",
            category=CATEGORY,
            severity="low",
            confidence="low",
            file="",
            line=None,
            evidence=f"wheel contains files absent from sdist: {sorted(wheel_only)[:5]}",
        ))
    return out


def _rapid_release(prev: Optional[datetime]) -> Optional[Finding]:
    if prev is None:
        return None
    now = datetime.now(timezone.utc)
    if now - prev < timedelta(hours=24):
        return Finding(
            rule_id="metadata.rapid_release",
            category=CATEGORY,
            severity="medium",
            confidence="medium",
            file="",
            line=None,
            evidence=f"new release < 24h after previous (prev={prev.isoformat()})",
        )
    return None


def _maintainer_change(now_list: list[str], prev_list: list[str]) -> Optional[Finding]:
    if not prev_list:
        return None
    now_set = {m.lower() for m in now_list}
    prev_set = {m.lower() for m in prev_list}
    added = now_set - prev_set
    removed = prev_set - now_set
    if added or removed:
        return Finding(
            rule_id="metadata.maintainer_change",
            category=CATEGORY,
            severity="medium",
            confidence="high",
            file="",
            line=None,
            evidence=f"maintainers changed (+{sorted(added)}, -{sorted(removed)})",
        )
    return None


def analyze_metadata(ctx: MetadataContext) -> list[Finding]:
    out: list[Finding] = []
    rr = _rapid_release(ctx.previous_release_at)
    if rr:
        out.append(rr)
    mc = _maintainer_change(ctx.maintainers_now, ctx.maintainers_prev)
    if mc:
        out.append(mc)
    out.extend(typosquat_distance(ctx.name, ctx.watchlist_top_names))
    out.extend(file_list_mismatch(ctx.sdist_files, ctx.wheel_files))
    out.extend(analyze_lure_name(ctx.name))
    return out
