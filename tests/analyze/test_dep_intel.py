# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scan-time finding: a package that declares a dependency on a confirmed-malicious
package. New edge -> critical; pre-existing edge -> high; cross-ecosystem name
collisions must NOT match."""
from __future__ import annotations

from pkgward.analyze.dep_intel import check_known_bad_deps


def test_new_bad_edge_is_critical():
    out = check_known_bad_deps(
        ecosystem="npm",
        requires_dist=["lodash", "evil-utils"],
        prev_requires_dist=["lodash"],  # evil-utils is newly added
        known_bad=frozenset({"evil-utils"}),
    )
    assert len(out) == 1
    assert out[0].rule_id == "dep_intel.depends_on_known_malicious"
    assert out[0].severity == "critical"
    assert "evil-utils" in out[0].evidence


def test_preexisting_bad_edge_is_high():
    out = check_known_bad_deps(
        ecosystem="npm",
        requires_dist=["lodash", "evil-utils"],
        prev_requires_dist=["lodash", "evil-utils"],  # already there last version
        known_bad=frozenset({"evil-utils"}),
    )
    assert len(out) == 1 and out[0].severity == "high"


def test_no_prev_is_high_not_critical():
    # brand-new package (no predecessor) — can't prove injection, so high not critical
    out = check_known_bad_deps(
        ecosystem="npm",
        requires_dist=["evil-utils"],
        prev_requires_dist=None,
        known_bad=frozenset({"evil-utils"}),
    )
    assert len(out) == 1 and out[0].severity == "high"


def test_pypi_pep508_entry_matches_normalized():
    out = check_known_bad_deps(
        ecosystem="pypi",
        requires_dist=["Evil_Pkg>=1.0; python_version>='3.8'", "requests>=2"],
        prev_requires_dist=["requests>=2"],
        known_bad=frozenset({"evil-pkg"}),
    )
    assert len(out) == 1 and out[0].severity == "critical"


def test_no_match_returns_empty():
    out = check_known_bad_deps(
        ecosystem="npm",
        requires_dist=["lodash", "react"],
        prev_requires_dist=["lodash"],
        known_bad=frozenset({"evil-utils"}),
    )
    assert out == []


def test_empty_known_bad_is_noop():
    assert check_known_bad_deps(
        ecosystem="npm", requires_dist=["evil-utils"],
        prev_requires_dist=None, known_bad=frozenset(),
    ) == []
