# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detection regression suite.

Runs every known-bad / known-good corpus sample through the real
analyze→score path and fails the build on a regression:

  - a known-bad sample that no longer reaches malicious/suspicious  (false negative)
  - a known-good sample that gets flagged                           (false-positive creep)
  - a missing `expect_rules` entry or a fired `forbid_rules` entry

Extra findings on a known-bad sample are surfaced as a warning, not a failure.

See tests/corpus_harness.py for tiers (public synthetic / private / vault) and
docs/regression-testing.md for how to add samples.
"""
from __future__ import annotations

import warnings

import pytest

from tests import corpus_harness as ch

_SAMPLES = ch.discover_samples()
_BAD_VERDICTS = {"malicious", "suspicious"}


def _idfn(sample: ch.Sample) -> str:
    return sample.sample_id


@pytest.mark.asyncio
@pytest.mark.parametrize("sample", _SAMPLES, ids=_idfn)
async def test_corpus_sample(sample: ch.Sample, tmp_path):
    result, fired = await ch.run_sample(sample, tmp_path)

    # --- Primary gate: the known-bad / known-good label ---
    if sample.label == "good":
        assert result.verdict == "clean", (
            f"{sample.sample_id}: FALSE-POSITIVE CREEP — known-good sample "
            f"flagged as {result.verdict!r} (score {result.score}); fired: {sorted(fired)}"
        )
    else:
        assert result.verdict in _BAD_VERDICTS, (
            f"{sample.sample_id}: FALSE-NEGATIVE REGRESSION — known-bad sample "
            f"scored {result.verdict!r} (score {result.score}); fired: {sorted(fired)}"
        )

    assert result.verdict == sample.expected_verdict, (
        f"{sample.sample_id}: verdict changed — expected {sample.expected_verdict!r}, "
        f"got {result.verdict!r} (score {result.score}); fired: {sorted(fired)}"
    )

    # --- Optional rule pinning ---
    missing = set(sample.expect_rules) - fired
    assert not missing, (
        f"{sample.sample_id}: expected rules did not fire: {sorted(missing)}; "
        f"fired: {sorted(fired)}"
    )
    forbidden = set(sample.forbid_rules) & fired
    assert not forbidden, (
        f"{sample.sample_id}: forbidden rules fired: {sorted(forbidden)}"
    )

    # --- Warn (non-fatal) on extra findings beyond what was pinned ---
    if sample.expect_rules and sample.label != "good":
        extra = fired - set(sample.expect_rules)
        if extra:
            warnings.warn(
                f"{sample.sample_id}: extra findings beyond expect_rules: {sorted(extra)}",
                stacklevel=1,
            )


def test_corpus_is_nonempty():
    """Guard against the suite silently collecting zero samples (e.g. a path typo)."""
    assert _SAMPLES, "no corpus samples discovered under tests/corpus/"
