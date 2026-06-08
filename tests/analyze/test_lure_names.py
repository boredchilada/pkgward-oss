# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os

import pytest
from pkgward.analyze.lure_names import analyze_lure_name, score_name

# Some TrapDoor campaign names only flag once the operator intel overlay is
# loaded (its lure-keyword list is broader than the baseline pack). On a
# baseline-only checkout (`PKGWARD_INTEL_PATH` unset — e.g. the public repo)
# these can't fire, so they skip. Same convention as test_staged_payload_rule.
_OVERLAY_LOADED = bool(os.environ.get("PKGWARD_INTEL_PATH"))
_overlay_only = pytest.mark.skipif(
    not _OVERLAY_LOADED, reason="needs the private intel overlay (PKGWARD_INTEL_PATH)"
)


class TestScoreName:
    def test_single_category_crypto(self):
        hits = score_name("wallet-utils")
        assert "crypto" in hits
        assert len(hits) == 1

    def test_multi_category_trapdoor(self):
        hits = score_name("wallet-security-checker")
        assert "crypto" in hits
        assert "security_theater" in hits
        assert len(hits) >= 2

    @_overlay_only
    def test_three_categories(self):
        hits = score_name("crypto-credential-scanner")
        assert len(hits) >= 3

    def test_clean_name(self):
        hits = score_name("requests")
        assert len(hits) == 0

    def test_legitimate_single_keyword(self):
        hits = score_name("flask")
        assert len(hits) == 0


class TestAnalyzeLureName:
    def test_no_finding_clean_name(self):
        assert analyze_lure_name("requests") == []

    def test_no_finding_single_category(self):
        assert analyze_lure_name("web3-utils") == []

    def test_medium_two_categories(self):
        findings = analyze_lure_name("wallet-security-checker")
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert findings[0].rule_id == "metadata.lure_name"

    @_overlay_only
    def test_high_three_categories(self):
        findings = analyze_lure_name("crypto-credential-scanner")
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].rule_id == "metadata.lure_name_combo"

    # TrapDoor campaign names the baseline pack detects on its own.
    @pytest.mark.parametrize("name", [
        "defi-risk-scanner",
        "wallet-security-checker",
        "wallet-backup-verifier",
        "crypto-credential-scanner",
        "web3-secrets-detector",
        "defi-threat-scanner",
    ])
    def test_trapdoor_names_flagged(self, name):
        findings = analyze_lure_name(name)
        assert len(findings) >= 1, f"{name} should trigger lure name detection"

    # TrapDoor names that only flag with the operator intel overlay loaded.
    @_overlay_only
    @pytest.mark.parametrize("name", [
        "eth-security-auditor",
        "mnemonic-safety-check",
        "eth-wallet-sentinel",
        "cryptowallet-safety",
        "solidity-deploy-guard",
        "chain-key-validator",
        "deployment-key-auditor",
    ])
    def test_trapdoor_names_flagged_overlay(self, name):
        findings = analyze_lure_name(name)
        assert len(findings) >= 1, f"{name} should trigger lure name detection"

    # Legitimate packages that should NOT trigger
    @pytest.mark.parametrize("name", [
        "requests",
        "flask",
        "django",
        "numpy",
        "pandas",
        "cryptography",
        "web3",
        "pytest",
        "setuptools",
        "boto3",
        "tensorflow",
        "kubernetes",
        "docker",
    ])
    def test_legitimate_names_clean(self, name):
        findings = analyze_lure_name(name)
        assert len(findings) == 0, f"{name} should not trigger lure name detection"

    # Single-category names that should NOT trigger
    @pytest.mark.parametrize("name", [
        "wallet-connect",
        "security-headers",
        "env-config",
        "llm-tools",
        "token-bucket",
    ])
    def test_single_category_no_finding(self, name):
        findings = analyze_lure_name(name)
        assert len(findings) == 0, f"{name} (single category) should not trigger"
