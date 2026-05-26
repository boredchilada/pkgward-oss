# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import pytest
from pkgsentry.analyze.lure_names import analyze_lure_name, score_name


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

    def test_high_three_categories(self):
        findings = analyze_lure_name("crypto-credential-scanner")
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].rule_id == "metadata.lure_name_combo"

    # TrapDoor campaign package names
    @pytest.mark.parametrize("name", [
        "eth-security-auditor",
        "defi-risk-scanner",
        "wallet-security-checker",
        "wallet-backup-verifier",
        "crypto-credential-scanner",
        "web3-secrets-detector",
        "mnemonic-safety-check",
        "eth-wallet-sentinel",
        "cryptowallet-safety",
        "solidity-deploy-guard",
        "defi-threat-scanner",
        "chain-key-validator",
        "deployment-key-auditor",
    ])
    def test_trapdoor_names_flagged(self, name):
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
