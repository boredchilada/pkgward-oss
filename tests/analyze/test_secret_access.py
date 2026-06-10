# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential-store-sweep detection (meoo-* / rookie-security-test stealer family)."""
from __future__ import annotations

from pkgward.analyze.secret_access import analyze_secret_access


def _ids(findings):
    return {f.rule_id for f in findings}


def test_credential_store_sweep_critical(tmp_path):
    # a "form validator" that reads shadow + proc-environ + ssh keys + aws creds
    (tmp_path / "index.js").write_text(
        "const fs=require('fs');\n"
        "fs.readFileSync('/etc/shadow');\n"
        "fs.readFileSync('/proc/1/environ');\n"
        "fs.readFileSync(process.env.HOME+'/.ssh/id_rsa');\n"
        "fs.readFileSync(process.env.HOME+'/.aws/credentials');\n"
    )
    fs = analyze_secret_access(tmp_path)
    sweep = [f for f in fs if f.rule_id == "malware.credential_store_sweep"]
    assert len(sweep) == 1 and sweep[0].severity == "critical"
    assert "malware.etc_shadow_read" in _ids(fs)


def test_k8s_and_env_harvest_counts_as_stores(tmp_path):
    (tmp_path / "s.js").write_text(
        "read('/var/run/secrets/kubernetes.io/serviceaccount/token');\n"
        "const e=Object.keys(process.env);\n"
        "read(home+'/.ssh/id_ed25519');\n"
    )
    assert "malware.credential_store_sweep" in _ids(analyze_secret_access(tmp_path))


def test_single_store_no_sweep(tmp_path):
    # a legit aws helper touches only its own store -> no sweep, no shadow
    (tmp_path / "aws.js").write_text("loadCreds(home+'/.aws/credentials');\n")
    ids = _ids(analyze_secret_access(tmp_path))
    assert "malware.credential_store_sweep" not in ids
    assert "malware.etc_shadow_read" not in ids


def test_etc_shadow_alone_is_high(tmp_path):
    (tmp_path / "x.sh").write_text("cat /etc/shadow\n")
    fs = analyze_secret_access(tmp_path)
    sh = [f for f in fs if f.rule_id == "malware.etc_shadow_read"]
    assert len(sh) == 1 and sh[0].severity == "high"
    assert "malware.credential_store_sweep" not in _ids(fs)


def test_benign_code_clean(tmp_path):
    (tmp_path / "lib.js").write_text("module.exports = (a,b) => a + b;\n")
    assert analyze_secret_access(tmp_path) == []


def test_security_denylist_not_a_sweep(tmp_path):
    # octocode-security-utils style (octocode-mcp 15.0.0 FP): a SecurityRegistry
    # that ENUMERATES credential files as /^...$/ regex literals to IGNORE — the
    # opposite of a harvest. Markers + many anchored regexes => suppressed.
    (tmp_path / "registry.js").write_text(
        "const extraIgnoredFilePatterns = [\n"
        "  /^\\.npmrc$/, /^\\.pypirc$/, /^\\.netrc$/, /^\\.env$/,\n"
        "  /^id_rsa$/, /^known_hosts$/, /^Login Data$/, /^Cookies$/,\n"
        "  /^credentials$/, /^keystore$/, /^\\.git-credentials$/,\n"
        "];\n"
        "class SecurityRegistry {\n"
        "  isIgnoredFile(n){ return extraIgnoredFilePatterns.some(re=>re.test(n)); }\n"
        "}\n"
    )
    ids = _ids(analyze_secret_access(tmp_path))
    assert "malware.credential_store_sweep" not in ids


def test_decoy_markers_without_regex_denylist_still_sweeps(tmp_path):
    # Anti-bypass: a real string-path harvest can't be disarmed just by pasting a
    # denylist marker comment — suppression also requires many anchored filename
    # regexes, which a stealer that READS paths does not carry.
    (tmp_path / "steal.js").write_text(
        "// secretPatterns redact denylist\n"
        "const fs=require('fs');\n"
        "fs.readFileSync(home+'/.aws/credentials');\n"
        "fs.readFileSync(home+'/.ssh/id_rsa');\n"
        "fs.readFileSync(home+'/.npmrc');\n"
        "fs.readFileSync(home+'/.config/gcloud/credential.json');\n"
    )
    assert "malware.credential_store_sweep" in _ids(analyze_secret_access(tmp_path))


def test_decoy_regex_array_plus_string_harvest_still_sweeps(tmp_path):
    # Evasion guard: an attacker can't disarm a real string-path harvest by pasting
    # a decoy regex-literal array next to it. The harvest reads creds as STRING
    # literals (outside any /regex/ array) so they still count toward the sweep.
    (tmp_path / "evil.js").write_text(
        "const extraIgnoredFilePatterns = ["
        + ", ".join(f"/^decoy{i}$/" for i in range(10))
        + "];\n"
        "const fs=require('fs');\n"
        "fs.readFileSync(home+'/.aws/credentials');\n"
        "fs.readFileSync(home+'/.ssh/id_rsa');\n"
        "fs.readFileSync(home+'/.npmrc');\n"
        "fs.readFileSync(home+'/.config/google-chrome/Default/Login Data');\n"
        "exfil(stolen);\n"
    )
    assert "malware.credential_store_sweep" in _ids(analyze_secret_access(tmp_path))
