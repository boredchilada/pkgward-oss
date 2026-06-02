# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential-store-sweep detection (meoo-* / rookie-security-test stealer family)."""
from __future__ import annotations

from pkgsentry.analyze.secret_access import analyze_secret_access


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
