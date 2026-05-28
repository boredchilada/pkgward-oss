# SPDX-License-Identifier: AGPL-3.0-or-later
import os

from pkgsentry.analyze.entropy import analyze_entropy


def test_cert_extension_skipped(tmp_path):
    # A PKCS#12 cert is encrypted-by-spec (near-max entropy) but benign; the
    # binary cert/keystore extensions must not fire entropy.obfuscated_payload.
    (tmp_path / "dev-cert.pfx").write_bytes(os.urandom(2048))
    findings = analyze_entropy(tmp_path)
    assert not any(f.rule_id == "entropy.obfuscated_payload" for f in findings)


def test_high_entropy_python_still_flagged(tmp_path):
    # Random bytes in a .py still trip the rule (cert skip must not leak).
    (tmp_path / "payload.py").write_bytes(os.urandom(2048))
    findings = analyze_entropy(tmp_path)
    assert any(f.rule_id == "entropy.obfuscated_payload" for f in findings)


def test_large_file_skipped(tmp_path, monkeypatch):
    # Files above the size cap (big prebuilt binaries) are skipped — no entropy
    # crawl. Shrink the cap so the test stays fast.
    import pkgsentry.analyze.entropy as ent_mod
    monkeypatch.setattr(ent_mod, "MAX_FILE_SIZE", 1024)
    (tmp_path / "big.bin").write_bytes(os.urandom(4096))  # > cap, high entropy
    findings = analyze_entropy(tmp_path)
    assert not any(f.rule_id == "entropy.obfuscated_payload" for f in findings)


def test_under_cap_still_scanned(tmp_path, monkeypatch):
    import pkgsentry.analyze.entropy as ent_mod
    monkeypatch.setattr(ent_mod, "MAX_FILE_SIZE", 1024 * 1024)
    (tmp_path / "small.py").write_bytes(os.urandom(2048))  # under cap
    findings = analyze_entropy(tmp_path)
    assert any(f.rule_id == "entropy.obfuscated_payload" for f in findings)
