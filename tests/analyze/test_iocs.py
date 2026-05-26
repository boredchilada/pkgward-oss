# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from pkgsentry.analyze.iocs import analyze_iocs


def test_url_detection_suspicious(tmp_path):
    (tmp_path / "a.py").write_text('URL = "http://evil-c2-server.xyz/pwn"\n')
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.url_suspicious" and "evil" in f.evidence for f in findings)


def test_url_benign_whitelisted(tmp_path):
    (tmp_path / "a.py").write_text('URL = "https://github.com/user/repo"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_ipv4_detection(tmp_path):
    # Pick an IP outside the RFC 5737 documentation ranges (192.0.2/0, 198.51.100/0,
    # 203.0.113/0), which the scanner intentionally skips as tutorial placeholders.
    (tmp_path / "a.py").write_text('HOST = "104.21.45.122"\n')
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.ipv4" for f in findings)


def test_ipv4_skip_rfc5737_documentation(tmp_path):
    (tmp_path / "a.py").write_text('EXAMPLE = "203.0.113.5"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.ipv4" for f in findings)


def test_onion_detection(tmp_path):
    (tmp_path / "a.py").write_text('X = "abcdefghijklmnop.onion"\n')
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.onion" for f in findings)


def test_base64_long_blob(tmp_path):
    blob = "A" * 200 + "=="
    (tmp_path / "a.py").write_text(f'B = "{blob}"\n')
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.base64_blob" for f in findings)


def test_skip_pyc_and_binaries(tmp_path):
    (tmp_path / "a.pyc").write_bytes(b"binary garbage \x00\x01\x02")
    findings = analyze_iocs(tmp_path)
    assert findings == []
