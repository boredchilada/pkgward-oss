# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("filename", [
    "index.js", "app.ts", "mod.mjs", "lib.cjs", "main.go", "lib.rs", "setup.sh", "run.ps1",
])
def test_scans_non_python_source(tmp_path, filename):
    (tmp_path / filename).write_text('fetch("abcdefghijklmnop.onion")\n')
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.onion" for f in findings), filename


def test_doc_file_url_skipped(tmp_path):
    # URLs in README/NOTICE/LICENSE etc. are doc links, not IOCs.
    (tmp_path / "README.md").write_text('See http://evil-c2-server.xyz/pwn for details\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_doc_file_ipv4_skipped(tmp_path):
    (tmp_path / "NOTICE.txt").write_text('Contact server at 104.21.45.122\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.ipv4" for f in findings)


def test_same_url_in_code_still_flagged(tmp_path):
    # The doc skip must not leak into real source files.
    (tmp_path / "LICENSE").write_text('http://evil-c2-server.xyz/pwn\n')
    (tmp_path / "mod.py").write_text('URL = "http://evil-c2-server.xyz/pwn"\n')
    findings = analyze_iocs(tmp_path)
    hits = [f for f in findings if f.rule_id == "iocs.url_suspicious"]
    assert len(hits) == 1 and hits[0].file == "mod.py"


def test_onion_in_doc_still_flagged(tmp_path):
    # High-signal IOCs (onion) are notable even in docs.
    (tmp_path / "README.md").write_text(
        "mirror at http://abcdefghij234567abcdefghij234567abcdefghij234567abcd.onion\n"
    )
    findings = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.onion" for f in findings)


def test_security_md_url_skipped(tmp_path):
    # SECURITY.md is a doc; its disclosure URLs are not IOCs.
    (tmp_path / "SECURITY.md").write_text("Report to http://evil-c2-server.xyz/report\n")
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_arbitrary_markdown_is_doc_context(tmp_path):
    # Any .md file is prose — URLs/IPs are doc noise (e.g. authn.md, tls_proxy.md).
    (tmp_path / "authn.md").write_text(
        "proxy via http://goproxy.example-bad.xyz and 104.21.45.122\n"
    )
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id in ("iocs.url_suspicious", "iocs.ipv4") for f in findings)


def test_placeholder_host_port_url_skipped(tmp_path):
    (tmp_path / "config.py").write_text('endpoint = "http://host:port/api"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_rfc2606_example_domain_skipped(tmp_path):
    (tmp_path / "config.py").write_text('url = "http://api.example.com/v1/data"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_placeholder_ip_skipped(tmp_path):
    (tmp_path / "config.py").write_text('host = "1.2.3.4"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.ipv4" for f in findings)
