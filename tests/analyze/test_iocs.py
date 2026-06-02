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


# ── OAST / out-of-band-interaction callback domains (high) ──────────
from pkgsentry.analyze.iocs import _is_oast_url


def test_oast_callback_detected_high(tmp_path):
    # the real adminui-deps C2 (subdomain of oastify.com)
    (tmp_path / "index.js").write_text(
        'const U = "https://zkn54ofrehcbk9jnc2fvocuvfmld93xs.oastify.com/detox56";\n')
    findings = analyze_iocs(tmp_path)
    oast = [f for f in findings if f.rule_id == "iocs.oast_callback"]
    assert len(oast) == 1
    assert oast[0].severity == "high"
    # must NOT also be double-reported as a low url_suspicious
    assert not any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_oast_various_services(tmp_path):
    (tmp_path / "a.js").write_text(
        'a="http://x.interact.sh/p"; b="https://abc.burpcollaborator.net/"; '
        'c="https://q.dnslog.cn/x"; d="https://foo.oast.fun/cb";\n')
    findings = analyze_iocs(tmp_path)
    assert sum(f.rule_id == "iocs.oast_callback" for f in findings) == 4


def test_dualuse_webhook_services_not_oast(tmp_path):
    # dual-use HTTP-mock/webhook services are NOT escalated to oast_callback (they
    # FP'd on benign test fixtures); they still surface as low url_suspicious.
    (tmp_path / "b.js").write_text(
        'a="https://abc.webhook.site/u"; b="https://x.beeceptor.com/"; '
        'c="https://y.pipedream.net/"; d="https://z.requestbin.net/"\n')
    findings = analyze_iocs(tmp_path)
    assert not any(f.rule_id == "iocs.oast_callback" for f in findings)
    assert any(f.rule_id == "iocs.url_suspicious" for f in findings)


def test_is_oast_url_matching():
    assert _is_oast_url(b"https://sub.oastify.com/x") is True
    assert _is_oast_url(b"https://oast.fun/cb") is True
    assert _is_oast_url(b"https://canarytokens.com/abc") is True
    # not OAST — normal-ish suspicious host, and a lookalike that only contains the token in the path
    assert _is_oast_url(b"https://evil-c2-server.xyz/pwn") is False
    assert _is_oast_url(b"https://example.com/oastify.com/path") is False
    # dual-use dev tunnel deliberately excluded
    assert _is_oast_url(b"https://abc.ngrok.io/x") is False


def _ids(findings):
    return {f.rule_id for f in findings}


def test_hardcoded_wan_ip_port_high(tmp_path):
    # C2-beacon shape: routable IP + explicit port (legit code uses DNS hostnames)
    (tmp_path / "a.js").write_text('const C2 = "195.201.194.107:8010"; connect(C2)\n')
    fs = analyze_iocs(tmp_path)
    hit = [f for f in fs if f.rule_id == "iocs.hardcoded_wan_ip_port"]
    assert len(hit) == 1 and hit[0].severity == "high"
    assert "195.201.194.107:8010" in hit[0].evidence


def test_cloud_metadata_ssrf_flagged(tmp_path):
    (tmp_path / "a.py").write_text(
        'import urllib.request\n'
        'urllib.request.urlopen("http://169.254.169.254/latest/meta-data/iam/")\n'
        'urllib.request.urlopen("http://169.254.170.2/v2/credentials")\n'
    )
    fs = analyze_iocs(tmp_path)
    meta = [f for f in fs if f.rule_id == "iocs.cloud_metadata_endpoint"]
    assert {f.evidence.split()[3] for f in meta} == {"169.254.169.254", "169.254.170.2"}
    assert all(f.severity == "medium" for f in meta)


def test_benign_dns_resolver_with_port_not_c2(tmp_path):
    # public DNS resolvers are public but not C2 — must not raise the high signal
    (tmp_path / "a.js").write_text('const r = "8.8.8.8:53";\n')
    assert "iocs.hardcoded_wan_ip_port" not in _ids(analyze_iocs(tmp_path))


def test_private_and_doc_ips_skipped(tmp_path):
    (tmp_path / "a.js").write_text(
        'lan="192.168.1.5:8080"; ten="10.0.0.1:22"; doc="203.0.113.9:443";\n'
    )
    ids = _ids(analyze_iocs(tmp_path))
    assert "iocs.hardcoded_wan_ip_port" not in ids
    assert "iocs.ipv4" not in ids  # all private/doc -> nothing


def test_public_ip_without_port_stays_low(tmp_path):
    (tmp_path / "a.js").write_text('const s = "45.77.12.34";\n')
    fs = analyze_iocs(tmp_path)
    assert "iocs.hardcoded_wan_ip_port" not in _ids(fs)
    assert any(f.rule_id == "iocs.ipv4" and f.severity == "low" for f in fs)


def test_decode_base64_hidden_c2_ip(tmp_path):
    import base64
    blob = base64.b64encode(b"195.201.194.107:8010").decode()
    (tmp_path / "a.js").write_text(f'const x = "{blob}";\n')
    fs = analyze_iocs(tmp_path)
    enc = [f for f in fs if f.rule_id == "iocs.encoded_ip"]
    assert len(enc) == 1 and enc[0].severity == "high"
    assert "195.201.194.107" in enc[0].evidence


def test_decode_base64_hidden_url(tmp_path):
    import base64
    blob = base64.b64encode(b"http://evil-c2.xyz/payload").decode()
    (tmp_path / "a.js").write_text(f'const x = "{blob}";\n')
    fs = analyze_iocs(tmp_path)
    assert any(f.rule_id == "iocs.encoded_url" and "evil-c2.xyz" in f.evidence for f in fs)


def test_decode_xesc_hidden_ip(tmp_path):
    # \xNN-escaped "195.201.194.107"
    esc = "".join(f"\\x{b:02x}" for b in b"45.77.12.34")
    (tmp_path / "a.js").write_text(f'var s = "{esc}";\n')
    assert any(f.rule_id == "iocs.encoded_ip" for f in analyze_iocs(tmp_path))


def test_decode_benign_base64_no_fp(tmp_path):
    import base64
    blob = base64.b64encode(b"visit https://github.com/user/repo for the docs ok").decode()
    (tmp_path / "a.js").write_text(f'const g = "{blob}";\n')
    ids = {f.rule_id for f in analyze_iocs(tmp_path)}
    assert "iocs.encoded_url" not in ids  # benign domain whitelisted
    assert "iocs.encoded_ip" not in ids


def test_decode_nonprintable_blob_skipped(tmp_path):
    import base64
    blob = base64.b64encode(bytes(range(0, 32)) * 4).decode()  # control bytes -> not printable
    (tmp_path / "a.js").write_text(f'const k = "{blob}";\n')
    ids = {f.rule_id for f in analyze_iocs(tmp_path)}
    assert "iocs.encoded_url" not in ids and "iocs.encoded_ip" not in ids
