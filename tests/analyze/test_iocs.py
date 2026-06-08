# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest

from pkgward.analyze.iocs import analyze_iocs


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
from pkgward.analyze.iocs import _is_oast_url


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


def test_test_file_downweights_hardcoded_ip_port(tmp_path):
    # A routable IP:port in a *_test.go fixture is test data, not a C2 beacon:
    # the finding still fires but is down-weighted to low so it can't drive a verdict.
    (tmp_path / "plugin_test.go").write_text('addr := "2.1.0.10:1234"\n')
    findings = analyze_iocs(tmp_path)
    hits = [f for f in findings if f.rule_id == "iocs.hardcoded_wan_ip_port"]
    assert hits and all(f.severity == "low" for f in hits)


def test_prod_file_keeps_hardcoded_ip_port_high(tmp_path):
    # Same content in a production file stays high — no blind spot for real code.
    (tmp_path / "plugin.go").write_text('addr := "2.1.0.10:1234"\n')
    findings = analyze_iocs(tmp_path)
    hits = [f for f in findings if f.rule_id == "iocs.hardcoded_wan_ip_port"]
    assert hits and any(f.severity == "high" for f in hits)


def test_test_file_suppresses_url_and_ip_noise(tmp_path):
    (tmp_path / "helm_test.go").write_text(
        'u := "https://docs.solo.io/x"\nip := "130.211.204.1"\n')
    ids = {f.rule_id for f in analyze_iocs(tmp_path)}
    assert "iocs.url_suspicious" not in ids and "iocs.ipv4" not in ids


def test_testdata_dir_treated_as_test(tmp_path):
    d = tmp_path / "testdata"
    d.mkdir()
    (d / "config.yaml").write_text('endpoint: "2.1.0.10:8080"\n')
    hits = [f for f in analyze_iocs(tmp_path) if f.rule_id == "iocs.hardcoded_wan_ip_port"]
    assert hits and all(f.severity == "low" for f in hits)


def _scan_bytes(tmp_path, b):
    from pkgward.analyze.iocs import _scan_file
    f = tmp_path / "f.js"
    f.write_bytes(b)
    return [x.rule_id for x in _scan_file(f)]


def test_decode_engine_multilayer_url(tmp_path):
    """The recursive engine catches a URL the single-layer pass can't: b64(gzip(b64()))."""
    import base64, gzip
    inner = base64.b64encode(b'fetch("http://evil.tld/c2")')
    payload = base64.b64encode(gzip.compress(inner))
    assert "iocs.encoded_url" in _scan_bytes(tmp_path, b'var x="' + payload + b'"')


def _scan_named(tmp_path, name, b):
    """Scan raw bytes written to a chosen filename; return Findings (severity-aware)."""
    from pkgward.analyze.iocs import _scan_file
    f = tmp_path / name
    f.write_bytes(b)
    return list(_scan_file(f))


def _b64_elf():
    import base64
    return base64.b64encode(b"\x7fELF" + b"\x02\x01\x01\x00" * 200)


def test_decode_engine_recovers_hidden_executable_with_sink_is_dropper(tmp_path):
    """Embedded native binary + an execution sink in the SAME file = the dropper shape
    (decode -> write -> execute) -> critical."""
    body = b'const b="' + _b64_elf() + b'";\nrequire("child_process").execSync(cmd);\n'
    hits = [f for f in _scan_named(tmp_path, "loader.js", body)
            if f.rule_id == "iocs.decoded_executable"]
    assert hits and all(f.severity == "critical" for f in hits)


def test_embedded_binary_no_exec_sink_is_not_dropper(tmp_path):
    """A binary decoded to be parsed/shipped (no execution primitive anywhere in the file)
    is an embedded resource, not a dropper — fire but at medium, can't drive a verdict.
    (cert/installer tooling that base64s a binary to inspect it.)"""
    body = b'const b="' + _b64_elf() + b'";\nparsePE(b);\n'
    hits = [f for f in _scan_named(tmp_path, "parse.js", body)
            if f.rule_id == "iocs.decoded_executable"]
    assert hits and all(f.severity == "medium" for f in hits)


def test_embedded_binary_in_test_file_is_fixture(tmp_path):
    """The smallstep/cli winpe_test.go FP: a *_test.go that decodes a PE to test PE
    parsing, with no exec sink, is fixture data -> low, never critical."""
    body = b'var ChromeExe = []byte(`' + _b64_elf() + b'`)\n_ = extractPE(name)\n'
    hits = [f for f in _scan_named(tmp_path, "winpe_test.go", body)
            if f.rule_id == "iocs.decoded_executable"]
    assert hits and all(f.severity == "low" for f in hits)


def test_decode_engine_recovers_hidden_executable(tmp_path):
    """Rule still fires (at some severity) on a bare embedded binary — presence check."""
    assert "iocs.decoded_executable" in _scan_bytes(tmp_path, b'const b="' + _b64_elf() + b'"')


def test_decode_engine_ignores_benign_base64(tmp_path):
    """Benign base64 data (no URL/code/exe) must NOT fire decoded_* (the fazzgram class)."""
    import base64
    blob = base64.b64encode(b"just some serialized framework strings: Context dispatcher getMe")
    rids = _scan_bytes(tmp_path, b'var d="' + blob + b'"')
    assert "iocs.decoded_executable" not in rids
    assert "iocs.decoded_code" not in rids


def test_decode_no_fp_on_reverse_reverse_source(tmp_path):
    """The flood bug: reverse->reverse is identity, 'recovering' visible source whose
    require()/function() tokens are NOT a hidden payload. Must be silent."""
    src = b"const x = require('lodash');\nfunction handler(){ return doStuff(); }\n" * 30
    rids = _scan_bytes(tmp_path, src)
    assert "iocs.decoded_code" not in rids
    assert "iocs.decoded_executable" not in rids


def test_decoded_code_needs_real_sink_not_just_code_tokens(tmp_path):
    """base64 of benign code (a bundle chunk / source map) has require()/function() but no
    execution sink — must NOT fire decoded_code."""
    import base64
    blob = base64.b64encode(b"function helper(){ return config.value }")
    assert "iocs.decoded_code" not in _scan_bytes(tmp_path, b'var d="' + blob + b'"')


def test_decoded_code_fires_on_real_encoded_eval_loader(tmp_path):
    """b64(gzip(b64('eval(payload)'))) — a real encoding chain decoding to an exec sink."""
    import base64, gzip
    p = base64.b64encode(gzip.compress(base64.b64encode(b"eval(maliciousPayload)")))
    assert "iocs.decoded_code" in _scan_bytes(tmp_path, b'var p="' + p + b'"')
