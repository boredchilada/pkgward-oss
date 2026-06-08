# SPDX-License-Identifier: AGPL-3.0-or-later
"""A lifecycle hook that directly executes a BUNDLED native binary is the dropper
signature (IronWorm: preinstall ./tools/setup / ./.github/scripts/precheck — a packed
Rust ELF). Regression guard: this must convict, and not fire on a JS launcher."""
from __future__ import annotations

from pkgward.ecosystems.npm.installer import _analyze_bundled_exec

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64


def _pkg(tmp_path, rel, data):
    p = tmp_path / "package" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return tmp_path / "package"


def test_preinstall_runs_bundled_elf_is_critical(tmp_path):
    pkg = _pkg(tmp_path, "tools/setup", ELF)
    f = _analyze_bundled_exec("preinstall", "./tools/setup", pkg, "")
    assert any(x.rule_id == "installer.npm_install_runs_bundled_binary" and x.severity == "critical"
               for x in f), f


def test_disguised_ci_script_elf_is_critical(tmp_path):
    pkg = _pkg(tmp_path, ".github/scripts/precheck", ELF)
    f = _analyze_bundled_exec("preinstall", "./.github/scripts/precheck", pkg, "")
    assert any(x.rule_id == "installer.npm_install_runs_bundled_binary" for x in f)


def test_sh_wrapped_bundled_binary(tmp_path):
    pkg = _pkg(tmp_path, "bin/run", ELF)
    f = _analyze_bundled_exec("postinstall", "sh ./bin/run", pkg, "")
    assert any(x.rule_id == "installer.npm_install_runs_bundled_binary" for x in f)


def test_js_launcher_does_not_fire_binary_rule(tmp_path):
    pkg = _pkg(tmp_path, "install.js", b"console.log('hi')\n")
    f = _analyze_bundled_exec("postinstall", "node ./install.js", pkg, "")
    assert not any(x.rule_id == "installer.npm_install_runs_bundled_binary" for x in f)


def test_benign_tool_command_does_not_fire(tmp_path):
    pkg = tmp_path / "package"; pkg.mkdir()
    f = _analyze_bundled_exec("postinstall", "tsc -p tsconfig.json", pkg, "")
    assert f == []
