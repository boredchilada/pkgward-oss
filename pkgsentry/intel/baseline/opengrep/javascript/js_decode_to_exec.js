// opengrep --test fixtures for js_decode_to_exec.

const cp = require("child_process");

function bad1() {
  const payload = Buffer.from("Y3VybCBldmlsLmNvbQ==", "base64").toString();
  // ruleid: js_decode_to_exec
  eval(payload);
}

function bad2() {
  const s = atob("Y29uc29sZS5sb2coMSk=");
  // ruleid: js_decode_to_exec
  new Function(s)();
}

function ok1() {
  const cfg = Buffer.from("eyJhIjoxfQ==", "base64").toString();
  // ok: js_decode_to_exec
  return JSON.parse(cfg);
}

function ok2() {
  // ok: js_decode_to_exec
  cp.execSync("tsc --build");
}
