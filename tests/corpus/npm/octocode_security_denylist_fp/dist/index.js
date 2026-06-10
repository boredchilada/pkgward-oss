// octo-secure-mcp — a GitHub code-search MCP server (synthetic FP fixture).
// Mirrors octocode-mcp 15.0.0: a security-utils denylist of credential files the
// agent REFUSES to read, at-rest encryption of the user's own GitHub token, and
// octokit-based GitHub Contents API usage. None of these is a stealer; the file
// must score CLEAN.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readdirSync, statSync } from "node:fs";
import { Octokit } from "@octokit/core";

// Benign globalThis shim. Kept far from any crypto and never wired to a decode,
// so it is not a self-decoding eval loader.
const _root =
  typeof globalThis !== "undefined" ? globalThis : Function("return this")();

// ---------------------------------------------------------------------------
// SecurityRegistry: files/paths this agent must NEVER read or hand to an LLM.
// These are IGNORE/redact patterns (a denylist) — enumerated as regex literals,
// not read targets. A stealer constructs string paths and reads them; a denylist
// lists "/^...$/" patterns so the agent can skip them.
// ---------------------------------------------------------------------------
const extraIgnoredFilePatterns = [
  /^\.npmrc$/,
  /^\.pypirc$/,
  /^\.netrc$/,
  /^\.env$/,
  /^\.env\..+$/,
  /^id_rsa$/,
  /^id_ed25519$/,
  /^known_hosts$/,
  /^authorized_keys$/,
  /^Login Data$/,
  /^Cookies$/,
  /^credentials$/,
  /^keystore$/,
  /^\.git-credentials$/,
  /^\.htpasswd$/,
  /^auth\.json$/,
];
const extraIgnoredPathPatterns = [
  /(?:^|\/)\.ssh(?:\/|$)/,
  /(?:^|\/)\.aws(?:\/|$)/,
  /(?:^|\/)\.gnupg(?:\/|$)/,
];
const secretPatterns = [/ghp_[A-Za-z0-9]{36}/, /AKIA[0-9A-Z]{16}/];

class SecurityRegistry {
  constructor() {
    this.extraIgnoredFilePatterns = extraIgnoredFilePatterns;
    this.extraIgnoredPathPatterns = extraIgnoredPathPatterns;
    this.secretPatterns = secretPatterns;
  }
  isIgnoredFile(name) {
    return this.extraIgnoredFilePatterns.some((re) => re.test(name));
  }
  isIgnoredPath(p) {
    return this.extraIgnoredPathPatterns.some((re) => re.test(p));
  }
  redact(text) {
    let out = text;
    for (const re of this.secretPatterns) out = out.replace(re, "***MASKED***");
    return out;
  }
}
const registry = new SecurityRegistry();

// ---------------------------------------------------------------------------
// At-rest encryption of the user's OWN GitHub token. The key is generated per
// install via randomBytes(32) — NOT hardcoded. The stored blob is
// "iv:authTag:ciphertext" (all hex), decrypted with Buffer.from(x,"hex"), and the
// plaintext feeds JSON.parse — never eval.
// ---------------------------------------------------------------------------
const TOKEN_KEY = randomBytes(32);

function encryptToken(plaintext) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", TOKEN_KEY, iv);
  let ct = c.update(plaintext, "utf8", "hex");
  ct += c.final("hex");
  return `${iv.toString("hex")}:${c.getAuthTag().toString("hex")}:${ct}`;
}

function decryptToken(blob) {
  const [ivHex, tagHex, ct] = blob.split(":");
  const d = createDecipheriv("aes-256-gcm", TOKEN_KEY, Buffer.from(ivHex, "hex"));
  d.setAuthTag(Buffer.from(tagHex, "hex"));
  return JSON.parse(d.update(ct, "hex", "utf8") + d.final("utf8"));
}

// ---------------------------------------------------------------------------
// GitHub Contents API via the octokit library (a real client, not a hand-rolled
// raw PUT). Used to write generated docs back to a user-chosen repo.
// ---------------------------------------------------------------------------
const octokit = new Octokit({ baseUrl: "https://api.github.com" });
const PUT_ROUTE = "PUT /repos/{owner}/{repo}/contents/{path}";

async function putFile(owner, repo, path, content) {
  return octokit.request(PUT_ROUTE, {
    owner,
    repo,
    path,
    message: "docs: update",
    content: Buffer.from(content).toString("base64"),
  });
}

function listLocalFiles(dir) {
  return readdirSync(dir).filter((f) => {
    if (registry.isIgnoredFile(f)) return false; // never touch denylisted files
    return statSync(`${dir}/${f}`).isFile();
  });
}

export { registry, encryptToken, decryptToken, putFile, listLocalFiles };
