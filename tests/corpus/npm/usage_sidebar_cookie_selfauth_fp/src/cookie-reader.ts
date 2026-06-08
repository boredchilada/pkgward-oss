import { execFile } from "node:child_process"
import { createDecipheriv, pbkdf2Sync } from "node:crypto"
import { copyFileSync, unlinkSync } from "node:fs"
import { readdir, stat } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import type { OAuthUsageResponse } from "./types"
import { snakeToCamel } from "./oauth-client"

function getChromeCookieDb(): string | null {
  switch (process.platform) {
    case "darwin":
      return join(homedir(), "Library/Application Support/Google/Chrome/Default/Cookies")
    case "linux":
      return join(homedir(), ".config/google-chrome/Default/Cookies")
    default:
      return null
  }
}

function getFirefoxProfilesDir(): string | null {
  switch (process.platform) {
    case "darwin":
      return join(homedir(), "Library/Application Support/Firefox/Profiles")
    case "linux":
      return join(homedir(), ".mozilla/firefox")
    default:
      return null
  }
}

function getChromeDecryptionPassword(): string | null {
  switch (process.platform) {
    case "darwin":
      return null
    case "linux":
      return "peanuts"
    default:
      return null
  }
}

const CHROME_SAFE_STORAGE_SERVICE = "Chrome Safe Storage"
const CLAUDE_DOMAIN = "%claude.ai%"
const SESSION_KEY_COOKIE = "sessionKey"
const SESSION_KEY_PREFIX = "sk-ant-"
const SQLITE_TIMEOUT = 5000
const FETCH_TIMEOUT_MS = 10_000

// ─── Utility ─────────────────────────────────────────────────────────────────

let sqliteDetected: boolean | null = null

export function detectSqlite(): Promise<boolean> {
  if (sqliteDetected !== null) return Promise.resolve(sqliteDetected)
  return new Promise((resolve) => {
    execFile("which", ["sqlite3"], { timeout: 5000 }, (err) => {
      sqliteDetected = !err
      resolve(sqliteDetected)
    })
  })
}

function runSqlite(dbPath: string, query: string): Promise<string | null> {
  const tempPath = join(tmpdir(), `cookie-reader-${Date.now()}.sqlite`)
  try {
    copyFileSync(dbPath, tempPath)
  } catch {
    return Promise.resolve(null)
  }
  return new Promise((resolve) => {
    execFile(
      "sqlite3",
      ["-readonly", tempPath, query],
      { timeout: SQLITE_TIMEOUT },
      (err, stdout) => {
        try { unlinkSync(tempPath) } catch {}
        resolve(err ? null : stdout.trim())
      },
    )
  })
}

function readSecurityPassword(service: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      "/usr/bin/security",
      ["find-generic-password", "-s", service, "-w"],
      { timeout: 5000 },
      (err, stdout) => {
        resolve(err ? null : stdout.trim())
      },
    )
  })
}

// ─── Chrome Cookie Decryption ────────────────────────────────────────────────

/**
 * Decrypt a Chrome "v10" encrypted cookie value on macOS.
 * Algorithm: PBKDF2(SafeStorageKey, "saltysalt", 1003, 16) → AES-128-CBC (IV = 16 spaces)
 */
function decryptChromeCookie(encrypted: Buffer, safeStorageKey: string): string | null {
  try {
    // Chrome macOS v10 format: first 3 bytes are "v10", rest is ciphertext
    if (encrypted.length < 3) return null
    const prefix = encrypted.subarray(0, 3).toString("ascii")
    if (prefix !== "v10") return null

    const ciphertext = encrypted.subarray(3)
    const key = pbkdf2Sync(safeStorageKey, "saltysalt", 1003, 16, "sha1")
    const iv = Buffer.alloc(16, " ") // 16 space characters (0x20)

    const decipher = createDecipheriv("aes-128-cbc", new Uint8Array(key), new Uint8Array(iv))
    const updated = decipher.update(new Uint8Array(ciphertext))
    const final = decipher.final()
    const decrypted = Buffer.concat([new Uint8Array(updated), new Uint8Array(final)])
    return decrypted.toString("utf8")
  } catch {
    return null
  }
}

async function extractChromeCookie(): Promise<string | null> {
  try {
    const dbPath = getChromeCookieDb()
    if (!dbPath) return null

    const hasSqlite = await detectSqlite()
    if (!hasSqlite) return null

    const result = await runSqlite(
      dbPath,
      "SELECT hex(encrypted_value) FROM cookies WHERE host_key LIKE '%claude.ai%' AND name = 'sessionKey' LIMIT 1",
    )
    if (!result) return null

    const hexValue = result.trim()
    if (!hexValue) return null

    const encryptedBuffer = Buffer.from(hexValue, "hex")

    let password: string | null = getChromeDecryptionPassword()
    if (!password) {
      password = await readSecurityPassword(CHROME_SAFE_STORAGE_SERVICE)
    }
    if (!password) return null

    const decrypted = decryptChromeCookie(encryptedBuffer, password)
    if (!decrypted?.startsWith(SESSION_KEY_PREFIX)) return null

    return decrypted
  } catch {
    return null
  }
}

// ─── Firefox Cookie ───────────────────────────────────────────────────────────

async function extractFirefoxCookie(): Promise<string | null> {
  try {
    const hasSqlite = await detectSqlite()
    if (!hasSqlite) return null

    const ffBase = getFirefoxProfilesDir()
    if (!ffBase) return null
    let cookieDb: string | null = null

    try {
      const profiles = await readdir(ffBase)
      for (const profile of profiles) {
        const candidate = join(ffBase, profile, "cookies.sqlite")
        try {
          await stat(candidate)
          cookieDb = candidate
          break
        } catch {
          continue
        }
      }
    } catch {
      return null
    }

    if (!cookieDb) return null

    const result = await runSqlite(
      cookieDb,
      `SELECT value FROM moz_cookies WHERE host LIKE '${CLAUDE_DOMAIN}' AND name = '${SESSION_KEY_COOKIE}' LIMIT 1`,
    )
    if (!result?.startsWith(SESSION_KEY_PREFIX)) return null
    return result
  } catch {
    return null
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Extract Claude sessionKey from Chrome (with decryption) or Firefox.
 * Returns null if not found or sqlite3 unavailable.
 */
export async function extractSessionKey(): Promise<string | null> {
  const chrome = await extractChromeCookie()
  if (chrome) return chrome
  return extractFirefoxCookie()
}

/**
 * Fetch Claude usage data via claude.ai web API using a session cookie.
 */
export async function fetchWebUsage(sessionKey: string): Promise<OAuthUsageResponse | null> {
  const cookie = `${SESSION_KEY_COOKIE}=${sessionKey}`
  const headers = { Cookie: cookie, "Content-Type": "application/json" }

  try {
    const controller1 = new AbortController()
    const t1 = setTimeout(() => controller1.abort(), FETCH_TIMEOUT_MS)
    let orgId: string | null = null

    try {
      const orgResp = await fetch("https://claude.ai/api/organizations", {
        headers,
        signal: controller1.signal,
      })
      clearTimeout(t1)
      if (!orgResp.ok) return null
      const orgs = await orgResp.json() as Array<{ id: string }>
      orgId = orgs?.[0]?.id ?? null
    } catch {
      clearTimeout(t1)
      return null
    }

    if (!orgId) return null

    const controller2 = new AbortController()
    const t2 = setTimeout(() => controller2.abort(), FETCH_TIMEOUT_MS)

    try {
      const usageResp = await fetch(
        `https://claude.ai/api/organizations/${orgId}/usage`,
        { headers, signal: controller2.signal },
      )
      clearTimeout(t2)
      if (!usageResp.ok) return null

      const raw = await usageResp.json() as Record<string, unknown>
      return snakeToCamel(raw) as OAuthUsageResponse
    } catch {
      clearTimeout(t2)
      return null
    }
  } catch {
    return null
  }
}
