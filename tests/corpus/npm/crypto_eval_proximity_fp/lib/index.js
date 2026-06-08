'use strict';

// Small AES-256-GCM config decryptor. The operator provisions an encrypted
// config blob out of band; the key + iv come from the environment and are never
// shipped in the package. createDecipheriv here is a normal library feature, NOT
// a self-decoding loader — its output is parsed as JSON config, never executed.
const crypto = require('crypto');

function decryptConfig(blob, key, iv) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  const tag = blob.slice(blob.length - 16);
  decipher.setAuthTag(tag);
  let out = decipher.update(blob.slice(0, blob.length - 16));
  out = Buffer.concat([out, decipher.final()]);
  return JSON.parse(out.toString('utf8'));
}

// ---------------------------------------------------------------------------
// Assorted benign helpers below. Their only purpose in this fixture is to push
// the (unrelated) globalThis shim well past the proximity window (600 chars)
// from the decipher call above, so the proximity gate correctly sees NO data
// flow between them. In real packages this kind of distance between a crypto
// helper and a globalThis polyfill is the common case (the ainx /
// expo-apple-utils shape).
// ---------------------------------------------------------------------------

function clampPort(n) {
  n = parseInt(n, 10);
  if (Number.isNaN(n) || n < 1) return 8080;
  if (n > 65535) return 65535;
  return n;
}

function mergeDefaults(cfg, defaults) {
  const out = Object.assign({}, defaults);
  for (const k of Object.keys(cfg || {})) {
    if (cfg[k] !== undefined && cfg[k] !== null) out[k] = cfg[k];
  }
  return out;
}

function redactSecrets(cfg) {
  const copy = Object.assign({}, cfg);
  for (const k of Object.keys(copy)) {
    if (/pass|secret|token|key/i.test(k)) copy[k] = '***';
  }
  return copy;
}

function validateConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') throw new Error('config must be an object');
  if (cfg.port !== undefined) cfg.port = clampPort(cfg.port);
  return cfg;
}

function parseList(s) {
  if (Array.isArray(s)) return s;
  if (typeof s !== 'string') return [];
  return s.split(',').map(function (x) { return x.trim(); }).filter(Boolean);
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise(function (_, reject) {
    timer = setTimeout(function () { reject(new Error('timeout')); }, ms);
  });
  return Promise.race([promise, timeout]).finally(function () { clearTimeout(timer); });
}

function backoff(attempt, baseMs) {
  const base = baseMs || 100;
  return Math.min(base * Math.pow(2, attempt), 30000);
}

// globalThis shim — Function('return this') is the standard cross-runtime way to
// reach the global object. It is the eval-family sink, deliberately far from the
// createDecipheriv above and operating on a constant string, not decrypted bytes.
const globalRef = (function () { return Function('return this')(); })();

module.exports = {
  decryptConfig,
  clampPort,
  mergeDefaults,
  redactSecrets,
  validateConfig,
  parseList,
  withTimeout,
  backoff,
  globalRef,
};
