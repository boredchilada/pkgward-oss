# Security Policy

## Reporting a vulnerability

pkgsentry is a security tool — vulnerabilities in the engine itself, in the detonation sandbox, or in the intel-pack loader could let attackers evade detection or pivot through deployments. We take these seriously.

**Please do not file public GitHub issues for active vulnerabilities.**

Instead, email **`security@cyfar.ca`** with:

- A clear description of the issue
- A proof-of-concept or repro case (a synthetic malicious package, a crafted intel pack, a fuzzed input — whatever demonstrates the problem)
- Affected pkgsentry version(s)
- Your contact info (so we can ask follow-up questions; anonymity is OK if you'd prefer)

We'll acknowledge receipt within 72 hours, give you a tracking handle, and keep you posted on remediation timing. Once a fix is released, we'll coordinate a public disclosure window with you.

## What's in scope

- Engine bugs that produce a false-negative on a malicious package, where the failure is exploitable (e.g., a malformed archive that crashes the scanner mid-extraction, leaving findings unrecorded)
- Detonation sandbox escapes (a package that breaks out of the Docker container)
- Intel-pack loader bugs that let a crafted overlay corrupt or override baseline detection unsafely
- Anything that lets an attacker write arbitrary content to disk via the scan-queue / archive-extraction path
- Credential exposure in logs, error messages, or persisted DB rows

## What's NOT in scope

- **False positives on legitimate packages.** Open a regular issue; we'll triage.
- **False negatives on packages where no current rule covers the technique.** Detection coverage is best-effort and depends on the loaded intel pack. Submit a YARA rule PR.
- **DoS against the scanner via malformed input that the scanner correctly rejects.** Crash-safe error handling is good; making the scanner slower against trivially-detected garbage is generally a fact of life.
- **Vulnerabilities in dependencies you can already see via `pip-audit` / `osv-scanner`.** We treat these as regular bugs and roll fixes in normal releases.
- **Issues with the maintainer's private intel pack content.** That content is not in this repo; reports about it should go to the maintainer directly.

## Disclosure history

This file tracks resolved security reports. Empty as of v0.1.0 — first public release.

## PGP / encrypted communications

If you need to send encrypted reports, request a current PGP key in your initial (unencrypted, content-free) email and we'll respond with a fresh fingerprint.
