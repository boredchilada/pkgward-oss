# Contributing to pkgsentry

Thanks for considering a contribution. pkgsentry catches supply-chain malware in package registries — the more eyes on the engine, the harder it is for attackers to hide.

## Ground rules

- **DCO required.** Every commit must carry a `Signed-off-by:` trailer (`git commit -s`). See [DCO](#dco-developer-certificate-of-origin) below. PRs without DCO are blocked by the [probot/dco](https://github.com/apps/dco) bot.
- **No PII in test fixtures or examples.** Use synthetic data. If you're adding a new YARA rule with a real-world reference, cite the public writeup (Phylum / ReversingLabs / Unit42 / etc.); don't paste live credentials or attribution-stripped malware samples.
- **No hardcoded secrets.** Use env vars + `.env.example`. The repo has `gitleaks` running in pre-commit; commits with secret-like strings will fail to push.
- **No private intel content in baseline.** The public baseline pack (`pkgsentry/intel/baseline/`) ships generic, publicly-derivable detection content. Operator-tuned content — full IOC whitelists, complete keyword categories, threat-intel hash seeds, tuned scoring thresholds — belongs in a private overlay pack loaded via `PKGSENTRY_INTEL_PATH`, not in this repo.

## Development setup

```bash
git clone https://github.com/boredchilada/pkgsentry-oss
cd pkgsentry-oss

# Python env
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install pytest ruff black pre-commit

# Pre-commit hooks
pre-commit install

# Run the test suite
.venv/bin/pytest tests/ -x -q

# Go detonation service (optional — only needed if you touch the sandbox)
cd detonation && go test ./... && go build ./...
```

## How to add an analyzer

Analyzers live in `pkgsentry/analyze/`. Each is a module exporting a single `analyze_<name>(extracted_root: Path, changed_files: set[str] | None) -> list[Finding]` function:

```python
from pkgsentry.adapter import Finding

CATEGORY = "<category>"

def analyze_<name>(extracted_root, changed_files=None):
    findings: list[Finding] = []
    for p in extracted_root.rglob("*.py"):
        if not p.is_file():
            continue
        if changed_files is not None and p.relative_to(extracted_root).as_posix() not in changed_files:
            continue
        # ... your detection logic ...
        findings.append(Finding(
            rule_id="<category>.<rule_name>",
            category=CATEGORY,
            severity="low" | "medium" | "high" | "critical",
            confidence="low" | "medium" | "high",
            file=str(p.relative_to(extracted_root)),
            line=None,
            evidence="<short, defangable evidence string>",
        ))
    return findings
```

Wire the analyzer into the pipeline at `pkgsentry/pipeline.py::_run_analyzers`. Add a unit test under `tests/analyze/` that exercises both positive and negative cases. Aim for finding-level high confidence; false-positive sensitivity matters more than coverage.

## How to add a YARA rule

Public, well-documented patterns belong in `pkgsentry/intel/baseline/yara/python_baseline.yar` (or `rust_baseline.yar`). Rule template:

```yara
rule <rule_name>
{
    meta:
        description = "<one-line summary of the malware behavior>"
        severity = "low" | "medium" | "high" | "critical"
        confidence = "low" | "medium" | "high"
        author = "<your name or handle>"
        reference = "<public technical writeup URL>"

    strings:
        $a = "..."
        // ...

    condition:
        // require multiple distinct signals — single-string rules are usually
        // too noisy for production
        2 of them
}
```

Submit a fixture sample under `tests/fixtures/yara/<rule_name>/` with at least one positive (real-world-ish) and one negative (legitimate code that resembles the pattern) input.

## How to propose intel-pack schema changes

The intel pack format is defined in `pkgsentry/intel/pack.py` and validated in `pkgsentry/intel/schema.py`. Schema changes need:

1. A backwards-compatible migration story for existing private overlays
2. Schema docs in `docs/intel-pack.md`
3. A test in `tests/intel/` covering both old and new formats

## DCO (Developer Certificate of Origin)

We use the DCO instead of a CLA. The DCO is a simple statement that you wrote the code (or have the right to contribute it) and that you agree to license it under the project's Apache 2.0 license.

To sign off:
```bash
git commit -s -m "your commit message"
```

This appends a trailer like:
```
Signed-off-by: Your Name <your.email@example.com>
```

The probot/dco bot will block PRs without sign-off and link to the fix. If you forgot to sign earlier commits in a branch:
```bash
git rebase --signoff HEAD~<N>
```

Full DCO text: [developercertificate.org](https://developercertificate.org).

## Reporting bugs

For non-security bugs, open a GitHub issue with:
- pkgsentry version (`pkgsentry --version`)
- Python / Go versions if relevant
- Steps to reproduce
- Expected vs actual behavior
- Relevant log lines (especially the `intel_loaded` line and any `scan_done` lines)

For security issues, see [SECURITY.md](SECURITY.md). Do not file public issues for active vulnerabilities.

## License

By contributing, you agree your contribution is licensed under the [Apache License 2.0](LICENSE).
