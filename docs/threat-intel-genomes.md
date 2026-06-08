# Malware genomes — manual fingerprinting for the threat-intel pack

`tools/genome.py` is a **manual** tool for turning a known-malicious sample into
threat-intel fingerprints ("genes"). You decide what's malicious; the tool only reads
and hashes bytes — it never executes anything. Output drops straight into the intel
pack's `hashes/known_malicious.jsonl`.

## Why fingerprints, and why three of them

The scanner already hashes every file it scans three ways. A gene is the same three
hashes taken from a *confirmed-malicious* file (and, optionally, the specific malicious
function) so a re-upload / repack / rename of that payload is caught on sight.

| hash | matches | beaten by |
|------|---------|-----------|
| **SHA256** | exact bytes | any change at all |
| **ssdeep** (via `ppdeep`) | near-identical (small edits) — similarity 0–100, match ≥ 70 | heavy rewrites |
| **TLSH** | structurally similar (renames, reordering, added wrapper code) — distance, match ≤ 120 | total rewrites |

TLSH is the workhorse: a renamed-variable variant of a real malicious function measured
TLSH distance **2** (identical is 0; < 40 is a strong match) while its SHA256 changed
completely.

## How matching works (file-level, today)

`analyze/threat_intel.check_file(name, sha256, ssdeep, tlsh)` compares each **scanned
file** against the loaded genes: exact SHA256 → ssdeep ≥ threshold → TLSH ≤ threshold
(campaign-tuned; "promoted" entries use tighter fuzzy thresholds; unreviewed auto-seeds
match on exact SHA256 only). `file_pattern` constrains which scanned filenames a gene
applies to, so a fuzzy hash can't bleed onto unrelated files.

Genes are loaded into the DB from `hashes/known_malicious.jsonl` **at scanner startup**
(`intel.load()`), so adding genes needs a scanner restart to take effect.

### Schema (`known_malicious.jsonl`, one object per line)

```json
{"sha256":"…","ssdeep":"…","tlsh":"…","file_pattern":"demo.py","campaign":"sha67",
 "label":"malicious","description":"…","source":"pkgward-genome"}
```

## Usage

```bash
# run inside the scanner container (it has ppdeep + tlsh + vault access):
#   docker exec pkgward python /app/tools/genome.py <args>

# 1) extract a vaulted sample to a temp dir (static — never executed)
genome.py pull pypi sha67 0.1.2          # prints the dir + candidate files

# 2) inspect: the file's own hashes + the functions it contains (so you can choose)
genome.py inspect <dir>/x/sha67-0.1.2/demo.py

# 3) emit the gene and append it to the PRIVATE overlay pack
genome.py gene <file> --func run_demo --campaign sha67 \
    --description "sha67 — pip-install env/credential exfil" \
    --append /home/pkgward/intel/private/hashes/known_malicious.jsonl
```

- `--func NAME` extracts a function (Python = real AST; JS/Go/Rust = best-effort brace
  match). `--lines A:B` carves an inclusive 1-based range — the universal escape hatch
  for any language/format.
- **stdout** is the pack-ready file-level line (`--append` writes it into the jsonl).
- **stderr** prints the function-level hashes, commented — kept for your records and a
  future function-matcher; they are **not** matched by the pack today (see below).
- Append to **`intel/private/`** (gitignored, mirrors to the `pkgward-intel` repo),
  never the public baseline. Then restart the scanner.

## File-level vs function-level — what's wired and what isn't

The pack matches **whole files**. So:

- **File-level genes** match at scan time today. When the malicious function is most of
  the file (common for droppers), the file gene already catches rename/repack variants.
- **Function-level genes** are *not* matched yet — the scanner never hashes the functions
  of files it scans, so a function seed has nothing to compare against. They're collected
  for analysis (proving two samples share the same malicious logic) and for an eventual
  scan-time function-matcher. Wiring that is the one piece of automation deliberately
  left out — it means extracting + hashing every function of every scanned file.

## Compiled payloads

`--func` needs source. Compiled droppers (e.g. a Windows `.pyd`, IronWorm's UPX-packed
Rust ELF) have no Python source to slice — fingerprint the **whole binary** (file-level)
or carve a byte-range against a disassembly with `--lines`. Source-based npm/PyPI malware
is where function genes shine.
