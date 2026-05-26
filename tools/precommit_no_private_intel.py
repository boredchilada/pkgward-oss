# SPDX-License-Identifier: AGPL-3.0-or-later
"""Block accidental commits of private intel pack content.

The public engine ships a baseline intel pack at `pkgsentry/intel/baseline/`.
The operator's private overlay lives under `intel/` at the repo root and is
gitignored. This hook fails the commit if any path under `intel/` (other than
the gitignore itself) is staged for commit.

Invoked by `.pre-commit-config.yaml` — receives staged file paths as argv.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    blocked: list[str] = []
    for path in argv:
        p = Path(path)
        parts = p.as_posix().split("/")
        if parts and parts[0] == "intel":
            blocked.append(path)

    if blocked:
        sys.stderr.write(
            "Refusing to commit private intel pack files:\n"
            + "".join(f"  {p}\n" for p in blocked)
            + "\nThe `intel/` directory is gitignored on purpose. The public\n"
              "baseline intel pack lives at `pkgsentry/intel/baseline/` and\n"
              "is the only intel content that ships with the open-source engine.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
