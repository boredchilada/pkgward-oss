# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioral chain rule registry.

The full set of chain IDs is data-driven (loaded from the intel pack's
`behavioral_chains.toml`). The DYNAMIC_CHAIN_RULES subset is kept as a
hardcoded label here because it identifies rules that fire from the
detonation sandbox specifically — a code-side categorisation, not a tuning
choice.

Consumers can do either of:
    from pkgsentry.detect.rules import BEHAVIORAL_CHAIN_RULES   # lazy via __getattr__
    from pkgsentry.detect.rules import behavioral_chain_rules    # function form
"""
from __future__ import annotations

DYNAMIC_CHAIN_RULES: set[str] = {
    "dyn_install_exfil",
    "dyn_reverse_shell",
    "dyn_proc_inject",
}


def behavioral_chain_rules() -> set[str]:
    from pkgsentry import intel
    return set(intel.current().behavioral_chain_ids)


def __getattr__(name: str):
    if name == "BEHAVIORAL_CHAIN_RULES":
        return behavioral_chain_rules()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
