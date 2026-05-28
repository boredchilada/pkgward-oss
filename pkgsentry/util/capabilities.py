# SPDX-License-Identifier: AGPL-3.0-or-later
"""Optional native-dependency probe for the detection tiers.

`yara`, `ppdeep`, and `tlsh` are C/C++ extensions: each can install but fail to
import (the py-tlsh incident). A missing one silently disables a detection tier,
so probing is centralised here — imported once, with a single startup line
(`log_capabilities`) reporting which tiers are live. Consumers read the exposed
module handle (or its `HAS_*` flag) instead of repeating their own guarded import.
"""
from __future__ import annotations

from pkgsentry.logging_setup import get_logger

log = get_logger("capabilities")

try:
    import yara  # type: ignore
except ImportError:
    yara = None  # type: ignore

try:
    import ppdeep  # type: ignore
except ImportError:
    ppdeep = None  # type: ignore

try:
    import tlsh  # type: ignore
except ImportError:
    tlsh = None  # type: ignore

HAS_YARA = yara is not None
HAS_PPDEEP = ppdeep is not None
HAS_TLSH = tlsh is not None


def capabilities() -> dict[str, bool]:
    return {"yara": HAS_YARA, "ppdeep": HAS_PPDEEP, "tlsh": HAS_TLSH}


def log_capabilities() -> dict[str, bool]:
    """Emit one startup line stating which detection tiers loaded.

    Logs at WARNING (not INFO) when any tier is missing so a silently-dead
    capability is visible in prod logs rather than discovered weeks later.
    """
    caps = capabilities()
    missing = sorted(k for k, v in caps.items() if not v)
    if missing:
        log.warning("detection_capabilities", missing=missing, **caps)
    else:
        log.info("detection_capabilities", **caps)
    return caps
