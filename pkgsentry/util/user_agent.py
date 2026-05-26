# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os

from pkgsentry import __version__

_PROJECT_URL = "https://github.com/boredchilada/pkgsentry-oss"


def user_agent() -> str:
    contact = os.environ.get("PKGSENTRY_CONTACT_EMAIL", "").strip()
    if contact:
        return f"pkgsentry/{__version__} (contact: {contact})"
    return f"pkgsentry/{__version__} (+{_PROJECT_URL})"
