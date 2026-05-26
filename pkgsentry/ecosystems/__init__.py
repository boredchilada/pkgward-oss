# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-register all ecosystem adapters on import."""
import pkgsentry.ecosystems.pypi    # noqa: F401
import pkgsentry.ecosystems.crates  # noqa: F401
import pkgsentry.ecosystems.gomod   # noqa: F401
