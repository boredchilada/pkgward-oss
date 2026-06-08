# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-register all ecosystem adapters on import."""
import pkgward.ecosystems.pypi    # noqa: F401
import pkgward.ecosystems.crates  # noqa: F401
import pkgward.ecosystems.gomod   # noqa: F401
import pkgward.ecosystems.npm     # noqa: F401
