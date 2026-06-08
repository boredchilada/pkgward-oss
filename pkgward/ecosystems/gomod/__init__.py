# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go modules ecosystem adapter."""
from pkgward.adapter import register
from pkgward.ecosystems.gomod.adapter import GoModAdapter

register(GoModAdapter())
