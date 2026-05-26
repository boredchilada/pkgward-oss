# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go modules ecosystem adapter."""
from pkgsentry.adapter import register
from pkgsentry.ecosystems.gomod.adapter import GoModAdapter

register(GoModAdapter())
