# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io ecosystem adapter."""
from pkgsentry.adapter import register
from pkgsentry.ecosystems.crates.adapter import CratesAdapter

register(CratesAdapter())
