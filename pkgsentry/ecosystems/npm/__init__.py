# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm (JavaScript) ecosystem adapter."""
from pkgsentry.adapter import register
from pkgsentry.ecosystems.npm.adapter import NpmAdapter

register(NpmAdapter())
