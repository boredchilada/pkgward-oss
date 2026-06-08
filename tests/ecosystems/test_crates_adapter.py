# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgward.adapter import adapter_registry
import pkgward.ecosystems.crates  # noqa: F401


def test_crates_adapter_registered():
    assert "crates" in adapter_registry


def test_crates_adapter_properties():
    adapter = adapter_registry["crates"]
    assert adapter.ecosystem_id == "crates"
    assert adapter.install_archive_kind == "crate"
    assert adapter.strips_top_dir is True
