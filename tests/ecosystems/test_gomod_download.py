# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.ecosystems.gomod.fetch.download import case_encode


def test_case_encode_lowercase():
    assert case_encode("github.com/foo/bar") == "github.com/foo/bar"


def test_case_encode_uppercase():
    assert case_encode("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


def test_case_encode_mixed():
    assert case_encode("github.com/Azure/go-SDK") == "github.com/!azure/go-!s!d!k"


def test_case_encode_all_upper():
    assert case_encode("ABC") == "!a!b!c"


def test_case_encode_empty():
    assert case_encode("") == ""


def test_case_encode_consecutive_upper():
    assert case_encode("github.com/GoogleCloudPlatform/foo") == "github.com/!google!cloud!platform/foo"
