"""Unit tests for app.runtime_layer.safety: the one gate every outbound probe
(runtime differential tests and the web crawler) is required to pass through.
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest

from app.runtime_layer.safety import (
    SSRFBlocked,
    TargetNotAllowed,
    assert_link_allowed,
    assert_target_allowed,
    resolve_public_ips,
)


@pytest.fixture(autouse=True)
def _isolated_settings():
    from app.config import settings

    prev_allowlist = settings.runtime_target_allowlist
    prev_public = settings.allow_public_targets
    yield settings
    settings.runtime_target_allowlist = prev_allowlist
    settings.allow_public_targets = prev_public


def test_allowlisted_private_host_is_always_allowed(_isolated_settings):
    _isolated_settings.runtime_target_allowlist = "http://vulnapi:8001,http://localhost,http://127.0.0.1"
    _isolated_settings.allow_public_targets = False
    assert assert_target_allowed("http://127.0.0.1:9999") == "http://127.0.0.1:9999"


def test_non_allowlisted_public_host_rejected_when_switch_is_off(_isolated_settings):
    _isolated_settings.runtime_target_allowlist = "http://localhost,http://127.0.0.1"
    _isolated_settings.allow_public_targets = False
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("http://93.184.216.34")


def test_public_ip_literal_allowed_once_switch_is_on(_isolated_settings):
    _isolated_settings.runtime_target_allowlist = "http://localhost,http://127.0.0.1"
    _isolated_settings.allow_public_targets = True
    assert assert_target_allowed("http://93.184.216.34") == "http://93.184.216.34"


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0"],
)
def test_private_and_reserved_ips_are_blocked(host):
    with pytest.raises(SSRFBlocked):
        resolve_public_ips(host)


def test_public_ip_literal_resolves_cleanly():
    assert resolve_public_ips("93.184.216.34") == ["93.184.216.34"]


def test_only_http_and_https_schemes_accepted(_isolated_settings):
    _isolated_settings.allow_public_targets = True
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("ftp://93.184.216.34")
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("file:///etc/passwd")
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("gopher://93.184.216.34")


def test_link_to_a_different_host_is_rejected(_isolated_settings):
    _isolated_settings.allow_public_targets = True
    with pytest.raises(TargetNotAllowed):
        assert_link_allowed("http://attacker.example/", "93.184.216.34")


def test_link_to_private_ip_is_rejected_even_on_authorized_crawl(_isolated_settings):
    _isolated_settings.allow_public_targets = True
    with pytest.raises(TargetNotAllowed):
        assert_link_allowed("http://169.254.169.254/latest/meta-data/", "169.254.169.254")


def test_link_on_the_operator_allowlist_is_always_followed(_isolated_settings):
    _isolated_settings.runtime_target_allowlist = "http://localhost,http://127.0.0.1"
    _isolated_settings.allow_public_targets = False
    assert assert_link_allowed("http://127.0.0.1:8099/anything", "127.0.0.1") == "http://127.0.0.1:8099/anything"


def test_empty_url_rejected():
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("")


def test_unresolvable_host_is_blocked(_isolated_settings):
    _isolated_settings.allow_public_targets = True
    with pytest.raises(SSRFBlocked):
        assert_target_allowed("http://this-host-should-not-resolve.invalid")
