
import pytest

from app.models.security_baseline import SettingStatus
from app.parsers.aruba_parser import parse_aruba_config


def test_aruba_ssh_server_enabled():
    baseline = parse_aruba_config("ssh server vrf default")
    setting = baseline.get_setting("ssh_service_enabled")

    assert baseline.vendor == "HPE Aruba"
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_aruba_ssh_server_disabled():
    baseline = parse_aruba_config("no ssh server vrf default")
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_aruba_conflicting_ssh_commands_return_unknown():
    config = (
        "ssh server vrf default\n"
        "no ssh server vrf default\n"
    )

    baseline = parse_aruba_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.source_lines == (1, 2)


def test_aruba_https_server_enabled():
    baseline = parse_aruba_config("https-server vrf default")
    setting = baseline.get_setting("https_management_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_aruba_https_server_disabled():
    baseline = parse_aruba_config("no https-server vrf default")
    setting = baseline.get_setting("https_management_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_aruba_conflicting_https_commands_return_unknown():
    config = (
        "https-server vrf default\n"
        "no https-server vrf default\n"
    )

    baseline = parse_aruba_config(config)
    setting = baseline.get_setting("https_management_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_aruba_http_state_remains_unknown():
    baseline = parse_aruba_config("https-server vrf default")
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_aruba_ssh_protocol_version_remains_unknown():
    baseline = parse_aruba_config("ssh server vrf default")
    setting = baseline.get_setting("ssh_protocol_version")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_aruba_remote_logging_detected():
    baseline = parse_aruba_config("logging 192.0.2.10")
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_aruba_missing_logging_is_unknown():
    baseline = parse_aruba_config("ssh server vrf default")
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_aruba_comments_are_ignored():
    baseline = parse_aruba_config(
        "! no ssh server vrf default\n"
        "ssh server vrf default\n"
    )

    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is True
    assert setting.source_lines == (2,)


@pytest.mark.parametrize("config", ["", "   ", "\n"])
def test_aruba_empty_configuration_is_rejected(config):
    with pytest.raises(ValueError, match="must not be empty"):
        parse_aruba_config(config)
