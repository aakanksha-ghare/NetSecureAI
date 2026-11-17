
import pytest

from app.models.security_baseline import SettingStatus
from app.parsers.checkpoint_parser import parse_checkpoint_config


def test_checkpoint_ssh_server_enabled():
    baseline = parse_checkpoint_config(
        "set ssh server enable"
    )

    setting = baseline.get_setting("ssh_service_enabled")

    assert baseline.vendor == "Check Point"
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_checkpoint_ssh_server_disabled():
    baseline = parse_checkpoint_config(
        "set ssh server disable"
    )

    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_checkpoint_conflicting_ssh_commands_return_unknown():
    config = """\
set ssh server enable
set ssh server disable
"""

    baseline = parse_checkpoint_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.source_lines == (1, 2)


def test_checkpoint_remote_syslog_is_detected():
    baseline = parse_checkpoint_config(
        "set syslog log-remote-address 192.0.2.10"
    )

    setting = baseline.get_setting("logging_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_checkpoint_missing_syslog_is_unknown():
    baseline = parse_checkpoint_config(
        "set ssh server enable"
    )

    setting = baseline.get_setting("logging_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_checkpoint_http_state_remains_unknown():
    baseline = parse_checkpoint_config(
        "set ssh server enable"
    )

    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_checkpoint_ssh_protocol_version_remains_unknown():
    baseline = parse_checkpoint_config(
        "set ssh server enable"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


@pytest.mark.parametrize("config", ["", "   ", "\n"])
def test_checkpoint_empty_configuration_is_rejected(config):
    with pytest.raises(ValueError, match="must not be empty"):
        parse_checkpoint_config(config)


def test_checkpoint_ignores_comments():
    baseline = parse_checkpoint_config(
        "# set ssh server disable\n"
        "set ssh server enable\n"
    )

    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is True
    assert setting.source_lines == (2,)
