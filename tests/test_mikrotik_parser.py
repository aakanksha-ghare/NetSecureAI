
import pytest

from app.models.security_baseline import SettingStatus
from app.parsers.mikrotik_parser import parse_mikrotik_config


def test_mikrotik_ssh_enabled():
    config = '/ip service\nadd name="ssh" disabled=no'
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert baseline.vendor == "MikroTik"
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (2,)


def test_mikrotik_ssh_disabled():
    config = '/ip service\nadd name="ssh" disabled=yes'
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_mikrotik_http_enabled():
    config = '/ip service\nadd name="www" disabled=no'
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_mikrotik_http_disabled():
    config = '/ip service\nadd name="www" disabled=yes'
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_mikrotik_conflicting_ssh_entries_return_unknown():
    config = (
        '/ip service\n'
        'add name="ssh" disabled=no\n'
        'add name="ssh" disabled=yes\n'
    )
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.source_lines == (2, 3)


def test_mikrotik_missing_ssh_entry_is_unknown():
    baseline = parse_mikrotik_config("/ip service")
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_mikrotik_remote_logging_detected():
    config = (
        "/system logging action\n"
        'add name="remote-syslog" target=remote '
        "remote=192.0.2.10"
    )
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (2,)


def test_mikrotik_missing_remote_logging_is_unknown():
    baseline = parse_mikrotik_config("/system logging action")
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_mikrotik_ssh_protocol_version_is_unknown():
    baseline = parse_mikrotik_config(
        '/ip service\nadd name="ssh" disabled=no'
    )
    setting = baseline.get_setting("ssh_protocol_version")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_mikrotik_https_is_not_treated_as_http():
    config = '/ip service\nadd name="www-ssl" disabled=no'
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_mikrotik_comments_are_ignored():
    config = (
        "# /ip service\n"
        '/ip service\n'
        '# add name="ssh" disabled=yes\n'
        'add name="ssh" disabled=no'
    )
    baseline = parse_mikrotik_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is True
    assert setting.source_lines == (4,)


@pytest.mark.parametrize("config", ["", "   ", "\n"])
def test_mikrotik_empty_configuration_is_rejected(config):
    with pytest.raises(ValueError, match="must not be empty"):
        parse_mikrotik_config(config)
