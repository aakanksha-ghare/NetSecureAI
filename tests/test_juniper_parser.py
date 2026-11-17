
import pytest

from app.models.security_baseline import SettingStatus
from app.parsers.juniper_parser import parse_juniper_config


def test_juniper_parser_identifies_ssh_protocol_version_2():
    baseline = parse_juniper_config(
        "set system services ssh protocol-version v2"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert baseline.vendor == "Juniper"
    assert setting is not None
    assert setting.value == 2
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)
    assert setting.evidence == (
        "set system services ssh protocol-version v2",
    )


def test_juniper_parser_identifies_ssh_protocol_version_1():
    baseline = parse_juniper_config(
        "set system services ssh protocol-version v1"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.value == 1
    assert setting.status == SettingStatus.CONFIGURED


def test_juniper_parser_identifies_http_enabled():
    baseline = parse_juniper_config(
        "set system services web-management http"
    )

    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_juniper_parser_identifies_logging_host():
    baseline = parse_juniper_config(
        "set system syslog host 192.0.2.10 any info"
    )

    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)
    assert setting.evidence == (
        "set system syslog host 192.0.2.10 any info",
    )


def test_missing_settings_remain_unknown():
    baseline = parse_juniper_config(
        "set system host-name edge-router"
    )

    for name in (
        "ssh_protocol_version",
        "http_server_enabled",
        "logging_enabled",
    ):
        setting = baseline.get_setting(name)

        assert setting is not None
        assert setting.status == SettingStatus.UNKNOWN


def test_comments_and_blank_lines_are_ignored():
    baseline = parse_juniper_config(
        "# Juniper configuration\n"
        "\n"
        "set system services ssh protocol-version v2\n"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.value == 2
    assert setting.source_lines == (3,)


def test_non_string_configuration_is_rejected():
    with pytest.raises(ValueError, match="must be a string"):
        parse_juniper_config(None)


def test_delete_statement_does_not_prove_ssh_is_disabled():
    baseline = parse_juniper_config(
        "delete system services ssh"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN



def test_conflicting_ssh_versions_remain_unknown():
    baseline = parse_juniper_config(
        "set system services ssh protocol-version v2\n"
        "set system services ssh protocol-version v1"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None
    assert setting.source_lines == (1, 2)
    assert setting.evidence == (
        "set system services ssh protocol-version v2",
        "set system services ssh protocol-version v1",
    )


def test_conflicting_http_statements_remain_unknown():
    baseline = parse_juniper_config(
        "set system services web-management http\n"
        "delete system services web-management http"
    )

    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
