
import pytest

from app.models.security_baseline import SettingStatus
from app.parsers.huawei_parser import parse_huawei_config


def test_huawei_stelnet_enabled():
    baseline = parse_huawei_config("stelnet server enable")
    setting = baseline.get_setting("ssh_service_enabled")

    assert baseline.vendor == "Huawei"
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_huawei_stelnet_disabled():
    baseline = parse_huawei_config("undo stelnet server enable")
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_huawei_conflicting_stelnet_commands_return_unknown():
    config = (
        "stelnet server enable\n"
        "undo stelnet server enable\n"
    )

    baseline = parse_huawei_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.source_lines == (1, 2)


def test_huawei_http_server_enabled():
    baseline = parse_huawei_config("http server enable")
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_huawei_http_server_disabled():
    baseline = parse_huawei_config("undo http server enable")
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_huawei_conflicting_http_commands_return_unknown():
    config = (
        "http server enable\n"
        "undo http server enable\n"
    )

    baseline = parse_huawei_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_huawei_remote_logging_detected():
    baseline = parse_huawei_config(
        "info-center loghost 192.0.2.10"
    )
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)


def test_huawei_missing_logging_is_unknown():
    baseline = parse_huawei_config("stelnet server enable")
    setting = baseline.get_setting("logging_enabled")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_huawei_ssh_protocol_version_is_unknown():
    baseline = parse_huawei_config("stelnet server enable")
    setting = baseline.get_setting("ssh_protocol_version")

    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_huawei_comments_are_ignored():
    baseline = parse_huawei_config(
        "# undo stelnet server enable\n"
        "stelnet server enable\n"
    )
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting.value is True
    assert setting.source_lines == (2,)


@pytest.mark.parametrize("config", ["", "   ", "\n"])
def test_huawei_empty_configuration_is_rejected(config):
    with pytest.raises(ValueError, match="must not be empty"):
        parse_huawei_config(config)
