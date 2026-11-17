
from app.models.security_baseline import SettingStatus
from app.parsers.fortinet_parser import parse_fortinet_config


def test_fortinet_parser_returns_fortinet_baseline():
    baseline = parse_fortinet_config(
        "config system global\n"
        "    set hostname FGT-TEST\n"
        "end\n"
    )

    assert baseline.vendor == "Fortinet"
    assert baseline.device_type == "network_device"


def test_fortinet_ssh_access_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https ssh\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.evidence == ("set allowaccess ping https ssh",)


def test_fortinet_ssh_access_absence_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_http_access_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping http https\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_http_access_absence_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https ssh\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_missing_interface_configuration_is_unknown():
    baseline = parse_fortinet_config(
        "config system global\n"
        "    set hostname FGT-TEST\n"
        "end\n"
    )

    for name in ("ssh_service_enabled", "http_server_enabled"):
        setting = baseline.get_setting(name)
        assert setting is not None
        assert setting.value is None
        assert setting.status == SettingStatus.UNKNOWN


def test_fortinet_logging_enabled_is_detected():
    config = (
        "config log syslogd setting\n"
        "    set status enable\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_logging_disabled_is_detected():
    config = (
        "config log syslogd setting\n"
        "    set status disable\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_missing_logging_configuration_is_unknown():
    baseline = parse_fortinet_config(
        "config system global\n"
        "    set hostname FGT-TEST\n"
        "end\n"
    )

    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_fortinet_ssh_protocol_version_remains_unknown():
    baseline = parse_fortinet_config(
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https ssh\n"
        "    next\n"
        "end\n"
    )

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN

def test_fortinet_conflicting_logging_states_remain_unknown():
    config = (
        "config log syslogd setting\n"
        "    set status enable\n"
        "    set status disable\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_fortinet_ssh_enabled_on_any_interface_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https\n"
        "    next\n"
        "    edit \"port2\"\n"
        "        set allowaccess ping ssh\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_fortinet_http_enabled_on_any_interface_is_detected():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https\n"
        "    next\n"
        "    edit \"port2\"\n"
        "        set allowaccess ping http\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED

def test_fortinet_interface_without_allowaccess_remains_unknown_for_absent_service():
    config = (
        "config system interface\n"
        "    edit \"port1\"\n"
        "        set allowaccess ping https\n"
        "    next\n"
        "    edit \"port2\"\n"
        "        set alias \"Unreviewed interface\"\n"
        "    next\n"
        "end\n"
    )

    baseline = parse_fortinet_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
