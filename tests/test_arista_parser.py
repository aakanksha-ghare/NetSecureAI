
from app.models.security_baseline import SettingStatus
from app.parsers.arista_parser import parse_arista_config


def test_arista_parser_returns_arista_baseline():
    baseline = parse_arista_config("hostname ARISTA-TEST\n")

    assert baseline.vendor == "Arista"
    assert baseline.device_type == "network_device"


def test_arista_ssh_remains_unknown():
    baseline = parse_arista_config("hostname ARISTA-TEST\n")

    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None


def test_arista_http_remains_unknown():
    baseline = parse_arista_config("hostname ARISTA-TEST\n")

    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None


def test_arista_logging_host_is_detected_with_evidence():
    config = (
        "hostname ARISTA-TEST\n"
        "logging host 192.0.2.10\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.value is True
    assert setting.source_lines == (2,)
    assert setting.evidence == ("logging host 192.0.2.10",)


def test_arista_missing_logging_destination_remains_unknown():
    baseline = parse_arista_config(
        "hostname ARISTA-TEST\n"
        "! no logging host configured\n"
    )

    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None
    assert setting.source_lines == ()
    assert setting.evidence == ()


def test_arista_ignores_blank_lines_and_comments():
    config = (
        "\n"
        "! configuration comment\n"
        "hostname ARISTA-TEST\n"
        "\n"
        "logging host 192.0.2.20\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("logging_enabled")

    assert setting is not None
    assert setting.source_lines == (5,)

def test_arista_ssh_shutdown_is_detected():
    config = (
        "hostname ARISTA-TEST\n"
        "management ssh\n"
        "   shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (3,)


def test_arista_ssh_no_shutdown_is_detected():
    config = (
        "hostname ARISTA-TEST\n"
        "management ssh\n"
        "   no shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_arista_missing_ssh_configuration_remains_unknown():
    baseline = parse_arista_config("hostname ARISTA-TEST\n")
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_arista_http_api_enabled_is_detected():
    config = (
        "hostname ARISTA-TEST\n"
        "management api http-commands\n"
        "   protocol http\n"
        "   no shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_arista_http_api_shutdown_is_detected():
    config = (
        "hostname ARISTA-TEST\n"
        "management api http-commands\n"
        "   protocol http\n"
        "   shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_arista_http_without_api_enable_remains_unknown():
    config = (
        "hostname ARISTA-TEST\n"
        "management api http-commands\n"
        "   protocol http\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN

def test_arista_conflicting_ssh_states_remain_unknown():
    config = (
        "management ssh\n"
        "   shutdown\n"
        "   no shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None
    assert setting.source_lines == (2, 3)


def test_arista_conflicting_http_states_remain_unknown():
    config = (
        "management api http-commands\n"
        "   protocol http\n"
        "   shutdown\n"
        "   no shutdown\n"
    )

    baseline = parse_arista_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None
    assert setting.source_lines == (2, 3, 4)
