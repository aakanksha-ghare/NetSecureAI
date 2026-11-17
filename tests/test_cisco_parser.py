
from pathlib import Path

from app.models.security_baseline import SettingStatus
from app.parsers.cisco_parser import parse_cisco_config


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cisco_basic.cfg"


def test_cisco_parser_normalizes_security_settings() -> None:
    config_text = FIXTURE_PATH.read_text(encoding="utf-8")
    baseline = parse_cisco_config(config_text)

    assert baseline.vendor == "Cisco"

    ssh = baseline.get_setting("ssh_protocol_version")
    assert ssh is not None
    assert ssh.value == 2
    assert ssh.status == SettingStatus.CONFIGURED

    http = baseline.get_setting("http_server_enabled")
    assert http is not None
    assert http.value is False
    assert http.status == SettingStatus.CONFIGURED

    logging = baseline.get_setting("logging_enabled")
    assert logging is not None
    assert logging.value is True
    assert logging.status == SettingStatus.CONFIGURED


def test_missing_ssh_command_is_unknown() -> None:
    baseline = parse_cisco_config("hostname TestRouter\n")

    ssh = baseline.get_setting("ssh_protocol_version")

    assert ssh is not None
    assert ssh.value is None
    assert ssh.status == SettingStatus.UNKNOWN
    assert ssh.source_lines == ()
    assert ssh.evidence == ()


def test_ssh_version_1_is_preserved() -> None:
    baseline = parse_cisco_config(
        "hostname TestRouter\n"
        "ip ssh version 1\n"
    )

    ssh = baseline.get_setting("ssh_protocol_version")

    assert ssh is not None
    assert ssh.value == 1
    assert ssh.status == SettingStatus.CONFIGURED
    assert ssh.source_lines == (2,)
    assert ssh.evidence == ("ip ssh version 1",)

def test_telnet_is_not_permitted_with_ssh_only_vty_transport() -> None:
    baseline = parse_cisco_config(
        "line vty 0 4\n"
        " transport input ssh\n"
    )

    telnet = baseline.get_setting("telnet_permitted")

    assert telnet is not None
    assert telnet.value is False
    assert telnet.status == SettingStatus.CONFIGURED
    assert telnet.source_lines == (2,)
    assert telnet.evidence == ("transport input ssh",)


def test_telnet_is_permitted_with_telnet_vty_transport() -> None:
    baseline = parse_cisco_config(
        "line vty 0 4\n"
        " transport input telnet\n"
    )

    telnet = baseline.get_setting("telnet_permitted")

    assert telnet is not None
    assert telnet.value is True
    assert telnet.status == SettingStatus.CONFIGURED
    assert telnet.source_lines == (2,)


def test_telnet_is_permitted_if_any_vty_section_allows_it() -> None:
    baseline = parse_cisco_config(
        "line vty 0 4\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " transport input telnet\n"
    )

    telnet = baseline.get_setting("telnet_permitted")

    assert telnet is not None
    assert telnet.value is True
    assert telnet.status == SettingStatus.CONFIGURED
    assert telnet.source_lines == (2, 4)


def test_telnet_is_unknown_when_vty_transport_is_missing() -> None:
    baseline = parse_cisco_config(
        "hostname TestRouter\n"
        "line vty 0 4\n"
    )

    telnet = baseline.get_setting("telnet_permitted")

    assert telnet is not None
    assert telnet.value is None
    assert telnet.status == SettingStatus.UNKNOWN
    assert telnet.source_lines == ()

def test_logging_host_is_enabled_with_source_evidence() -> None:
    baseline = parse_cisco_config("logging host 192.0.2.50\n")

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (1,)
    assert setting.evidence == ("logging host 192.0.2.50",)


def test_removed_logging_host_is_disabled_with_traceable_evidence() -> None:
    baseline = parse_cisco_config(
        "logging host 192.0.2.50\n"
        "no logging host 192.0.2.50\n"
    )

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (2,)
    assert setting.evidence == (
        "logging host 192.0.2.50 -> no logging host 192.0.2.50",
    )


def test_removing_one_of_multiple_logging_hosts_keeps_logging_enabled() -> None:
    baseline = parse_cisco_config(
        "logging host 192.0.2.50\n"
        "logging host 192.0.2.60\n"
        "no logging host 192.0.2.50\n"
    )

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (2,)
    assert setting.evidence == ("logging host 192.0.2.60",)


def test_all_observed_logging_hosts_removed_disables_logging() -> None:
    baseline = parse_cisco_config(
        "logging host 192.0.2.50\n"
        "logging host 192.0.2.60\n"
        "no logging host 192.0.2.50\n"
        "no logging host 192.0.2.60\n"
    )

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (3, 4)
    assert setting.evidence == (
        "logging host 192.0.2.50 -> no logging host 192.0.2.50",
        "logging host 192.0.2.60 -> no logging host 192.0.2.60",
    )


def test_readded_logging_host_is_enabled() -> None:
    baseline = parse_cisco_config(
        "logging host 192.0.2.50\n"
        "no logging host 192.0.2.50\n"
        "logging host 192.0.2.50\n"
    )

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED
    assert setting.source_lines == (3,)
    assert setting.evidence == ("logging host 192.0.2.50",)


def test_unpaired_logging_host_removal_is_unknown() -> None:
    baseline = parse_cisco_config("no logging host 192.0.2.50\n")

    setting = baseline.get_setting("logging_enabled")
    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
