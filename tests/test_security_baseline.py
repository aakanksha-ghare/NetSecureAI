
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def test_baseline_stores_normalized_settings() -> None:
    ssh = SecuritySetting(
        name="ssh_protocol_version",
        value=2,
        status=SettingStatus.CONFIGURED,
        source_lines=(12,),
        evidence=("ip ssh version 2",),
    )

    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={"ssh_protocol_version": ssh},
    )

    assert baseline.vendor == "Cisco"
    assert baseline.get_setting("ssh_protocol_version") == ssh
    assert baseline.get_setting("ssh_protocol_version").value == 2


def test_missing_setting_returns_none() -> None:
    baseline = SecurityBaseline(
        vendor="unknown",
        device_type="unknown",
        settings={},
    )

    assert baseline.get_setting("ssh_protocol_version") is None


def test_unknown_setting_is_not_assumed_to_be_false() -> None:
    setting = SecuritySetting(
        name="logging_enabled",
        value=None,
        status=SettingStatus.UNKNOWN,
    )

    assert setting.status == SettingStatus.UNKNOWN
    assert setting.value is None
