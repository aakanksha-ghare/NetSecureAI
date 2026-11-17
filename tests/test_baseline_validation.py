
import pytest

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def test_unknown_setting_can_preserve_value_without_becoming_configured():
    setting = SecuritySetting(
        name="logging_enabled",
        value=False,
        status=SettingStatus.UNKNOWN,
    )

    assert setting.value is False
    assert setting.status == SettingStatus.UNKNOWN


def test_invalid_setting_name_is_rejected():
    with pytest.raises(ValueError, match="Setting name"):
        SecuritySetting(
            name=" ",
            value=None,
            status=SettingStatus.UNKNOWN,
        )


@pytest.mark.parametrize("line_number", [0, -1, True, 1.5])
def test_invalid_source_line_numbers_are_rejected(line_number):
    with pytest.raises(ValueError, match="positive integers"):
        SecuritySetting(
            name="ssh_protocol_version",
            value=2,
            status=SettingStatus.CONFIGURED,
            source_lines=(line_number,),
        )


def test_evidence_must_be_a_tuple_of_strings():
    with pytest.raises(ValueError, match="Evidence"):
        SecuritySetting(
            name="ssh_protocol_version",
            value=2,
            status=SettingStatus.CONFIGURED,
            evidence=("SSH version configured", 123),
        )


def test_baseline_rejects_mismatched_setting_key():
    setting = SecuritySetting(
        name="ssh_protocol_version",
        value=2,
        status=SettingStatus.CONFIGURED,
    )

    with pytest.raises(ValueError, match="does not match"):
        SecurityBaseline(
            vendor="Cisco",
            device_type="router",
            settings={"ssh_version": setting},
        )


def test_baseline_accepts_normalized_settings():
    setting = SecuritySetting(
        name="ssh_protocol_version",
        value=2,
        status=SettingStatus.CONFIGURED,
        source_lines=(2,),
        evidence=("ip ssh version 2",),
    )

    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={"ssh_protocol_version": setting},
    )

    assert baseline.get_setting("ssh_protocol_version") == setting
