
import xml.etree.ElementTree as ET

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def _read_disabled_setting(
    root: ET.Element,
    xml_path: str,
    setting_name: str,
) -> SecuritySetting:
    """Read an explicit PAN-OS yes/no disable setting conservatively."""
    elements = root.findall(xml_path)

    observed_values: set[bool] = set()
    evidence: list[str] = []

    for element in elements:
        if element.text is None:
            continue

        raw_value = element.text.strip().lower()

        if raw_value == "yes":
            observed_values.add(False)
        elif raw_value == "no":
            observed_values.add(True)
        else:
            evidence.append(
                f"{xml_path}: unsupported value {element.text!r}"
            )

    for element in elements:
        if element.text is not None and element.text.strip().lower() in (
            "yes",
            "no",
        ):
            evidence.append(
                f"{xml_path} = {element.text.strip().lower()}"
            )

    if len(observed_values) == 1 and not any(
        "unsupported value" in item for item in evidence
    ):
        return SecuritySetting(
            name=setting_name,
            value=next(iter(observed_values)),
            status=SettingStatus.CONFIGURED,
            evidence=tuple(evidence),
        )

    return SecuritySetting(
        name=setting_name,
        value=None,
        status=SettingStatus.UNKNOWN,
        evidence=tuple(evidence),
    )


def parse_palo_alto_config(config_text: str) -> SecurityBaseline:
    """Parse a supported subset of PAN-OS XML configuration.

    This parser does not interpret CLI configuration, inherited settings,
    templates, device-group overrides, or effective runtime state.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    try:
        root = ET.fromstring(config_text)
    except ET.ParseError as exc:
        raise ValueError("Invalid PAN-OS XML configuration.") from exc

    if root.tag != "config":
        raise ValueError(
            "Unsupported configuration format: expected a PAN-OS <config> root."
        )

    service_path = (
        "./devices/entry/deviceconfig/system/service/"
    )

    settings: dict[str, SecuritySetting] = {
        "ssh_service_enabled": _read_disabled_setting(
            root,
            service_path + "disable-ssh",
            "ssh_service_enabled",
        ),
        "http_server_enabled": _read_disabled_setting(
            root,
            service_path + "disable-http",
            "http_server_enabled",
        ),
        "ssh_protocol_version": SecuritySetting(
            name="ssh_protocol_version",
            value=None,
            status=SettingStatus.UNKNOWN,
        ),
        "logging_enabled": SecuritySetting(
            name="logging_enabled",
            value=None,
            status=SettingStatus.UNKNOWN,
        ),
    }

    return SecurityBaseline(
        vendor="Palo Alto Networks",
        device_type="network_device",
        settings=settings,
    )
