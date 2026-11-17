
import re

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


ATTRIBUTE_PATTERN = re.compile(
    r'([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|(\S+))'
)


def _parse_attributes(text: str) -> dict[str, str]:
    """Parse quoted and unquoted RouterOS export attributes."""
    attributes: dict[str, str] = {}

    for key, quoted_value, plain_value in ATTRIBUTE_PATTERN.findall(text):
        attributes[key.lower()] = (
            quoted_value if quoted_value else plain_value
        )

    return attributes


def _configured(
    name: str,
    value: bool,
    source_lines: list[int],
    evidence: list[str],
) -> SecuritySetting:
    return SecuritySetting(
        name=name,
        value=value,
        status=SettingStatus.CONFIGURED,
        source_lines=tuple(source_lines),
        evidence=tuple(evidence),
    )


def _unknown(
    name: str,
    source_lines: list[int] | None = None,
    evidence: list[str] | None = None,
) -> SecuritySetting:
    return SecuritySetting(
        name=name,
        value=None,
        status=SettingStatus.UNKNOWN,
        source_lines=tuple(source_lines or ()),
        evidence=tuple(evidence or ()),
    )


def parse_mikrotik_config(config_text: str) -> SecurityBaseline:
    """Parse a limited subset of MikroTik RouterOS export syntax.

    Supported evidence:
    - /ip service entries for ssh and www.
    - Explicit disabled=yes/no values.
    - /system logging action entries with remote targets.

    This parser does not interpret every RouterOS version, configuration
    context, firewall rule, inherited setting, or effective runtime state.
    Missing service entries are UNKNOWN, not proof that a service is
    disabled. HTTPS (www-ssl) is not treated as plain HTTP.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    section: str | None = None

    service_values: dict[str, set[bool]] = {
        "ssh_service_enabled": set(),
        "http_server_enabled": set(),
    }
    service_lines: dict[str, list[int]] = {
        "ssh_service_enabled": [],
        "http_server_enabled": [],
    }
    service_evidence: dict[str, list[str]] = {
        "ssh_service_enabled": [],
        "http_server_enabled": [],
    }

    logging_lines: list[int] = []
    logging_evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("/"):
            section = re.sub(r"\s+", "/", line.lower()).rstrip("/")
            continue

        if section == "/ip/service":
            entry_match = re.match(
                r"add\s+(.*)",
                line,
                flags=re.IGNORECASE,
            )
            if not entry_match:
                continue

            attributes = _parse_attributes(entry_match.group(1))
            service_name = attributes.get("name", "").lower()
            disabled_value = attributes.get("disabled", "").lower()

            setting_name: str | None = None

            if service_name == "ssh":
                setting_name = "ssh_service_enabled"
            elif service_name == "www":
                setting_name = "http_server_enabled"

            if setting_name is None:
                continue

            service_lines[setting_name].append(line_number)
            service_evidence[setting_name].append(
                f"Line {line_number}: {line}"
            )

            if disabled_value in {"yes", "no"}:
                service_values[setting_name].add(
                    disabled_value == "no"
                )

        elif section == "/system/logging/action":
            entry_match = re.match(
                r"add\s+(.*)",
                line,
                flags=re.IGNORECASE,
            )
            if not entry_match:
                continue

            attributes = _parse_attributes(entry_match.group(1))

            action_name = attributes.get("name", "").lower()
            target = attributes.get("target", "").lower()
            remote_address = attributes.get("remote", "").strip()

            if (
                action_name
                and target == "remote"
                and remote_address
                and remote_address.lower() not in {"none", "0.0.0.0"}
            ):
                logging_lines.append(line_number)
                logging_evidence.append(
                    f"Line {line_number}: {line}"
                )

    settings: dict[str, SecuritySetting] = {}

    for setting_name in (
        "ssh_service_enabled",
        "http_server_enabled",
    ):
        values = service_values[setting_name]

        if len(values) == 1:
            settings[setting_name] = _configured(
                setting_name,
                next(iter(values)),
                service_lines[setting_name],
                service_evidence[setting_name],
            )
        else:
            settings[setting_name] = _unknown(
                setting_name,
                service_lines[setting_name],
                service_evidence[setting_name] or [
                    "No supported service entry was found."
                ],
            )

    settings["ssh_protocol_version"] = _unknown(
        "ssh_protocol_version",
        evidence=[
            "The supported RouterOS export subset does not establish "
            "the enforced SSH protocol version."
        ],
    )

    if logging_lines:
        settings["logging_enabled"] = _configured(
            "logging_enabled",
            True,
            logging_lines,
            logging_evidence,
        )
    else:
        settings["logging_enabled"] = _unknown(
            "logging_enabled",
            evidence=[
                "No supported remote logging action was found. "
                "This does not prove that logging is disabled."
            ],
        )

    return SecurityBaseline(
        vendor="MikroTik",
        device_type="network_device",
        settings=settings,
    )
