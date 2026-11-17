
import re

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


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


def _collect_commands(
    config_text: str,
    enabled_pattern: str,
    disabled_pattern: str,
) -> tuple[set[bool], list[int], list[str]]:
    values: set[bool] = set()
    source_lines: list[int] = []
    evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        if re.fullmatch(enabled_pattern, line, re.IGNORECASE):
            values.add(True)
            source_lines.append(line_number)
            evidence.append(f"Line {line_number}: {line}")
        elif re.fullmatch(disabled_pattern, line, re.IGNORECASE):
            values.add(False)
            source_lines.append(line_number)
            evidence.append(f"Line {line_number}: {line}")

    return values, source_lines, evidence


def parse_aruba_config(config_text: str) -> SecurityBaseline:
    """Parse a limited subset of Aruba AOS-CX-style configurations.

    Recognizes:
    - ssh server vrf <name>
    - no ssh server vrf <name>
    - https-server vrf <name>
    - no https-server vrf <name>
    - logging <IPv4-address>

    These patterns are deliberately limited. This parser does not
    establish effective runtime state, SSH protocol version, or full
    compatibility across Aruba operating systems and releases.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    ssh_values, ssh_lines, ssh_evidence = _collect_commands(
        config_text,
        r"ssh\s+server\s+vrf\s+\S+",
        r"no\s+ssh\s+server\s+vrf\s+\S+",
    )

    https_values, https_lines, https_evidence = _collect_commands(
        config_text,
        r"https-server\s+vrf\s+\S+",
        r"no\s+https-server\s+vrf\s+\S+",
    )

    logging_lines: list[int] = []
    logging_evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        if re.fullmatch(
            r"logging\s+\d{1,3}(?:\.\d{1,3}){3}(?:\s+.*)?",
            line,
            re.IGNORECASE,
        ):
            logging_lines.append(line_number)
            logging_evidence.append(f"Line {line_number}: {line}")

    settings: dict[str, SecuritySetting] = {}

    if len(ssh_values) == 1:
        settings["ssh_service_enabled"] = _configured(
            "ssh_service_enabled",
            next(iter(ssh_values)),
            ssh_lines,
            ssh_evidence,
        )
    else:
        settings["ssh_service_enabled"] = _unknown(
            "ssh_service_enabled",
            ssh_lines,
            ssh_evidence or [
                "No unambiguous supported SSH server command was found."
            ],
        )

    if len(https_values) == 1:
        # HTTPS management is not the same as HTTP management.
        # Do not map HTTPS state to http_server_enabled.
        https_setting = _configured(
            "https_management_enabled",
            next(iter(https_values)),
            https_lines,
            https_evidence,
        )
    else:
        https_setting = _unknown(
            "https_management_enabled",
            https_lines,
            https_evidence or [
                "No unambiguous supported HTTPS server command was found."
            ],
        )

    settings["https_management_enabled"] = https_setting

    settings["http_server_enabled"] = _unknown(
        "http_server_enabled",
        evidence=[
            "The supported AOS-CX command subset does not establish "
            "the HTTP management server state."
        ],
    )

    settings["ssh_protocol_version"] = _unknown(
        "ssh_protocol_version",
        evidence=[
            "The supported command subset does not establish "
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
                "No supported remote logging destination was found. "
                "This does not prove that logging is disabled."
            ],
        )

    return SecurityBaseline(
        vendor="HPE Aruba",
        device_type="network_device",
        settings=settings,
    )
