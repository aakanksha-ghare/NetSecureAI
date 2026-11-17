
import re

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def _configured_setting(
    name: str,
    value: object,
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


def _unknown_setting(
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


def parse_checkpoint_config(config_text: str) -> SecurityBaseline:
    """Parse a limited subset of Check Point Gaia Clish commands.

    Supported evidence:
    - Explicit SSH server enable/disable commands.
    - Explicit remote syslog destination configuration.

    SSH protocol version and HTTP management state remain UNKNOWN because
    this parser does not establish those settings reliably.

    This parser does not interpret Gaia backups, exported database files,
    SmartConsole policies, or effective runtime state.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    ssh_values: set[bool] = set()
    ssh_lines: list[int] = []
    ssh_evidence: list[str] = []

    logging_lines: list[int] = []
    logging_evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        ssh_match = re.fullmatch(
            r"set\s+ssh\s+server\s+(enable|disable)",
            line,
            flags=re.IGNORECASE,
        )

        if ssh_match:
            action = ssh_match.group(1).lower()
            ssh_values.add(action == "enable")
            ssh_lines.append(line_number)
            ssh_evidence.append(f"Line {line_number}: {line}")
            continue

        # Recognize an explicit remote syslog destination command.
        # Merely enabling local logging is not treated as proof that
        # a remote logging destination is configured.
        syslog_match = re.fullmatch(
            r"set\s+syslog\s+log-remote-address\s+"
            r"(\S+)",
            line,
            flags=re.IGNORECASE,
        )

        if syslog_match:
            address = syslog_match.group(1)

            # Avoid treating placeholders as real configuration evidence.
            if address.lower() not in {
                "",
                "none",
                "unset",
                "0.0.0.0",
            }:
                logging_lines.append(line_number)
                logging_evidence.append(
                    f"Line {line_number}: {line}"
                )

    settings: dict[str, SecuritySetting] = {}

    if len(ssh_values) == 1:
        settings["ssh_service_enabled"] = _configured_setting(
            name="ssh_service_enabled",
            value=next(iter(ssh_values)),
            source_lines=ssh_lines,
            evidence=ssh_evidence,
        )
    else:
        settings["ssh_service_enabled"] = _unknown_setting(
            name="ssh_service_enabled",
            source_lines=ssh_lines,
            evidence=ssh_evidence,
        )

    settings["ssh_protocol_version"] = _unknown_setting(
        "ssh_protocol_version",
        evidence=[
            "The supported configuration subset does not establish "
            "the negotiated or enforced SSH protocol version."
        ],
    )

    settings["http_server_enabled"] = _unknown_setting(
        "http_server_enabled",
        evidence=[
            "The supported configuration subset does not establish "
            "whether HTTP management is enabled or disabled."
        ],
    )

    if logging_lines:
        settings["logging_enabled"] = _configured_setting(
            name="logging_enabled",
            value=True,
            source_lines=logging_lines,
            evidence=logging_evidence,
        )
    else:
        settings["logging_enabled"] = _unknown_setting(
            name="logging_enabled",
            evidence=[
                "No supported explicit remote syslog destination "
                "was found. This does not prove logging is disabled."
            ],
        )

    return SecurityBaseline(
        vendor="Check Point",
        device_type="network_device",
        settings=settings,
    )
