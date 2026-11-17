
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def parse_arista_config(config_text: str) -> SecurityBaseline:
    """Normalize supported security settings from an Arista EOS config.

    Only explicitly observed settings are marked CONFIGURED. Missing or
    conflicting evidence remains UNKNOWN.
    """
    settings: dict[str, SecuritySetting] = {}

    logging_lines: list[int] = []
    logging_evidence: list[str] = []

    ssh_lines: list[int] = []
    ssh_evidence: list[str] = []
    ssh_states: set[bool] = set()

    http_lines: list[int] = []
    http_evidence: list[str] = []
    http_protocol_lines: list[int] = []
    http_protocol_evidence: list[str] = []
    http_states: set[bool] = set()

    in_management_ssh = False
    in_http_commands = False
    http_protocol_seen = False

    for line_number, raw_line in enumerate(
        config_text.splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        indentation = len(raw_line) - len(raw_line.lstrip())

        # Top-level commands establish or leave configuration sections.
        if indentation == 0:
            in_management_ssh = line == "management ssh"
            in_http_commands = line == "management api http-commands"

            if not in_http_commands:
                http_protocol_seen = False

            if line.startswith("logging host "):
                logging_lines.append(line_number)
                logging_evidence.append(line)

            continue

        if in_management_ssh:
            if line == "shutdown":
                ssh_states.add(False)
                ssh_lines.append(line_number)
                ssh_evidence.append(line)
            elif line == "no shutdown":
                ssh_states.add(True)
                ssh_lines.append(line_number)
                ssh_evidence.append(line)

        elif in_http_commands:
            if line == "protocol http":
                http_protocol_seen = True
                http_protocol_lines.append(line_number)
                http_protocol_evidence.append(line)

            elif line == "shutdown":
                if http_protocol_seen:
                    http_states.add(False)
                    http_lines.append(line_number)
                    http_evidence.append(line)

            elif line == "no shutdown":
                if http_protocol_seen:
                    http_states.add(True)
                    http_lines.append(line_number)
                    http_evidence.append(line)

    # SSH service state: report only an explicit, unambiguous state.
    if len(ssh_states) == 1:
        ssh_value = next(iter(ssh_states))
        settings["ssh_service_enabled"] = SecuritySetting(
            name="ssh_service_enabled",
            value=ssh_value,
            status=SettingStatus.CONFIGURED,
            source_lines=tuple(ssh_lines),
            evidence=tuple(ssh_evidence),
        )
    else:
        settings["ssh_service_enabled"] = SecuritySetting(
            name="ssh_service_enabled",
            value=None,
            status=SettingStatus.UNKNOWN,
            source_lines=tuple(ssh_lines),
            evidence=tuple(ssh_evidence),
        )

    # SSH protocol version is not inferred from service enablement.
    settings["ssh_protocol_version"] = SecuritySetting(
        name="ssh_protocol_version",
        value=None,
        status=SettingStatus.UNKNOWN,
    )

    # HTTP is known only when an HTTP protocol declaration and a matching
    # explicit, unambiguous shutdown state are present.
    if http_protocol_seen and len(http_states) == 1:
        http_value = next(iter(http_states))
        settings["http_server_enabled"] = SecuritySetting(
            name="http_server_enabled",
            value=http_value,
            status=SettingStatus.CONFIGURED,
            source_lines=tuple(
                http_protocol_lines + http_lines
            ),
            evidence=tuple(
                http_protocol_evidence + http_evidence
            ),
        )
    else:
        settings["http_server_enabled"] = SecuritySetting(
            name="http_server_enabled",
            value=None,
            status=SettingStatus.UNKNOWN,
            source_lines=tuple(
                http_protocol_lines + http_lines
            ),
            evidence=tuple(
                http_protocol_evidence + http_evidence
            ),
        )

    # Logging destination detection.
    settings["logging_enabled"] = SecuritySetting(
        name="logging_enabled",
        value=True if logging_lines else None,
        status=(
            SettingStatus.CONFIGURED
            if logging_lines
            else SettingStatus.UNKNOWN
        ),
        source_lines=tuple(logging_lines),
        evidence=tuple(logging_evidence),
    )

    return SecurityBaseline(
        vendor="Arista",
        device_type="network_device",
        settings=settings,
    )
