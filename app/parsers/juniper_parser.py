
import re

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def parse_juniper_config(config_text: str) -> SecurityBaseline:
    """Parse supported Junos display-set statements conservatively."""

    if not isinstance(config_text, str):
        raise ValueError("Configuration text must be a string.")

    ssh_values: list[tuple[int, int, str]] = []
    http_values: list[tuple[int, bool, str]] = []
    logging_entries: list[tuple[int, str]] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        normalized = re.sub(r"\s+", " ", line)
        lowered = normalized.lower()

        ssh_match = re.fullmatch(
            r"set system services ssh protocol-version v([12])",
            lowered,
        )
        if ssh_match:
            ssh_values.append(
                (line_number, int(ssh_match.group(1)), line)
            )
            continue

        if lowered.startswith(
            "set system services web-management http"
        ):
            if re.fullmatch(
                r"set system services web-management http(?: .*)?",
                lowered,
            ):
                http_values.append((line_number, True, line))
            continue

        if lowered.startswith(
            "delete system services web-management http"
        ):
            if re.fullmatch(
                r"delete system services web-management http(?: .*)?",
                lowered,
            ):
                http_values.append((line_number, False, line))
            continue

        if re.fullmatch(
            r"delete system services ssh(?: .*)?",
            lowered,
        ):
            # Deletion alone does not establish the effective SSH state.
            continue

        if re.match(
            r"^set system syslog host \S+(?:\s|$)",
            lowered,
        ):
            logging_entries.append((line_number, line))

    settings: dict[str, SecuritySetting] = {}

    # SSH: accept only a single unambiguous observed version.
    ssh_lines = tuple(item[0] for item in ssh_values)
    ssh_evidence = tuple(item[2] for item in ssh_values)
    distinct_ssh_versions = {item[1] for item in ssh_values}

    if len(distinct_ssh_versions) == 1:
        ssh_version = ssh_values[-1][1]
        ssh_status = SettingStatus.CONFIGURED
    else:
        ssh_version = None
        ssh_status = SettingStatus.UNKNOWN

    settings["ssh_protocol_version"] = SecuritySetting(
        name="ssh_protocol_version",
        value=ssh_version,
        status=ssh_status,
        source_lines=ssh_lines,
        evidence=ssh_evidence,
    )

    # HTTP: a set/delete combination is ambiguous in a snippet.
    http_lines = tuple(item[0] for item in http_values)
    http_evidence = tuple(item[2] for item in http_values)
    distinct_http_states = {item[1] for item in http_values}

    if len(distinct_http_states) == 1 and http_values:
        http_state = http_values[-1][1]
        http_status = SettingStatus.CONFIGURED
    else:
        http_state = None
        http_status = SettingStatus.UNKNOWN

    settings["http_server_enabled"] = SecuritySetting(
        name="http_server_enabled",
        value=http_state,
        status=http_status,
        source_lines=http_lines,
        evidence=http_evidence,
    )

    # A configured syslog host is evidence of a logging destination.
    log_lines = tuple(item[0] for item in logging_entries)
    log_evidence = tuple(item[1] for item in logging_entries)

    settings["logging_enabled"] = SecuritySetting(
        name="logging_enabled",
        value=True if logging_entries else None,
        status=(
            SettingStatus.CONFIGURED
            if logging_entries
            else SettingStatus.UNKNOWN
        ),
        source_lines=log_lines,
        evidence=log_evidence,
    )

    return SecurityBaseline(
        vendor="Juniper",
        device_type="network_device",
        settings=settings,
    )
