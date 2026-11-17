
import re

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def _make_setting(
    name: str,
    value: bool | int | None,
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


def _make_unknown(
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


def _collect_boolean_commands(
    config_text: str,
    enable_pattern: str,
    disable_pattern: str,
) -> tuple[set[bool], list[int], list[str]]:
    """Collect explicit enable/disable commands and their evidence."""
    observed: set[bool] = set()
    source_lines: list[int] = []
    evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if re.fullmatch(enable_pattern, line, re.IGNORECASE):
            observed.add(True)
            source_lines.append(line_number)
            evidence.append(f"Line {line_number}: {line}")
        elif re.fullmatch(disable_pattern, line, re.IGNORECASE):
            observed.add(False)
            source_lines.append(line_number)
            evidence.append(f"Line {line_number}: {line}")

    return observed, source_lines, evidence


def parse_huawei_config(config_text: str) -> SecurityBaseline:
    """Parse a limited subset of Huawei VRP CLI configurations.

    Recognized commands:
    - stelnet server enable / undo stelnet server enable
    - http server enable / undo http server enable
    - info-center loghost <address>

    This parser does not evaluate all VRP releases, configuration
    contexts, inherited settings, or effective runtime state.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    ssh_values, ssh_lines, ssh_evidence = _collect_boolean_commands(
        config_text,
        r"stelnet\s+server\s+enable",
        r"undo\s+stelnet\s+server\s+enable",
    )

    http_values, http_lines, http_evidence = _collect_boolean_commands(
        config_text,
        r"http\s+server\s+enable",
        r"undo\s+http\s+server\s+enable",
    )

    logging_lines: list[int] = []
    logging_evidence: list[str] = []

    for line_number, raw_line in enumerate(
        config_text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if re.fullmatch(
            r"info-center\s+loghost\s+\S+.*",
            line,
            re.IGNORECASE,
        ):
            logging_lines.append(line_number)
            logging_evidence.append(f"Line {line_number}: {line}")

    settings: dict[str, SecuritySetting] = {}

    if len(ssh_values) == 1:
        settings["ssh_service_enabled"] = _make_setting(
            "ssh_service_enabled",
            next(iter(ssh_values)),
            ssh_lines,
            ssh_evidence,
        )
    else:
        settings["ssh_service_enabled"] = _make_unknown(
            "ssh_service_enabled",
            ssh_lines,
            ssh_evidence or [
                "No unambiguous supported SSH service command was found."
            ],
        )

    if len(http_values) == 1:
        settings["http_server_enabled"] = _make_setting(
            "http_server_enabled",
            next(iter(http_values)),
            http_lines,
            http_evidence,
        )
    else:
        settings["http_server_enabled"] = _make_unknown(
            "http_server_enabled",
            http_lines,
            http_evidence or [
                "No unambiguous supported HTTP server command was found."
            ],
        )

    if logging_lines:
        settings["logging_enabled"] = _make_setting(
            "logging_enabled",
            True,
            logging_lines,
            logging_evidence,
        )
    else:
        settings["logging_enabled"] = _make_unknown(
            "logging_enabled",
            evidence=[
                "No supported remote log-host command was found. "
                "This does not prove that logging is disabled."
            ],
        )

    settings["ssh_protocol_version"] = _make_unknown(
        "ssh_protocol_version",
        evidence=[
            "The supported command subset does not establish "
            "the enforced SSH protocol version."
        ],
    )

    return SecurityBaseline(
        vendor="Huawei",
        device_type="network_device",
        settings=settings,
    )
