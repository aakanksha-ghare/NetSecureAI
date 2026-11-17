
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def parse_cisco_config(config_text: str) -> SecurityBaseline:
    """Normalize selected security settings from a Cisco IOS-style config."""

    settings: dict[str, SecuritySetting] = {}

    ssh_version: int | None = None
    ssh_line: int | None = None
    ssh_evidence: str | None = None

    http_state: bool | None = None
    http_line: int | None = None
    http_evidence: str | None = None

    # Track supported logging-host commands in configuration order.
    # Each address maps to its latest observed state and evidence.
    logging_hosts: dict[str, tuple[bool, int, str]] = {}
    logging_syntax_ambiguous = False
    logging_command_seen = False

    # Track transport input commands inside VTY sections only.
    vty_sections: list[dict[str, object]] = []
    current_vty: dict[str, object] | None = None

    for line_number, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        if line.startswith("line "):
            current_vty = None

            if line == "line vty" or line.startswith("line vty "):
                current_vty = {
                    "commands": [],
                    "start_line": line_number,
                }
                vty_sections.append(current_vty)

            continue

        if line == "ip ssh version 2":
            ssh_version = 2
            ssh_line = line_number
            ssh_evidence = line
        elif line == "ip ssh version 1":
            ssh_version = 1
            ssh_line = line_number
            ssh_evidence = line

        elif line == "ip http server":
            http_state = True
            http_line = line_number
            http_evidence = line
        elif line == "no ip http server":
            http_state = False
            http_line = line_number
            http_evidence = line

        elif line.startswith("logging host "):
            logging_command_seen = True
            parts = line.split()

            if len(parts) != 3:
                logging_syntax_ambiguous = True
            else:
                address = parts[2]
                logging_hosts[address] = (True, line_number, line)

        elif line.startswith("no logging host "):
            logging_command_seen = True
            parts = line.split()

            if len(parts) != 4 or parts[:3] != ["no", "logging", "host"]:
                logging_syntax_ambiguous = True
            else:
                address = parts[3]

                if address in logging_hosts:
                    _, _, original_command = logging_hosts[address]
                    logging_hosts[address] = (
                        False,
                        line_number,
                        f"{original_command} -> {line}",
                    )
                else:
                    # A removal without an observed addition does not prove
                    # that no other logging destination is configured.
                    logging_syntax_ambiguous = True

        elif line.startswith("logging "):
            # Other logging commands can affect logging behavior, but this
            # parser only models explicit logging-host destinations.
            logging_syntax_ambiguous = True

        elif current_vty is not None and line.startswith("transport input "):
            commands = current_vty["commands"]
            assert isinstance(commands, list)
            commands.append((line_number, line))

    settings["ssh_protocol_version"] = SecuritySetting(
        name="ssh_protocol_version",
        value=ssh_version,
        status=(
            SettingStatus.CONFIGURED
            if ssh_line is not None
            else SettingStatus.UNKNOWN
        ),
        source_lines=(ssh_line,) if ssh_line is not None else (),
        evidence=(ssh_evidence,) if ssh_evidence is not None else (),
    )

    settings["http_server_enabled"] = SecuritySetting(
        name="http_server_enabled",
        value=http_state,
        status=(
            SettingStatus.CONFIGURED
            if http_line is not None
            else SettingStatus.UNKNOWN
        ),
        source_lines=(http_line,) if http_line is not None else (),
        evidence=(http_evidence,) if http_evidence is not None else (),
    )

    active_hosts = {
        address: state
        for address, state in logging_hosts.items()
        if state[0]
    }

    if active_hosts and not logging_syntax_ambiguous:
        logging_setting = SecuritySetting(
            name="logging_enabled",
            value=True,
            status=SettingStatus.CONFIGURED,
            source_lines=tuple(state[1] for state in active_hosts.values()),
            evidence=tuple(state[2] for state in active_hosts.values()),
        )
    elif (
        logging_command_seen
        and logging_hosts
        and not active_hosts
        and not logging_syntax_ambiguous
    ):
        logging_setting = SecuritySetting(
            name="logging_enabled",
            value=False,
            status=SettingStatus.CONFIGURED,
            source_lines=tuple(state[1] for state in logging_hosts.values()),
            evidence=tuple(state[2] for state in logging_hosts.values()),
        )
    else:
        logging_setting = SecuritySetting(
            name="logging_enabled",
            value=None,
            status=SettingStatus.UNKNOWN,
        )

    settings["logging_enabled"] = logging_setting

    # Only conclude whether Telnet is permitted when every detected
    # VTY section has a supported, explicit transport input command.
    telnet_setting: SecuritySetting

    if not vty_sections:
        telnet_setting = SecuritySetting(
            name="telnet_permitted",
            value=None,
            status=SettingStatus.UNKNOWN,
        )
    else:
        all_commands: list[tuple[int, str]] = []
        sections_supported = True

        for section in vty_sections:
            commands = section["commands"]
            assert isinstance(commands, list)

            if len(commands) != 1:
                sections_supported = False
                break

            line_number, command = commands[0]
            all_commands.append((line_number, command))

            parts = command.split()
            if len(parts) < 3 or parts[:2] != ["transport", "input"]:
                sections_supported = False
                break

            protocols = parts[2:]

            # This implementation recognizes only explicit, simple
            # protocol lists. Negated and platform-specific forms remain
            # UNKNOWN rather than being guessed.
            if any(protocol.startswith("no-") for protocol in protocols):
                sections_supported = False
                break

        if not sections_supported:
            telnet_setting = SecuritySetting(
                name="telnet_permitted",
                value=None,
                status=SettingStatus.UNKNOWN,
            )
        else:
            telnet_allowed = any(
                "telnet" in command.split()[2:]
                or "all" in command.split()[2:]
                for _, command in all_commands
            )

            # An SSH-only transport line is restrictive. Other protocol
            # combinations that cannot be confidently interpreted should
            # not be silently declared safe.
            supported = all(
                set(command.split()[2:]).issubset({"ssh", "telnet", "all"})
                for _, command in all_commands
            )

            if not supported:
                telnet_setting = SecuritySetting(
                    name="telnet_permitted",
                    value=None,
                    status=SettingStatus.UNKNOWN,
                )
            else:
                telnet_setting = SecuritySetting(
                    name="telnet_permitted",
                    value=telnet_allowed,
                    status=SettingStatus.CONFIGURED,
                    source_lines=tuple(
                        line_number for line_number, _ in all_commands
                    ),
                    evidence=tuple(
                        command for _, command in all_commands
                    ),
                )

    settings["telnet_permitted"] = telnet_setting

    return SecurityBaseline(
        vendor="Cisco",
        device_type="network_device",
        settings=settings,
    )
