
import shlex

from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


def parse_fortinet_config(config_text: str) -> SecurityBaseline:
    """Parse supported FortiGate configuration into a security baseline.

    Interface-level access is aggregated conservatively. A service is
    considered enabled if any observed interface explicitly allows it.
    It is considered disabled only when every observed interface has an
    explicit allowaccess list excluding it. Otherwise, the result is UNKNOWN.
    """
    settings: dict[str, SecuritySetting] = {}

    interfaces: list[dict[str, object]] = []
    logging_states: list[tuple[int, bool, str]] = []

    current_section: str | None = None
    current_edit: str | None = None
    current_interface: dict[str, object] | None = None

    def save_interface() -> None:
        nonlocal current_interface
        if current_interface is not None:
            interfaces.append(current_interface)
            current_interface = None

    for line_number, raw_line in enumerate(
        config_text.splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("config "):
            save_interface()
            current_section = line[len("config "):].strip()
            current_edit = None
            continue

        if line == "end":
            save_interface()
            current_section = None
            current_edit = None
            continue

        if line == "next":
            save_interface()
            current_edit = None
            continue

        if line.startswith("edit "):
            save_interface()
            try:
                parts = shlex.split(line)
            except ValueError:
                current_edit = None
                continue

            current_edit = parts[1] if len(parts) > 1 else None

            if current_section == "system interface":
                current_interface = {
                    "name": current_edit,
                    "allowaccess": None,
                    "line": line_number,
                    "evidence": [],
                }
            continue

        if current_section == "system interface":
            if (
                current_interface is not None
                and line.startswith("set allowaccess ")
            ):
                try:
                    parts = shlex.split(line)
                except ValueError:
                    continue

                if len(parts) >= 3:
                    current_interface["allowaccess"] = set(parts[2:])
                    current_interface["evidence"].append(
                        (line_number, line)
                    )

        elif current_section == "log syslogd setting":
            if line == "set status enable":
                logging_states.append((line_number, True, line))
            elif line == "set status disable":
                logging_states.append((line_number, False, line))

    save_interface()

    # Evaluate management access conservatively across observed interfaces.
    for setting_name, service_name in (
        ("ssh_service_enabled", "ssh"),
        ("http_server_enabled", "http"),
    ):
        enabled_interfaces = [
            interface
            for interface in interfaces
            if isinstance(interface["allowaccess"], set)
            and service_name in interface["allowaccess"]
        ]

        all_interfaces_explicit = bool(interfaces) and all(
            isinstance(interface["allowaccess"], set)
            for interface in interfaces
        )

        evidence_items = [
            item
            for interface in interfaces
            for item in interface["evidence"]
        ]
        source_lines = tuple(line for line, _ in evidence_items)
        evidence = tuple(text for _, text in evidence_items)

        if enabled_interfaces:
            value = True
            status = SettingStatus.CONFIGURED
        elif all_interfaces_explicit:
            value = False
            status = SettingStatus.CONFIGURED
        else:
            value = None
            status = SettingStatus.UNKNOWN

        settings[setting_name] = SecuritySetting(
            name=setting_name,
            value=value,
            status=status,
            source_lines=source_lines,
            evidence=evidence,
        )

    settings["ssh_protocol_version"] = SecuritySetting(
        name="ssh_protocol_version",
        value=None,
        status=SettingStatus.UNKNOWN,
    )

    distinct_logging_states = {
        state for _, state, _ in logging_states
    }

    if len(distinct_logging_states) == 1:
        logging_value = next(iter(distinct_logging_states))
        logging_status = SettingStatus.CONFIGURED
    else:
        logging_value = None
        logging_status = SettingStatus.UNKNOWN

    settings["logging_enabled"] = SecuritySetting(
        name="logging_enabled",
        value=logging_value,
        status=logging_status,
        source_lines=tuple(line for line, _, _ in logging_states),
        evidence=tuple(text for _, _, text in logging_states),
    )

    return SecurityBaseline(
        vendor="Fortinet",
        device_type="network_device",
        settings=settings,
    )
