
from dataclasses import dataclass
from enum import Enum
from typing import Any


class SettingStatus(str, Enum):
    CONFIGURED = "configured"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SecuritySetting:
    """A normalized security setting with traceable source evidence."""

    name: str
    value: Any
    status: SettingStatus
    source_lines: tuple[int, ...] = ()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Setting name must be a non-empty string.")

        if not isinstance(self.status, SettingStatus):
            raise ValueError("Setting status must be a SettingStatus value.")

        if not isinstance(self.source_lines, tuple):
            raise ValueError("Source lines must be provided as a tuple.")

        if any(
            type(line_number) is not int or line_number < 1
            for line_number in self.source_lines
        ):
            raise ValueError("Source line numbers must be positive integers.")

        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, str) for item in self.evidence
        ):
            raise ValueError("Evidence must be a tuple of strings.")


@dataclass
class SecurityBaseline:
    """Common representation of a network device's security settings."""

    vendor: str
    device_type: str
    settings: dict[str, SecuritySetting]

    def __post_init__(self) -> None:
        if not isinstance(self.vendor, str) or not self.vendor.strip():
            raise ValueError("Vendor must be a non-empty string.")

        if (
            not isinstance(self.device_type, str)
            or not self.device_type.strip()
        ):
            raise ValueError("Device type must be a non-empty string.")

        if not isinstance(self.settings, dict):
            raise ValueError("Settings must be a dictionary.")

        for name, setting in self.settings.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("Setting keys must be non-empty strings.")

            if not isinstance(setting, SecuritySetting):
                raise ValueError(
                    f"Setting '{name}' must be a SecuritySetting instance."
                )

            if name != setting.name:
                raise ValueError(
                    f"Setting key '{name}' does not match "
                    f"setting name '{setting.name}'."
                )

    def get_setting(self, name: str) -> SecuritySetting | None:
        """Return a normalized setting, or None if it is unavailable."""
        return self.settings.get(name)
