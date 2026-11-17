
from collections.abc import Callable

from app.models.security_baseline import SecurityBaseline
from app.parsers.arista_parser import parse_arista_config
from app.parsers.aruba_parser import parse_aruba_config
from app.parsers.checkpoint_parser import parse_checkpoint_config
from app.parsers.cisco_parser import parse_cisco_config
from app.parsers.fortinet_parser import parse_fortinet_config
from app.parsers.huawei_parser import parse_huawei_config
from app.parsers.juniper_parser import parse_juniper_config
from app.parsers.mikrotik_parser import parse_mikrotik_config
from app.parsers.palo_alto_parser import parse_palo_alto_config
from app.rules.compliance_engine import (
    ComplianceFinding,
    evaluate_baseline,
)


ConfigParser = Callable[[str], SecurityBaseline]


PARSER_REGISTRY: dict[str, ConfigParser] = {
    "cisco": parse_cisco_config,
    "juniper": parse_juniper_config,
    "arista": parse_arista_config,
    "fortinet": parse_fortinet_config,
    "palo_alto": parse_palo_alto_config,
    "checkpoint": parse_checkpoint_config,
    "huawei": parse_huawei_config,
    "aruba": parse_aruba_config,
    "mikrotik": parse_mikrotik_config,
}


def normalize_vendor_name(vendor: str) -> str:
    """Normalize a vendor name for parser lookup."""
    if not isinstance(vendor, str) or not vendor.strip():
        raise ValueError("A non-empty vendor name is required.")

    return vendor.strip().lower()


def audit_config(
    vendor: str,
    config_text: str,
    risk_inputs: dict[
        str, tuple[int | None, int | None, str]
    ] | None = None,
) -> tuple[SecurityBaseline, list[ComplianceFinding]]:
    """Parse a vendor configuration and evaluate its security baseline."""
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("Configuration text must not be empty.")

    normalized_vendor = normalize_vendor_name(vendor)
    parser = PARSER_REGISTRY.get(normalized_vendor)

    if parser is None:
        supported = ", ".join(sorted(PARSER_REGISTRY))
        raise ValueError(
            f"Unsupported vendor '{vendor}'. Supported vendors: "
            f"{supported}."
        )

    baseline = parser(config_text)
    findings = evaluate_baseline(
        baseline,
        risk_inputs=risk_inputs,
    )

    return baseline, findings


def audit_cisco_config(
    config_text: str,
    risk_inputs: dict[
        str, tuple[int | None, int | None, str]
    ] | None = None,
) -> tuple[SecurityBaseline, list[ComplianceFinding]]:
    """Preserve the existing Cisco-specific audit interface."""
    return audit_config(
        vendor="cisco",
        config_text=config_text,
        risk_inputs=risk_inputs,
    )
