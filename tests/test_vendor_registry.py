
import pytest
from app.services.audit_service import PARSER_REGISTRY, audit_config
from app.services.audit_service import (
    PARSER_REGISTRY,
    audit_config,
    normalize_vendor_name,
)


def test_cisco_is_registered():
    assert "cisco" in PARSER_REGISTRY


def test_vendor_name_is_normalized():
    assert normalize_vendor_name("  CISCO  ") == "cisco"


@pytest.mark.parametrize("vendor", ["", "   ", None, 123])
def test_invalid_vendor_name_is_rejected(vendor):
    with pytest.raises(ValueError, match="vendor name"):
        normalize_vendor_name(vendor)


def test_unsupported_vendor_is_rejected():
    with pytest.raises(ValueError, match="Unsupported vendor"):
        audit_config("unknown_vendor", "some config")

def test_empty_configuration_is_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        audit_config("cisco", "   ")


def test_cisco_dispatch_returns_cisco_baseline():
    baseline, findings = audit_config(
        "CISCO",
        "hostname TEST-ROUTER\nip ssh version 2\n",
    )

    assert baseline.vendor == "Cisco"
    assert baseline.get_setting("ssh_protocol_version").value == 2
    assert len(findings) == 4


def test_juniper_vendor_is_registered():
    from app.services.audit_service import PARSER_REGISTRY

    assert "juniper" in PARSER_REGISTRY


def test_juniper_audit_returns_juniper_baseline():
    from app.services.audit_service import audit_config

    baseline, findings = audit_config(
        "juniper",
        "set system services ssh protocol-version v2\n"
        "set system syslog host 192.0.2.10 any info",
    )

    assert baseline.vendor == "Juniper"
    assert baseline.get_setting("ssh_protocol_version").value == 2
    assert len(findings) > 0


def test_vendor_lookup_is_case_insensitive():
    from app.services.audit_service import audit_config

    baseline, _ = audit_config(
        "JUNIPER",
        "set system services ssh protocol-version v2",
    )

    assert baseline.vendor == "Juniper"

def test_arista_vendor_is_registered():
    assert "arista" in PARSER_REGISTRY


def test_arista_audit_returns_arista_baseline():
    baseline, findings = audit_config(
        "arista",
        "hostname ARISTA-TEST\n"
        "logging host 192.0.2.10\n",
    )

    assert baseline.vendor == "Arista"
    assert baseline.get_setting("logging_enabled").value is True
    assert len(findings) == 4


def test_arista_vendor_lookup_is_case_insensitive():
    baseline, _ = audit_config(
        "ARISTA",
        "hostname ARISTA-TEST\n",
    )

    assert baseline.vendor == "Arista"

def test_fortinet_vendor_is_registered():
    assert "fortinet" in PARSER_REGISTRY


def test_fortinet_audit_returns_fortinet_baseline():
    baseline, findings = audit_config(
        "fortinet",
        (
            "config system interface\n"
            "    edit \"port1\"\n"
            "        set allowaccess ping https ssh\n"
            "    next\n"
            "end\n"
            "config log syslogd setting\n"
            "    set status enable\n"
            "end\n"
        ),
    )

    assert baseline.vendor == "Fortinet"
    assert baseline.get_setting("ssh_service_enabled").value is True
    assert baseline.get_setting("logging_enabled").value is True
    assert len(findings) == 4


def test_fortinet_vendor_lookup_is_case_insensitive():
    baseline, _ = audit_config(
        "FORTINET",
        (
            "config system interface\n"
            "    edit \"port1\"\n"
            "        set allowaccess ping https\n"
            "    next\n"
            "end\n"
        ),
    )

    assert baseline.vendor == "Fortinet"

def test_palo_alto_vendor_is_registered():
    assert "palo_alto" in PARSER_REGISTRY


def test_palo_alto_audit_returns_palo_alto_baseline():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-ssh>yes</disable-ssh>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline, findings = audit_config("palo_alto", config)

    assert baseline.vendor == "Palo Alto Networks"
    assert baseline.get_setting("ssh_service_enabled").value is False
    assert len(findings) == 4


def test_palo_alto_vendor_lookup_is_case_insensitive():
    config = "<config><devices><entry name='localhost.localdomain'/>"
    config += "</devices></config>"

    baseline, _ = audit_config("PALO_ALTO", config)

    assert baseline.vendor == "Palo Alto Networks"
def test_checkpoint_vendor_is_registered():
    assert "checkpoint" in PARSER_REGISTRY


def test_checkpoint_audit_returns_checkpoint_baseline():
    config = """\
set ssh server enable
set syslog log-remote-address 192.0.2.10
"""

    baseline, findings = audit_config("checkpoint", config)

    assert baseline.vendor == "Check Point"
    assert baseline.get_setting("ssh_service_enabled").value is True
    assert baseline.get_setting("logging_enabled").value is True
    assert len(findings) == 4


def test_checkpoint_vendor_lookup_is_case_insensitive():
    config = "set ssh server enable"

    baseline, _ = audit_config("CHECKPOINT", config)

    assert baseline.vendor == "Check Point"
def test_huawei_vendor_is_registered():
    assert "huawei" in PARSER_REGISTRY


def test_huawei_audit_returns_huawei_baseline():
    config = """\
stelnet server enable
info-center loghost 192.0.2.10
"""

    baseline, findings = audit_config("huawei", config)

    assert baseline.vendor == "Huawei"
    assert baseline.get_setting("ssh_service_enabled").value is True
    assert baseline.get_setting("logging_enabled").value is True
    assert len(findings) == 4


def test_huawei_vendor_lookup_is_case_insensitive():
    baseline, _ = audit_config("HUAWEI", "stelnet server enable")

    assert baseline.vendor == "Huawei"
def test_aruba_vendor_is_registered():
    assert "aruba" in PARSER_REGISTRY


def test_aruba_audit_returns_aruba_baseline():
    config = """\
ssh server vrf default
logging 192.0.2.10
"""

    baseline, findings = audit_config("aruba", config)

    assert baseline.vendor == "HPE Aruba"
    assert baseline.get_setting("ssh_service_enabled").value is True
    assert baseline.get_setting("logging_enabled").value is True
    assert len(findings) == 4


def test_aruba_vendor_lookup_is_case_insensitive():
    baseline, _ = audit_config("ARUBA", "ssh server vrf default")

    assert baseline.vendor == "HPE Aruba"
