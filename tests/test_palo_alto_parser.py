
from app.models.security_baseline import SettingStatus
from app.parsers.palo_alto_parser import parse_palo_alto_config


def test_palo_alto_parser_returns_palo_alto_baseline():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-TEST</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)

    assert baseline.vendor == "Palo Alto Networks"
    assert baseline.device_type == "network_device"


def test_palo_alto_ssh_enabled_is_detected():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-ssh>no</disable-ssh>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is True
    assert setting.status == SettingStatus.CONFIGURED


def test_palo_alto_ssh_disabled_is_detected():
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

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_palo_alto_http_disabled_is_detected():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-http>yes</disable-http>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is False
    assert setting.status == SettingStatus.CONFIGURED


def test_palo_alto_missing_management_settings_remain_unknown():
    baseline = parse_palo_alto_config(
        "<config><devices><entry name='localhost.localdomain'/>"
        "</devices></config>"
    )

    for name in (
        "ssh_service_enabled",
        "http_server_enabled",
        "ssh_protocol_version",
        "logging_enabled",
    ):
        setting = baseline.get_setting(name)
        assert setting is not None
        assert setting.value is None
        assert setting.status == SettingStatus.UNKNOWN


def test_palo_alto_ssh_protocol_version_remains_unknown():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-ssh>no</disable-ssh>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("ssh_protocol_version")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_palo_alto_invalid_xml_raises_value_error():
    try:
        parse_palo_alto_config("<config><devices>")
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid XML should raise ValueError")

def test_palo_alto_conflicting_ssh_values_remain_unknown():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-ssh>yes</disable-ssh>
            <disable-ssh>no</disable-ssh>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("ssh_service_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN


def test_palo_alto_unsupported_http_value_remains_unknown():
    config = """\
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <service>
            <disable-http>maybe</disable-http>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""

    baseline = parse_palo_alto_config(config)
    setting = baseline.get_setting("http_server_enabled")

    assert setting is not None
    assert setting.value is None
    assert setting.status == SettingStatus.UNKNOWN
    assert setting.evidence
