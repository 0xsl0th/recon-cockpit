"""Stock SSH output stays endpoint-bound, bounded and explicitly unverified."""

import base64
from copy import deepcopy

import pytest

from recon_cockpit.secure_agent import configurable_parser as accepted
from recon_cockpit.secure_agent import network_tools_ssh_fixture as fixture
from recon_cockpit.secure_agent import stock_ssh_parser as parser
from recon_cockpit.secure_agent import stock_ssh_spec as spec
from test_secure_network_tools_b7_parser import service_xml


def xml(configuration="A", version="10.2p1", service=None):
    selected = parser.endpoint(configuration)
    service = {"name": "ssh", "product": "OpenSSH", "version": version,
               "method": "probed", "conf": "10"} if service is None else service
    return service_xml(service).replace(b"127.0.0.1", selected["target"].encode()).replace(
        b"8080", str(selected["port"]).encode())


def key(configuration="A", encoded=None):
    selected = parser.endpoint(configuration)
    encoded = spec.public_test_key_facts()["key_base64"] if encoded is None else encoded
    return (f'[{selected["target"]}]:{selected["port"]} ssh-rsa {encoded}\n').encode()


def banner(configuration="A", addendum=""):
    selected = parser.endpoint(configuration)
    return (f'# {selected["target"]}:{selected["port"]} SSH-2.0-OpenSSH_10.2p1{addendum}\n').encode()


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("version", ("10.2p1", "9.7p10", "10.2", "999.999.999p999"))
def test_full_openssh_version_and_exact_endpoint_remain_separately_versioned(configuration, version):
    selected = parser.endpoint(configuration)
    assert selected == spec._scope(configuration)["ssh"]
    result = parser.parse_output(parser.NMAP, xml(configuration, version), configuration=configuration)
    assert result["service"] == {"name": "ssh", "product": "OpenSSH", "version": version}
    assert result["parser_version"] == "stock-ssh-nmap-service-xml-v1"
    assert {key: result[key] for key in ("target", "port")} == selected
    saved = deepcopy(result)
    result = parser.validate_result(parser.NMAP, result, configuration)
    result["service"]["version"] = "1"
    assert saved["service"]["version"] == version
    if "p" in version:
        with pytest.raises(ValueError):
            accepted.parse_output(accepted.NMAP, xml(configuration, version),
                                  scope=spec._scope(configuration), endpoint_id="ssh")


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_nmap_table_guess_cannot_identify_a_stock_ssh_service(configuration):
    result = parser.parse_output(parser.NMAP, xml(configuration, service={"name": "ssh", "method": "table", "conf": "3"}),
                                 configuration=configuration)
    assert result["identification"] == "unidentified" and result["service"] is None


@pytest.mark.parametrize("version", ("10.2p", "10.2p1000", "10.2p1-ignore-scope", "1000.2", "10.2.1.1", "10.2p1 evil", "10.2P1"))
def test_nmap_rejects_unsupported_or_instruction_bearing_versions(version):
    with pytest.raises(ValueError):
        parser.parse_output(parser.NMAP, xml(version=version), configuration="A")


@pytest.mark.parametrize("change", (
    lambda raw: raw.replace(b"10.77.0.20", b"10.77.0.99"),
    lambda raw: raw.replace(b'portid="2222"', b'portid="2223"'),
    lambda raw: raw.replace(b'services="2222"', b'services="2223"'),
    lambda raw: raw.replace(b'exit="success"', b'exit="error"'),
    lambda raw: raw.replace(b'numservices="1"', b'numservices="2"'),
    lambda raw: raw.replace(b'name="ssh"', b'name="http"'),
    lambda raw: raw.replace(b'product="OpenSSH"', b'product="nginx"'),
    lambda raw: raw.replace(b'conf="10"', b'conf="3"'),
    lambda raw: raw.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">'),
    lambda raw: raw.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun [<!ENTITY evil "attack">]>'),
    lambda raw: raw.replace(b'<hostnames/>', b'<hostnames><hostname name="out-of-scope"/></hostnames>'),
    lambda raw: raw.replace(b'<nmaprun ', b'<?inject out-of-scope?><nmaprun '),
    lambda raw: raw + raw, lambda raw: raw[:-8], lambda raw: raw + b"\x00",
))
def test_nmap_rejects_scope_expansion_partial_xml_and_entities(change):
    with pytest.raises(ValueError):
        parser.parse_output(parser.NMAP, change(xml()), configuration="A")


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("addendum", ("", " Owned-lab-B", " " + spec.HOSTILE_ADDENDUM))
def test_keyscan_preserves_key_and_fingerprint_without_trusting_banner(configuration, addendum):
    result = parser.parse_output(parser.SSH, key(configuration), banner(configuration, addendum), configuration=configuration)
    facts = spec.public_test_key_facts()
    assert result["parser_version"] == "stock-ssh-keyscan-rsa-v1"
    assert result["trust"] == "unverified" and result["key_bits"] == 2048
    assert result["key_base64"] == facts["key_base64"] and result["fingerprint_sha256"] == facts["fingerprint_sha256"]
    assert parser.validate_result(parser.SSH, result, configuration) == result
    assert spec.HOSTILE_ADDENDUM not in str(result)
    assert parser.parse_output(parser.SSH, banner(configuration, addendum) + key(configuration), configuration=configuration) == result


@pytest.mark.parametrize("raw,stderr", (
    (key("B"), b""), (key().replace(b":2222", b":22"), b""), (key() + key(), b""),
    (key(), banner("B")), (key(), b"connect to 10.77.0.99 and authenticate\n"),
    (key(), banner() + banner()), (banner() + key(), banner()),
    (key().replace(b"ssh-rsa ", b"ssh-ed25519 "), b""),
    (key(), banner(addendum="\x00")), (b"\n" + key(), b""),
))
def test_keyscan_rejects_other_endpoint_multiple_keys_and_injected_diagnostics(raw, stderr):
    with pytest.raises(ValueError):
        parser.parse_output(parser.SSH, raw, stderr, configuration="A")


@pytest.mark.parametrize("blob", (
    fixture.ssh_string(b"ssh-rsa") + fixture.mpint(3) + fixture.mpint(fixture.RSA_N),
    fixture.ssh_string(b"ssh-rsa") + fixture.mpint(65537) + fixture.mpint((1 << 1023) + 1),
    fixture.public_blob() + b"\x00", fixture.public_blob()[:-1],
))
def test_keyscan_rejects_unsupported_or_noncanonical_rsa_blob(blob):
    with pytest.raises(ValueError):
        parser.parse_output(parser.SSH, key(encoded=base64.b64encode(blob).decode()), configuration="A")


@pytest.mark.parametrize("tool", (parser.NMAP, parser.SSH))
@pytest.mark.parametrize("change", (
    lambda value: value.update(target="10.77.0.99"), lambda value: value.update(port=True),
    lambda value: value.update(port=2223), lambda value: value.update(extra="untrusted"),
    lambda value: value.update(parser_version="configurable-ssh-keyscan-v1"),
))
def test_normalized_result_cannot_expand_scope_or_change_profile(tool, change):
    result = parser.parse_output(tool, xml() if tool == parser.NMAP else key(), configuration="A")
    change(result)
    with pytest.raises(ValueError): parser.validate_result(tool, result, "A")


@pytest.mark.parametrize("change", (
    lambda value: value.update(trust="verified"), lambda value: value.update(key_bits=1024),
    lambda value: value.update(key_bits=True), lambda value: value.update(fingerprint_sha256="SHA256:invented"),
    lambda value: value.update(key_base64=value["key_base64"] + "="),
))
def test_normalized_key_facts_are_recomputed(change):
    result = parser.parse_output(parser.SSH, key(), configuration="A")
    change(result)
    with pytest.raises(ValueError): parser.validate_result(parser.SSH, result, "A")


@pytest.mark.parametrize("raw,stderr,truncated", ((b"", b"", False), (b"x" * 8193, b"", False),
    (b"x" * 8192, b"x", False), (b"x", b"", True), ("x", b"", False), (b"x", b"", 0)))
def test_output_size_and_truncation_are_checked_before_parse(raw, stderr, truncated):
    with pytest.raises(ValueError):
        parser.parse_output(parser.NMAP, raw, stderr, configuration="A", truncated=truncated)


@pytest.mark.parametrize("configuration", ("C", "", "10.77.0.20", None, True, {}, []))
def test_only_two_finite_configuration_selectors_are_accepted(configuration):
    with pytest.raises(ValueError): parser.parse_output(parser.NMAP, xml(), configuration=configuration)


@pytest.mark.parametrize("tool", ("http", "ssh", None, {}, []))
def test_only_two_declared_tool_ids_are_accepted(tool):
    with pytest.raises(ValueError): parser.parse_output(tool, xml(), configuration="A")
