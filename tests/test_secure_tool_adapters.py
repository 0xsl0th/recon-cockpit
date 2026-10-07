"""Reviewed adapters are pure descriptions; no tool or network is launched."""

from dataclasses import FrozenInstanceError
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import openai_protocol as protocol
from recon_cockpit.secure_agent.models import (
    NmapTCPParameters, TCPParameters, ValidationError, parse_action, parse_policy,
)
from recon_cockpit.secure_agent.tool_adapters import (
    ADAPTERS, NMAP_PROPOSAL_PROFILE, NMAP_TOOL_ID, compile_nmap_argv, get_adapter,
)


def nmap_action():
    return {
        "schema_version": "1", "action_id": "00000000-0000-4000-8000-000000000001",
        "tool_id": NMAP_TOOL_ID, "target": "127.0.0.1",
        "parameters": {"port": 8080, "timeout_seconds": 5, "max_output_bytes": 16384},
        "rationale": "Reviewed owned scan.",
    }


def policy():
    return {
        "schema_version": "1", "policy_version": "test-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 4096, "max_targets": 1,
        "require_approval": True, "approval_ttl_seconds": 60,
    }


def test_existing_wire_digests_and_default_request_bytes_stay_unchanged():
    action = nmap_action()
    action.update(tool_id="http_probe", rationale="Deterministic owned-fixture probe.")
    action["parameters"] = {
        "port": 8080, "method": "GET", "path": "/", "timeout_seconds": 2,
        "max_output_bytes": 1024,
    }
    assert parse_action(action).digest == "08304c8acdcbf508088f242a921d00344743feb8ef192a188617c4da2aaba4e5"
    action["tool_id"] = "tcp_connect"
    del action["parameters"]["method"], action["parameters"]["path"]
    assert parse_action(action).digest == "33a17cd9ddc49e906195767fa587210c2f3f8122ad0a7f55dc6b73958c8ab0aa"
    assert parse_policy(policy()).digest == "47c8492f3660246245fad4ff72ea99309c2dbb0e9506eee3a4312af0e7032776"
    request = protocol.build_request(protocol.OpenAIConfig("test-model"),
                                     b'{"step":1,"untrusted_observation":null}')
    assert hashlib.sha256(request).hexdigest() == "0f311e326477d9c0e8ed0ea4b4c600f56d4623e48166cedc8b2e17b6f57b8498"


def test_registry_is_explicit_immutable_and_returns_detached_metadata():
    assert tuple(ADAPTERS) == ("http_probe", "tcp_connect", NMAP_TOOL_ID, "http_headers_v1",
                              "curl_https_get_v1", "ffuf_content_discovery_v1",
                               "dig_dns_query_v1", "dig_dns_srv_v1", "rdp_initial_negotiation_v1", "openssl_tls_handshake_v1",
                               "postgresql_tls_handshake_v1", "mysql_tls_handshake_v1", "whatweb_http_fingerprint_v1",
                               "ssh_host_keys_v1", "ldap_rootdse_v1", "smb_share_list_v1",
                               "rpcinfo_dump_v1", "showmount_exports_v1",
                               "curl_ftp_list_v1", "curl_smtp_capabilities_v1",
                               "curl_docker_ping_v1", "curl_docker_version_v1", "redis_server_info_v1", "snmp_system_get_v1", "kerbrute_userenum_v1", "nmap_service_identify_v1", "curl_winrm_metadata_v1",
                               "configurable_nmap_service_v1", "configurable_http_headers_v1", "configurable_ssh_host_keys_v1")
    with pytest.raises(TypeError):
        ADAPTERS["arbitrary"] = get_adapter(NMAP_TOOL_ID)
    adapter = get_adapter(NMAP_TOOL_ID)
    with pytest.raises(FrozenInstanceError):
        adapter.tool_id = "arbitrary"
    descriptor = adapter.to_dict()
    descriptor["parameters"]["properties"]["port"]["maximum"] = 999999
    descriptor["execution_requirements"].clear()
    assert adapter.parameter_schema()["properties"]["port"]["maximum"] == 65535
    assert "no_child_processes" in adapter.to_dict()["execution_requirements"]
    assert descriptor["adapter_api_version"] == descriptor["capability_version"] == "1"
    assert descriptor["approval"] == "operator_policy"


@pytest.mark.parametrize("tool", [None, [], {}, "shell", "nmap", "nmap_tcp_connect_v2"])
def test_unknown_tool_never_selects_or_imports_an_adapter(tool):
    with pytest.raises(ValidationError, match="^unsupported_tool$"):
        get_adapter(tool)


@pytest.mark.parametrize("version", [None, 1, True, "2", "1.0"])
def test_unknown_adapter_interface_version_is_rejected(version):
    with pytest.raises(ValidationError, match="^unsupported_adapter_api$"):
        get_adapter(NMAP_TOOL_ID, adapter_api_version=version)


def test_nmap_typed_roundtrip_and_policy_are_separate_from_profile_compilation():
    value = nmap_action()
    action = parse_action(value)
    assert type(action.parameters) is NmapTCPParameters
    assert action.to_dict() == value
    assert parse_action(json.dumps(value)).digest == action.digest
    assert type(action.parameters) is not TCPParameters
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 80
    configured = policy()
    assert "tool_not_allowed" in parse_policy(configured).evaluate(action).reasons
    configured.update(allowed_tools=[NMAP_TOOL_ID], max_timeout_seconds=5,
                      max_output_bytes=16384, allowed_methods=[])
    assert parse_policy(configured).evaluate(action).decision == "approval_required"
    value["target"] = "127.0.0.2"
    value["parameters"]["port"] = 8081
    outside = parse_action(value)
    assert parse_policy(configured).evaluate(outside).reasons == (
        "target_out_of_scope", "port_not_allowed",
    )
    with pytest.raises(ValidationError, match="^unsupported_nmap_execution_profile$"):
        compile_nmap_argv(outside)


@pytest.mark.parametrize("field,value", [
    ("port", True), ("port", "8080"), ("port", 8080.0), ("port", [8080]),
    ("port", 0), ("port", 65536), ("timeout_seconds", False),
    ("timeout_seconds", 0), ("timeout_seconds", 31), ("max_output_bytes", True),
    ("max_output_bytes", 0), ("max_output_bytes", 65537),
])
def test_nmap_rejects_malformed_parameters(field, value):
    action = nmap_action()
    action["parameters"][field] = value
    with pytest.raises(ValidationError, match=f"^invalid_{field}$"):
        parse_action(action)


@pytest.mark.parametrize("field", [
    "argv", "executable", "path", "method", "ports", "scripts", "environment",
    "credentials", "output_path", "retries", "datadir",
])
def test_nmap_cannot_request_another_capability_through_extra_parameters(field):
    action = nmap_action()
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError, match="^unknown_parameters_fields$"):
        parse_action(action)


@pytest.mark.parametrize("field", ["port", "timeout_seconds", "max_output_bytes"])
def test_nmap_requires_each_bound(field):
    action = nmap_action()
    del action["parameters"][field]
    with pytest.raises(ValidationError, match="^missing_parameters_fields$"):
        parse_action(action)


@pytest.mark.parametrize("target", ["127.0.0.1/32", "127.0.0.0/24", "::1"])
def test_nmap_v1_only_describes_one_literal_ipv4_target(target):
    action = nmap_action()
    action["target"] = target
    with pytest.raises(ValidationError, match="^unsupported_nmap_target$"):
        parse_action(action)


def test_fixed_nmap_compiler_has_no_user_supplied_process_configuration():
    assert compile_nmap_argv(parse_action(nmap_action())) == (
        "/tool/nmap", "--unprivileged", "-sT", "-Pn", "-n", "-p", "8080",
        "--max-retries", "0", "--max-parallelism", "1", "--host-timeout", "3s",
        "--datadir", "/tool/data", "--no-stylesheet", "-oX", "-", "127.0.0.1",
    )
    forged = parse_action(nmap_action())
    object.__setattr__(forged.parameters, "port", "8080 --script all")
    with pytest.raises(ValidationError, match="^invalid_port$"):
        compile_nmap_argv(forged)


@pytest.mark.parametrize("field,value", [
    ("port", 80), ("timeout_seconds", 4), ("max_output_bytes", 1024),
])
def test_valid_syntax_does_not_expand_the_reviewed_nmap_profile(field, value):
    action = nmap_action()
    action["parameters"][field] = value
    with pytest.raises(ValidationError, match="^unsupported_nmap_execution_profile$"):
        compile_nmap_argv(parse_action(action))


def nmap_response():
    return json.dumps({
        "object": "response", "status": "completed", "error": None,
        "incomplete_details": None,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": json.dumps({
                        "schema_version": "1", "action": nmap_action(), "done": False,
                    })}]}],
    }).encode()


def test_nmap_codec_profile_is_explicit_and_default_decoder_remains_legacy_only():
    with pytest.raises(protocol.OpenAIProtocolError, match="^invalid_openai_response$"):
        protocol.decode_response(nmap_response())
    decoded = protocol.decode_response(nmap_response(), profile=NMAP_PROPOSAL_PROFILE)
    assert json.loads(decoded)["action"] == nmap_action()
    request = json.loads(protocol.build_request(
        protocol.OpenAIConfig("offline-test-model"),
        b'{"step":1,"untrusted_observation":null}', profile=NMAP_PROPOSAL_PROFILE,
    ))
    variants = request["text"]["format"]["schema"]["properties"]["action"]["anyOf"]
    assert [item["properties"]["tool_id"]["enum"][0] for item in variants[:-1]] == [
        NMAP_TOOL_ID, "http_probe",
    ]
    assert request["tools"] == [] and request["tool_choice"] == "none"
    assert variants[-1] == {"type": "null"}


@pytest.mark.parametrize("profile", [None, [], 1, "unknown", "owned-nmap-http-v2"])
def test_unknown_codec_profiles_cannot_widen_existing_broker_requests(profile):
    with pytest.raises(protocol.OpenAIProtocolError, match="^invalid_openai_profile$"):
        protocol.build_request(protocol.OpenAIConfig("test-model"),
                               b'{"step":1,"untrusted_observation":null}', profile=profile)
    with pytest.raises(protocol.OpenAIProtocolError, match="^invalid_openai_response$"):
        protocol.decode_response(nmap_response(), profile=profile)
