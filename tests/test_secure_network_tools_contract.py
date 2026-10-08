"""Fixed tool authority, request continuity, and independently replayable bytes."""

import base64
import copy
import hashlib
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent.models import (NucleiParameters, TLSCertificateParameters, SSHAlgorithmsParameters, SNMPInterfaceNextParameters, HTTPOptionsParameters, FTPStartTLSParameters, LDAPStartTLSParameters, SMTPStartTLSParameters, SMB2NegotiateParameters, DigDNSParameters, OpenSSLTLSParameters,
    SSHHostKeysParameters, LDAPRootDSEParameters, SMBShareListParameters, RPCInfoDumpParameters, ShowmountExportsParameters,
    CurlFTPListParameters, CurlSMTPCapabilitiesParameters,
    CurlDockerPingParameters, CurlDockerVersionParameters, CurlWinRMMetadataParameters, NmapServiceParameters, KerbruteUserenumParameters, RedisServerInfoParameters, SNMPSystemGetParameters, PostgreSQLTLSParameters, MySQLTLSParameters, WhatWebParameters, DigSRVParameters, DigNSIDParameters, DigAXFRParameters, RDPInitialParameters, ValidationError, parse_action, parse_policy)
from recon_cockpit.secure_agent.tool_adapters import LEGACY_PROPOSAL_PROFILE, NMAP_PROPOSAL_PROFILE, proposal_tools
from recon_cockpit.secure_agent.network_tools_fixture import CA_PEM, QUERY_NAME, TLS_NAME
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from test_secure_network_tools_parser import dns_output, tls_output


def manifest(tool_id):
    if tool_id in (runtime.NUCLEI, runtime.NUCLEI_GIT):
        from recon_cockpit.secure_agent.network_tools_nuclei_runtime import for_tool
        return for_tool(tool_id).manifest()
    if tool_id == runtime.SSH_ALGORITHMS:
        from test_secure_ssh_algorithms_runtime import manifest as algorithms_manifest
        return algorithms_manifest()
    interpreter = "/lib64/ld-linux-x86-64.so.2"
    files = [{"source": runtime.EXECUTABLES[tool_id], "destination": runtime.FIXED_ARGV[tool_id][0],
              "size": 1, "sha256": "a" * 64},
             {"source": interpreter, "destination": interpreter, "size": 1, "sha256": "b" * 64}]
    for source, destination, compiled in runtime.compiled_files(tool_id):
        files.append({"source": source, "destination": destination, "size": len(compiled),
                      "sha256": hashlib.sha256(compiled).hexdigest()})
    return runtime.validate_manifest(runtime.compact_manifest({"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
        "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": interpreter,
        "files": sorted(files, key=lambda item: item["destination"])}))


def receipt(tool_id=contract.DIG_TOOL_ID, *, status="succeeded", raw=None, stderr=b""):
    if raw is None:
        raw = dns_output() if tool_id == contract.DIG_TOOL_ID else b""
        if tool_id == contract.OPENSSL_TOOL_ID:
            stderr = tls_output()
    normalized = parser.parse_tool_output(tool_id, raw, stderr) if status == "succeeded" and (raw or stderr) else None
    pinned = manifest(tool_id)
    return {"status": status, "results": [], "tool_observation": normalized,
        "raw_output_base64": base64.b64encode(raw).decode(), "raw_stderr_base64": base64.b64encode(stderr).decode(),
        "bytes_received": len(raw) + len(stderr), "truncated": status == "output_limit",
        "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS, True),
        "provenance": {"runtime_sha256": runtime.manifest_digest(pinned), "runtime_manifest": pinned,
            "output_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": contract.parser_version(tool_id), "exit_code": 0 if status == "succeeded" else -9,
            "stop_reason": status if status in {"timeout", "output_limit"} else None}}


def policy(**changes):
    return parse_policy({"schema_version": "1", "policy_version": "web-tools-test-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": list(contract.PARAMETERS),
        "allowed_ports": [8080, 111], "allowed_methods": ["GET", "OPTIONS"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True,
        "approval_ttl_seconds": 60, **changes})


@pytest.mark.parametrize("case", contract.CASES)
def test_case_selects_exact_typed_single_action_and_existing_policy_gates(case):
    action = parse_action(contract.action(case))
    expected = contract.NUCLEI_GIT_TOOL_ID if case in contract.C17_CASES else contract.NUCLEI_TOOL_ID if case in contract.C16_CASES else contract.TLS_CERTIFICATE_TOOL_ID if case in contract.C15_CASES else contract.SSH_ALGORITHMS_TOOL_ID if case in contract.C14_CASES else contract.SNMP_NEXT_TOOL_ID if case in contract.C13_CASES else contract.HTTP_OPTIONS_TOOL_ID if case in contract.C12_CASES else contract.DIG_AXFR_TOOL_ID if case in contract.C11_CASES else contract.DIG_NSID_TOOL_ID if case in contract.C10_CASES else contract.FTP_TLS_TOOL_ID if case in contract.C9_CASES else contract.LDAP_TLS_TOOL_ID if case in contract.C8_CASES else contract.SMTP_TLS_TOOL_ID if case in contract.C7_CASES else contract.SMB2_TOOL_ID if case in contract.C6_CASES else contract.RDP_TOOL_ID if case in contract.C5_CASES else contract.DIG_SRV_TOOL_ID if case in contract.C4_CASES else {"whatweb": contract.WHATWEB_TOOL_ID, "postgresql": contract.POSTGRESQL_TLS_TOOL_ID, "mysql": contract.MYSQL_TLS_TOOL_ID, "redis": contract.REDIS_TOOL_ID, "snmp": contract.SNMP_TOOL_ID, "dig": contract.DIG_TOOL_ID, "openssl": contract.OPENSSL_TOOL_ID,
                "ssh": contract.SSH_TOOL_ID, "ldap": contract.LDAP_TOOL_ID,
                "smb": contract.SMB_TOOL_ID, "rpc": contract.RPCINFO_TOOL_ID,
                "nfs": contract.SHOWMOUNT_TOOL_ID, "ftp": contract.FTP_TOOL_ID,
                "smtp": contract.SMTP_TOOL_ID, "winrm": contract.WINRM_TOOL_ID, "nmap": contract.NMAP_SERVICE_TOOL_ID, "kerberos": contract.KERBRUTE_TOOL_ID,
                "docker": contract.DOCKER_PING_TOOL_ID if case.startswith("docker-ping-") else contract.DOCKER_VERSION_TOOL_ID}[case.split("-")[0]]
    assert action.tool_id == expected and action.target == "127.0.0.1"
    assert type(action.parameters) is {contract.NUCLEI_GIT_TOOL_ID: NucleiParameters, contract.NUCLEI_TOOL_ID: NucleiParameters, contract.TLS_CERTIFICATE_TOOL_ID: TLSCertificateParameters, contract.SSH_ALGORITHMS_TOOL_ID: SSHAlgorithmsParameters, contract.SNMP_NEXT_TOOL_ID: SNMPInterfaceNextParameters, contract.HTTP_OPTIONS_TOOL_ID: HTTPOptionsParameters, contract.DIG_AXFR_TOOL_ID: DigAXFRParameters, contract.DIG_NSID_TOOL_ID: DigNSIDParameters, contract.FTP_TLS_TOOL_ID: FTPStartTLSParameters, contract.LDAP_TLS_TOOL_ID: LDAPStartTLSParameters, contract.SMTP_TLS_TOOL_ID: SMTPStartTLSParameters, contract.SMB2_TOOL_ID: SMB2NegotiateParameters, contract.RDP_TOOL_ID: RDPInitialParameters, contract.DIG_SRV_TOOL_ID: DigSRVParameters, contract.WHATWEB_TOOL_ID: WhatWebParameters, contract.POSTGRESQL_TLS_TOOL_ID: PostgreSQLTLSParameters, contract.MYSQL_TLS_TOOL_ID: MySQLTLSParameters, contract.REDIS_TOOL_ID: RedisServerInfoParameters, contract.SNMP_TOOL_ID: SNMPSystemGetParameters, contract.DIG_TOOL_ID: DigDNSParameters,
        contract.OPENSSL_TOOL_ID: OpenSSLTLSParameters, contract.SSH_TOOL_ID: SSHHostKeysParameters,
        contract.LDAP_TOOL_ID: LDAPRootDSEParameters, contract.SMB_TOOL_ID: SMBShareListParameters,
        contract.RPCINFO_TOOL_ID: RPCInfoDumpParameters, contract.SHOWMOUNT_TOOL_ID: ShowmountExportsParameters,
        contract.FTP_TOOL_ID: CurlFTPListParameters, contract.SMTP_TOOL_ID: CurlSMTPCapabilitiesParameters,
        contract.DOCKER_PING_TOOL_ID: CurlDockerPingParameters, contract.DOCKER_VERSION_TOOL_ID: CurlDockerVersionParameters,
        contract.WINRM_TOOL_ID: CurlWinRMMetadataParameters, contract.NMAP_SERVICE_TOOL_ID: NmapServiceParameters, contract.KERBRUTE_TOOL_ID: KerbruteUserenumParameters}[expected]
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == "approval_required"
    if case in contract.B6_CASES + contract.B7_CASES + contract.C12_CASES + contract.C16_CASES + contract.C17_CASES:
        assert policy(allowed_methods=[]).evaluate(action).reasons == ("method_not_allowed",)
    else:
        assert policy(allowed_methods=[]).evaluate(action).decision == "approval_required"
    assert policy(allowed_ports=[]).evaluate(action).reasons == ("port_not_allowed",)
    assert contract.LIMITS == {"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192}
    with pytest.raises(ValueError):
        contract.action(case, 2)


def test_shared_static_contracts_agree_and_model_profiles_stay_unchanged():
    assert contract.PARSER_VERSIONS == parser.PARSER_VERSIONS
    assert QUERY_NAME == parser.QUERY_NAME and TLS_NAME == parser.TLS_NAME
    assert proposal_tools(LEGACY_PROPOSAL_PROFILE) == ("http_probe", "tcp_connect")
    assert proposal_tools(NMAP_PROPOSAL_PROFILE) == ("nmap_tcp_connect_v1", "http_probe")
    assert contract.capability_descriptor()["live_calls_enabled"] is False


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok"])
@pytest.mark.parametrize("key,value", [("port", 8081), ("timeout_seconds", 2), ("max_output_bytes", 2048)])
def test_syntactic_parameters_do_not_expand_reviewed_profile(case, key, value):
    action = contract.action(case)
    action["parameters"][key] = value
    assert not contract.profile_allows(parse_action(action), case)


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok"])
@pytest.mark.parametrize("field", ["argv", "executable", "wordlist", "url", "headers", "credentials", "environment"])
def test_no_arbitrary_tool_input_fields(case, field):
    action = contract.action(case)
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError):
        parse_action(action)


@pytest.mark.parametrize("tool", [contract.DIG_TOOL_ID, contract.OPENSSL_TOOL_ID])
def test_valid_receipt_binds_raw_bytes_runtime_and_parser(tool):
    value = receipt(tool)
    output, stderr = contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded",
        runtime_sha256=value["provenance"]["runtime_sha256"])
    assert parser.parse_tool_output(tool, output, stderr) == value["tool_observation"]
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded", runtime_sha256="0" * 64)


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(extra=True), lambda r: r.update(results=[{}]),
    lambda r: r.update(bytes_received=True), lambda r: r.update(bytes_received=8193),
    lambda r: r.update(truncated=0), lambda r: r.update(truncated=True),
    lambda r: r.update(raw_output_base64="!bad!"), lambda r: r.update(raw_stderr_base64="A" * 10925),
    lambda r: r["boundary_checks"].update(forbidden_ip_blocked=1),
    lambda r: r["provenance"].update(output_sha256="0" * 64),
    lambda r: r["provenance"].update(stderr_sha256="0" * 64),
    lambda r: r["provenance"].update(runtime_sha256="0" * 64),
    lambda r: r["provenance"].update(exit_code=True),
    lambda r: r["provenance"].update(exit_code=1),
    lambda r: r["provenance"].update(stop_reason="timeout"),
    lambda r: r["provenance"].update(parser_version="old"),
    lambda r: r["provenance"].update(runtime_manifest=manifest(contract.OPENSSL_TOOL_ID)),
    lambda r: r["tool_observation"]["answers"][0].update(ttl=True),
])
def test_receipt_tampering_never_produces_observations(mutation):
    value = receipt()
    mutation(value)
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.DIG_TOOL_ID, execution_status="succeeded")
    assert contract.parse_observation(contract.action("dig-ok"), value,
        execution_status="succeeded")["classification"] == "inconclusive"


@pytest.mark.parametrize("status,raw", [("failed", b""), ("timeout", b"partial"), ("output_limit", b"x" * 8192)])
def test_native_failure_bytes_are_validated_but_never_interpreted(status, raw):
    value = receipt(status=status, raw=raw)
    assert contract.validate_tool_result(value, tool_id=contract.DIG_TOOL_ID, execution_status=status)[0] == raw
    assert contract.parse_observation(contract.action("dig-ok"), value,
        execution_status=status)["reason"] == "execution_not_succeeded"
    value["tool_observation"] = receipt()["tool_observation"]
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.DIG_TOOL_ID, execution_status=status)


@pytest.mark.parametrize("tool,raw,stderr", [(contract.DIG_TOOL_ID, b"", b""),
    (contract.DIG_TOOL_ID, b"", parser.DIG_DENIED_PROBE),
    (contract.OPENSSL_TOOL_ID, b"", b"x" * 8189)])
def test_output_limit_can_retain_less_than_cap_when_overflowing_read_is_discarded(tool, raw, stderr):
    value = receipt(tool, status="output_limit", raw=raw, stderr=stderr)
    assert contract.validate_tool_result(value, tool_id=tool, execution_status="output_limit") == (raw, stderr)
    case = "dig-ok" if tool == contract.DIG_TOOL_ID else "openssl-ok"
    assert contract.parse_observation(contract.action(case), value, execution_status="output_limit")["reason"] == "execution_not_succeeded"


@pytest.mark.parametrize("mutation", [lambda r: r.update(bytes_received=8193),
    lambda r: r.update(truncated=False),
    lambda r: r["provenance"].update(stop_reason="timeout"),
    lambda r: r["provenance"].update(stderr_sha256="0" * 64),
    lambda r: r["provenance"].update(runtime_sha256="0" * 64),
    lambda r: r.update(tool_observation=receipt(contract.OPENSSL_TOOL_ID)["tool_observation"])])
def test_partial_truncated_receipts_still_require_exact_provenance_and_no_observation(mutation):
    value = receipt(contract.OPENSSL_TOOL_ID, status="output_limit", raw=b"", stderr=b"x" * 8189)
    mutation(value)
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.OPENSSL_TOOL_ID, execution_status="output_limit")


def test_successful_exit_with_no_output_cannot_claim_negotiation():
    value = receipt(contract.OPENSSL_TOOL_ID, raw=b"")
    assert contract.validate_tool_result(value, tool_id=contract.OPENSSL_TOOL_ID, execution_status="succeeded") == (b"", b"")
    assert contract.parse_observation(contract.action("openssl-stalled"), value,
        execution_status="succeeded")["reason"] == "tool_output_not_interpretable"


@pytest.mark.parametrize("tool,raw,stderr,classification,reason", [
    (contract.DIG_TOOL_ID, dns_output(), b"", "answer_observed", "dns_answer_observed"),
    (contract.DIG_TOOL_ID, dns_output(injected=True), b"", "answer_observed", "dns_answer_observed"),
    (contract.DIG_TOOL_ID, dns_output(status="NXDOMAIN", answer=False), b"", "name_not_found", "dns_name_not_found"),
    (contract.DIG_TOOL_ID, dns_output(answer=False), b"", "no_answer_observed", "dns_no_answer_observed"),
    (contract.OPENSSL_TOOL_ID, b"", tls_output(), "handshake_verified", "tls_handshake_verified"),
])
def test_classification_follows_verified_transcript_facts(tool, raw, stderr, classification, reason):
    observation = contract.classify_tool(tool, parser.parse_tool_output(tool, raw, stderr))
    assert observation["classification"] == classification and observation["reason"] == reason
    assert observation["followup_path"] is None


@pytest.mark.parametrize("case,requests,normalized,status", [("dig-ok", 1, True, "succeeded"),
    ("dig-injected", 1, True, "succeeded"), ("dig-nxdomain", 1, True, "succeeded"),
    ("dig-malformed", 1, False, "failed"), ("dig-stalled", 1, False, "timeout"),
    ("openssl-ok", 1, True, "succeeded"), ("openssl-untrusted", 0, False, "failed"),
    ("openssl-malformed", 0, False, "failed"), ("openssl-stalled", 0, False, "timeout")])
def test_request_continuity_distinguishes_dns_questions_and_tls_handshakes(case, requests, normalized, status):
    owned = identity(case, str(uuid4()))
    tool = contract.action(case)["tool_id"]
    result = {"backend": contract.BACKEND, "owned_lab": {"identity": owned,
        "connection_count": 1, "request_count": requests}, "tool_observation": {} if normalized else None}
    assert contract.validate_result_context(result, owned, tool_id=tool, execution_status=status)
    if normalized:
        result["owned_lab"]["request_count"] = 0
        with pytest.raises(ValueError):
            contract.validate_result_context(result, owned, tool_id=tool, execution_status=status)
    elif case.startswith("openssl-"):
        result["owned_lab"]["request_count"] = 1
        with pytest.raises(ValueError):
            contract.validate_result_context(result, owned, tool_id=tool, execution_status=status)


@pytest.mark.parametrize("protocol,cipher", [("TLSv1.2", "TLS_AES_256_GCM_SHA384"),
    ("TLSv1.3", "TLS_AES_128_GCM_SHA256"), ("TLSv1.3", "other")])
def test_normalized_negotiation_must_match_runtime_fixed_profile(protocol, cipher):
    value = receipt(contract.OPENSSL_TOOL_ID)
    value["tool_observation"].update(protocol=protocol, cipher=cipher)
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.OPENSSL_TOOL_ID, execution_status="succeeded")


def test_tls_raw_diagnostics_hash_is_required_even_when_stdout_is_empty():
    value = receipt(contract.OPENSSL_TOOL_ID)
    assert value["raw_output_base64"] == ""
    assert contract.validate_tool_result(value, tool_id=contract.OPENSSL_TOOL_ID, execution_status="succeeded")[1] == tls_output()
    value["raw_stderr_base64"] = base64.b64encode(tls_output().replace(b"OK", b"NO")).decode()
    with pytest.raises(ValueError):
        contract.validate_tool_result(value, tool_id=contract.OPENSSL_TOOL_ID, execution_status="succeeded")
