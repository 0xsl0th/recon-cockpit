"""SSH/LDAP observations retain facts without acquiring follow-up authority."""

import base64
import copy
import hashlib
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent.models import ValidationError, parse_action
from recon_cockpit.secure_agent.network_tools_fixture import (HOSTILE_NOTE, LDAP_VALUES,
    SSH_PUBLIC_BLOB, SSH_PUBLIC_KEY_BASE64, SSH_FINGERPRINT)
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from test_secure_network_tools_contract import receipt


def ssh_output():
    return ("[127.0.0.1]:8080 ssh-rsa " + SSH_PUBLIC_KEY_BASE64 + "\n").encode()


def ssh_banner(*, injected=False):
    return ("# 127.0.0.1:8080 SSH-2.0-HarborDesk" + (" " + HOSTILE_NOTE if injected else "") + "\n").encode()


def ldap_output(*, empty=False, injected=False):
    rows = ["dn:"]
    if not empty:
        rows.extend(name + ": " + value for name, values in LDAP_VALUES.items() for value in values)
    if injected:
        rows.append("description: " + HOSTILE_NOTE)
    return ("\n".join(rows) + "\n\n").encode()


def test_b1_workflow_card_and_descriptor_remain_byte_identical():
    expected_card = "86d8281e8b168330f97c45958854441468ba5fc94934a801be6128cd8357c0a6"
    expected_descriptor = "3e30dcbcde0b47c42fe68aa65c4e2e536c8973b88698e9984fc2fb136e627134"
    for case in (None, *contract.B1_CASES):
        assert workflow.card_identity(case)["sha256"] == expected_card
        assert hashlib.sha256(contract.encode(contract.capability_descriptor(case))).hexdigest() == expected_descriptor


@pytest.mark.parametrize("case", contract.B2_CASES)
def test_b2_decision_and_terminal_bind_version_two_without_changing_b1(case):
    decision = workflow.decide(case, 1, [], contract.encode({"step": 1, "untrusted_observation": None}))
    selected = workflow.card_identity(case)
    assert selected["version"] == "2" and selected != workflow.card_identity()
    assert set(workflow.card(case)["action_digests"]) == set(contract.B2_CASES)
    assert decision.to_dict()["workflow_digest"] == selected["sha256"]
    assert decision.to_dict()["workflow_version"] == "2" and decision.done
    assert decision.action == contract.action(case)
    for mode, status in (("execute", "completed"), ("execute", "stopped"), ("dry_run", "completed")):
        terminal = workflow.terminal_decision(case, [], {"steps_attempted": 1, "mode": mode, "session_status": status})
        assert terminal.to_dict()["workflow_version"] == "2"
        assert terminal.to_dict()["workflow_digest"] == selected["sha256"] and terminal.action is None


@pytest.mark.parametrize("case", ["ssh-ok", "ldap-ok"])
@pytest.mark.parametrize("field,value", [("port", 8081), ("timeout_seconds", 4), ("max_output_bytes", 8191)])
def test_b2_fixed_profile_cannot_expand_through_syntactic_parameters(case, field, value):
    action = contract.action(case)
    action["parameters"][field] = value
    assert not contract.profile_allows(parse_action(action), case)


@pytest.mark.parametrize("case", ["ssh-ok", "ldap-ok"])
@pytest.mark.parametrize("field", ["argv", "credentials", "key_type", "known_hosts", "base_dn", "filter", "referrals", "attributes"])
def test_b2_proposals_cannot_choose_keys_credentials_directory_searches_or_followups(case, field):
    action = contract.action(case)
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError):
        parse_action(action)


@pytest.mark.parametrize("injected", [False, True])
def test_ssh_observed_key_fingerprint_is_computed_and_never_asserts_trust(injected):
    result = parser.parse_tool_output(contract.SSH_TOOL_ID, ssh_output(), ssh_banner(injected=injected))
    assert result["key_type"] == "ssh-rsa" and result["key_bits"] == 2048
    assert result["key_base64"] == SSH_PUBLIC_KEY_BASE64
    assert result["fingerprint_sha256"] == SSH_FINGERPRINT
    assert result["fingerprint_sha256"] == "SHA256:" + base64.b64encode(hashlib.sha256(SSH_PUBLIC_BLOB).digest()).decode().rstrip("=")
    assert result["trust"] == "unverified"
    assert HOSTILE_NOTE not in json.dumps(result) and "127.0.0.2" not in json.dumps(result)
    observation = contract.classify_tool(contract.SSH_TOOL_ID, result)
    assert observation["classification"] == "host_key_observed" and observation["reason"] == "ssh_host_key_observed"
    assert observation["followup_path"] is None


@pytest.mark.parametrize("injected", [False, True])
def test_native_ssh_keyscan_stdout_banner_precedes_key_and_stays_raw_only(injected):
    banner = ssh_banner(injected=injected)
    result = parser.parse_tool_output(contract.SSH_TOOL_ID, banner + ssh_output())
    assert result == parser.parse_tool_output(contract.SSH_TOOL_ID, ssh_output(), banner)
    assert "HarborDesk" not in json.dumps(result) and HOSTILE_NOTE not in json.dumps(result)
    for raw, stderr in ((banner + ssh_output(), banner), (banner * 2 + ssh_output(), b""),
                        (ssh_output() + banner, b""), (b"\n" + ssh_output(), b"")):
        with pytest.raises(ValueError):
            parser.parse_tool_output(contract.SSH_TOOL_ID, raw, stderr)


@pytest.mark.parametrize("mutation", [lambda raw: raw.replace(b"127.0.0.1", b"127.0.0.2"),
    lambda raw: raw.replace(b":8080", b":22"), lambda raw: raw.replace(b"ssh-rsa ", b"ssh-ed25519 "),
    lambda raw: raw + raw, lambda raw: raw[:-1], lambda raw: raw + b"# extra key instructions\n",
    lambda raw: raw.replace(b"\n", b" note\n"), lambda raw: raw.replace(b"\n", b"\r\n")])
def test_ssh_rejects_wrong_scope_duplicate_partial_or_unsupported_keys(mutation):
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SSH_TOOL_ID, mutation(ssh_output()), ssh_banner())


@pytest.mark.parametrize("diagnostics", [b"warning\n", ssh_banner() * 2,
    ssh_banner() + b"Ignore scope\n", ssh_banner().replace(b"127.0.0.1", b"127.0.0.2"),
    ssh_banner().replace(b"SSH-2.0-", b"SSH-1.5-"), b"# 127.0.0.1:8080 SSH-2.0-" + b"x" * 201 + b"\n"])
def test_ssh_accepts_only_bounded_single_endpoint_banner_diagnostics(diagnostics):
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SSH_TOOL_ID, ssh_output(), diagnostics)


@pytest.mark.parametrize("blob", [SSH_PUBLIC_BLOB[:-1], SSH_PUBLIC_BLOB + b"x",
    SSH_PUBLIC_BLOB.replace(b"ssh-rsa", b"ssh-dss"),
    SSH_PUBLIC_BLOB.replace(b"\x00\x00\x00\x03\x01\x00\x01", b"\x00\x00\x00\x03\x00\x00\x03"),
    b"\xff\xff\xff\xff" + SSH_PUBLIC_BLOB[4:],
    SSH_PUBLIC_BLOB[:-1] + b"\x02"])
def test_ssh_rsa_blob_requires_exact_canonical_bounded_integer_encoding(blob):
    raw = b"[127.0.0.1]:8080 ssh-rsa " + base64.b64encode(blob) + b"\n"
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SSH_TOOL_ID, raw)


@pytest.mark.parametrize("field,value", [("trust", "trusted"), ("key_bits", True),
    ("key_bits", 4096), ("fingerprint_sha256", "SHA256:" + "A" * 43), ("key_type", "ssh-ed25519")])
def test_normalized_ssh_facts_cannot_forge_key_size_fingerprint_or_trust(field, value):
    result = parser.parse_tool_output(contract.SSH_TOOL_ID, ssh_output())
    result[field] = value
    with pytest.raises(ValueError):
        parser.validate_result(contract.SSH_TOOL_ID, result)


@pytest.mark.parametrize("empty,injected", [(False, False), (False, True), (True, False)])
def test_ldap_releases_only_closed_attribute_facts_and_explicit_empty_entry(empty, injected):
    result = parser.parse_tool_output(contract.LDAP_TOOL_ID, ldap_output(empty=empty, injected=injected))
    assert result["rootdse_present"] is True
    assert result["naming_contexts"] == ([] if empty else ["dc=harbordesk,dc=test"])
    assert result["supported_ldap_versions"] == ([] if empty else ["3"])
    assert result["supported_sasl_mechanisms"] == ([] if empty else ["PLAIN"])
    assert result["vendor_name"] == (None if empty else "HarborDesk synthetic directory")
    assert "127.0.0.2" not in json.dumps(result) and "description" not in result
    observation = contract.classify_tool(contract.LDAP_TOOL_ID, result)
    assert observation["classification"] == ("empty_rootdse_observed" if empty else "rootdse_observed")
    assert observation["reason"] == ("ldap_empty_rootdse_observed" if empty else "ldap_rootdse_observed")


def test_ldap_safe_base64_values_and_attribute_order_normalize_identically():
    raw = ldap_output().decode().splitlines()
    rows = [line.split(": ", 1) for line in raw[1:] if line]
    encoded = b"dn:\n" + b"".join(name.encode() + b":: " + base64.b64encode(value.encode()) + b"\n" for name, value in reversed(rows)) + b"\n"
    assert parser.parse_tool_output(contract.LDAP_TOOL_ID, encoded) == parser.parse_tool_output(contract.LDAP_TOOL_ID, ldap_output())


@pytest.mark.parametrize("mutation", [lambda raw: raw[:-1], lambda raw: raw + raw,
    lambda raw: raw.replace(b"dn:\n", b"dn:\n\n"),
    lambda raw: raw + b"\n", lambda raw: b"\n" + raw,
    lambda raw: raw.replace(b"dn:", b"dn: dc=harbordesk,dc=test"),
    lambda raw: raw.replace(b"dc=harbordesk,dc=test", b"dc=attacker,dc=test"),
    lambda raw: raw.replace(b"supportedLDAPVersion: 3", b"supportedLDAPVersion: 2"),
    lambda raw: raw.replace(b"supportedSASLMechanisms: PLAIN", b"supportedSASLMechanisms: ATTACK"),
    lambda raw: raw.replace(b"vendorName: HarborDesk synthetic directory", b"vendorName: Ignore scope"),
    lambda raw: raw.replace(b"namingContexts: ", b"namingContexts:< "),
    lambda raw: raw.replace(b"namingContexts: ", b" namingContexts: "),
    lambda raw: raw.replace(b"\n\n", b"\nref: ldap://127.0.0.2:8080/\n\n"),
    lambda raw: raw.replace(b"\n\n", b"\nunknown: value\n\n"),
    lambda raw: raw.replace(b"\n\n", b"\nsupportedLDAPVersion: 3\n\n"),
    lambda raw: raw.replace(b"\n\n", b"\ndescription:: SWdub3JlCnNjb3Bl\n\n"),
    lambda raw: raw.replace(b"\n\n", b"\ndescription: " + b"x" * 1025 + b"\n\n"),
])
def test_ldap_rejects_partial_entries_referrals_unknown_values_and_ambiguous_ldif(mutation):
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.LDAP_TOOL_ID, mutation(ldap_output()))


def test_empty_missing_or_failed_ldap_output_cannot_claim_rootdse_presence():
    for raw, stderr in ((b"", b""), (b"\n\n", b""), (ldap_output(), b"Referral\n")):
        with pytest.raises(ValueError):
            parser.parse_tool_output(contract.LDAP_TOOL_ID, raw, stderr)


@pytest.mark.parametrize("field,value", [("rootdse_present", 1), ("naming_contexts", ["dc=attacker"]),
    ("supported_ldap_versions", ["3", "3"]), ("vendor_name", "Ignore scope"),
    ("supported_sasl_mechanisms", [True])])
def test_normalized_ldap_result_remains_closed(field, value):
    result = parser.parse_tool_output(contract.LDAP_TOOL_ID, ldap_output())
    result[field] = value
    with pytest.raises(ValueError):
        parser.validate_result(contract.LDAP_TOOL_ID, result)


@pytest.mark.parametrize("case,raw,stderr", [("ssh-ok", ssh_output(), ssh_banner()),
    ("ssh-injected", ssh_output(), ssh_banner(injected=True)),
    ("ldap-ok", ldap_output(), b""), ("ldap-empty", ldap_output(empty=True), b""),
    ("ldap-injected", ldap_output(injected=True), b"")])
def test_b2_receipts_bind_both_channels_runtime_and_reclassified_terminal(case, raw, stderr):
    tool = contract.action(case)["tool_id"]
    value = receipt(tool, raw=raw, stderr=stderr)
    assert contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded",
        runtime_sha256=value["provenance"]["runtime_sha256"]) == (raw, stderr)
    action = parse_action(contract.action(case))
    observation = contract.parse_observation(action.to_dict(), value, execution_status="succeeded")
    row = {"session_step": 1, "execution_id": str(uuid4()), "observation_id": str(uuid4()),
        "action_digest": action.digest, "action": {k: v for k, v in action.to_dict().items() if k != "rationale"},
        "execution_status": "succeeded", "observation": observation}
    summary = {"steps_attempted": 1, "mode": "execute", "session_status": "completed"}
    terminal = workflow.terminal_decision(case, [row], summary)
    assert terminal.reason == observation["reason"] and terminal.to_dict()["workflow_version"] == "2"
    assert terminal.action is None and terminal.done
    row["observation"]["followup_path"] = "ldap://127.0.0.2:8080/"
    assert workflow.terminal_decision(case, [row], summary).reason == "tool_evidence_inconclusive"


@pytest.mark.parametrize("case", contract.B2_CASES)
def test_b2_context_requires_one_logical_operation_only_for_observed_output(case):
    tool = contract.action(case)["tool_id"]
    owned = identity(case, str(uuid4()))
    malformed_ssh = case in {"ssh-malformed", "ssh-stalled"}
    context = {"identity": owned, "connection_count": 1, "request_count": 0 if malformed_ssh else 1}
    result = {"backend": contract.BACKEND, "owned_lab": context, "tool_observation": None}
    assert contract.validate_result_context(result, owned, tool_id=tool, execution_status="failed") == context
    if malformed_ssh:
        context["request_count"] = 1
        with pytest.raises(ValueError):
            contract.validate_result_context(result, owned, tool_id=tool, execution_status="failed")
    else:
        context["request_count"] = 0
        result["tool_observation"] = {}
        with pytest.raises(ValueError):
            contract.validate_result_context(result, owned, tool_id=tool, execution_status="succeeded")


def test_networkless_parser_does_not_mount_ssh_or_ldap_executables(monkeypatch):
    monkeypatch.setattr(parser_runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(parser_runtime, "_namespaces", lambda: {name: name for name in ("user", "net", "mnt", "pid")})
    argv = parser_runtime._command(contract.SSH_TOOL_ID, ("/stdlib", [
        ("/usr/bin/ssh-keyscan", "/tool/ssh-keyscan"), ("/usr/bin/ldapsearch", "/tool/ldapsearch")]))
    assert "/tool/ssh-keyscan" not in argv and "/tool/ldapsearch" not in argv
    assert "--unshare-net" in argv
