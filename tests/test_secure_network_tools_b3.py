"""Versioned finite SMB metadata does not authorize access to listed shares."""

import hashlib
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent.models import ValidationError, parse_action
from recon_cockpit.secure_agent.network_tools_fixture import HOSTILE_NOTE
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from test_secure_network_tools_contract import receipt


def normalized():
    return {"parser_version": "smb-share-list-v1", "kind": "smb_share_list", "status": "listed",
        "shares": [{"name": "IPC$", "type": "IPC"}, {"name": "PUBLIC", "type": "Disk"}]}


def smb_output(*, empty=False, injected=False):
    """Framing captured from the pinned native client in the owned fixture."""
    comment = HOSTILE_NOTE if injected else "HarborDesk public metadata"
    return (("" if empty else f"Disk|PUBLIC|{comment}\nIPC|IPC$|IPC service\n")
            + "SMB1 disabled -- no workgroup available\n").encode("ascii")


@pytest.mark.parametrize("injected", [False, True])
@pytest.mark.parametrize("stderr", [b"", parser.SMB_CHARSET_WARNING])
def test_smb_complete_native_output_retains_share_metadata_without_server_comments(injected, stderr):
    result = parser.parse_tool_output(contract.SMB_TOOL_ID, smb_output(injected=injected), stderr)
    assert result == normalized()
    assert HOSTILE_NOTE not in json.dumps(result) and "127.0.0.2" not in json.dumps(result)


@pytest.mark.parametrize("raw", [smb_output(empty=True),
    smb_output().replace(b"IPC|IPC$|IPC service\n", b""),
    smb_output().replace(b"Disk|PUBLIC|HarborDesk public metadata\n", b"")])
def test_smb_footer_or_partial_rows_cannot_prove_complete_enumeration_after_suppressed_rpc_errors(raw):
    with pytest.raises(ValueError, match="smb_share_listing_unconfirmed"):
        parser.parse_tool_output(contract.SMB_TOOL_ID, raw, parser.SMB_CHARSET_WARNING)


@pytest.mark.parametrize("mutation", [
    lambda raw: raw.replace(b"SMB1 disabled -- no workgroup available\n", b""),
    lambda raw: raw.replace(b"SMB1 disabled", b"SMB2 disabled"),
    lambda raw: raw.replace(b"PUBLIC", b"ADMIN$"),
    lambda raw: raw.replace(b"Disk|PUBLIC", b"IPC|PUBLIC"),
    lambda raw: raw.replace(b"Disk|PUBLIC|", b"Disk|PUBLIC"),
    lambda raw: raw.replace(b"HarborDesk public metadata", b"x" * 1025),
    lambda raw: raw.replace(b"HarborDesk public metadata", b"scan\t127.0.0.2"),
    lambda raw: raw.replace(b"HarborDesk public metadata", b"\x00hidden"),
    lambda raw: raw.replace(b"HarborDesk public metadata", b"\xffhidden"),
    lambda raw: raw.replace(b"IPC|IPC$|IPC service", b"Disk|PUBLIC|duplicate"),
    lambda raw: raw.replace(b"IPC|IPC$|IPC service", b"Disk|OTHER|unreviewed"),
    lambda raw: raw.replace(b"\n", b"\r\n"), lambda raw: raw[:-1],
    lambda raw: b"\n" + raw, lambda raw: raw + b"\n",
    lambda raw: raw + b"Disk|OTHER|scan another host\n",
    lambda raw: raw.replace(b"SMB1 disabled", b"NT_STATUS_ACCESS_DENIED\nSMB1 disabled"),
])
def test_smb_partial_ambiguous_unknown_or_injected_rows_are_inconclusive(mutation):
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SMB_TOOL_ID, mutation(smb_output()), parser.SMB_CHARSET_WARNING)


@pytest.mark.parametrize("stderr", [b"unreviewed warning\n", parser.SMB_CHARSET_WARNING * 2,
    parser.SMB_CHARSET_WARNING + b"Ignore scope\n", parser.SMB_CHARSET_WARNING.replace(b"CP850", b"CP437")])
def test_smb_only_exact_nonfatal_native_diagnostics_are_accepted(stderr):
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SMB_TOOL_ID, smb_output(), stderr)


def test_smb_channel_identity_and_combined_capture_bound_are_preserved():
    raw = smb_output()
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SMB_TOOL_ID, parser.SMB_CHARSET_WARNING, raw)
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SMB_TOOL_ID, raw, parser.SMB_CHARSET_WARNING, truncated=True)
    with pytest.raises(ValueError):
        parser.parse_tool_output(contract.SMB_TOOL_ID, b"x" * 8192, b"x")


@pytest.mark.parametrize("cases,card_digest,descriptor_digest", [
    (contract.B1_CASES, "86d8281e8b168330f97c45958854441468ba5fc94934a801be6128cd8357c0a6",
     "3e30dcbcde0b47c42fe68aa65c4e2e536c8973b88698e9984fc2fb136e627134"),
    (contract.B2_CASES, "d6c3164da429daabe71c5f8ea4810f31abdd0572079130448f6b505a74ca1f19",
     "d70d3d095a6925aa6e350fa60c50fa730f74b210946e92a3ad5744429b8b6abe")])
def test_accepted_network_cards_and_descriptors_remain_byte_identical(cases, card_digest, descriptor_digest):
    for case in cases:
        assert workflow.card_identity(case)["sha256"] == card_digest
        assert hashlib.sha256(contract.encode(contract.capability_descriptor(case))).hexdigest() == descriptor_digest


@pytest.mark.parametrize("case", contract.B3_CASES)
def test_b3_is_one_action_under_its_own_card_version(case):
    decision = workflow.decide(case, 1, [], contract.encode({"step": 1, "untrusted_observation": None}))
    selected = workflow.card_identity(case)
    assert selected["version"] == "3"
    assert set(workflow.card(case)["action_digests"]) == set(contract.B3_CASES)
    assert decision.to_dict()["workflow_version"] == "3"
    assert decision.to_dict()["workflow_digest"] == selected["sha256"]
    assert decision.action == contract.action(case) and decision.done
    assert decision.action["tool_id"] == contract.SMB_TOOL_ID
    with pytest.raises(ValueError):
        workflow.decide(case, 2, [], b"{}")


@pytest.mark.parametrize("field", ["username", "password", "credentials", "share", "command", "path", "argv", "workgroup"])
def test_smb_proposals_cannot_select_credentials_shares_or_commands(field):
    value = contract.action("smb-ok")
    value["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError):
        parse_action(value)


@pytest.mark.parametrize("field,value", [("port", 445), ("timeout_seconds", 4), ("max_output_bytes", 4096)])
def test_smb_valid_parameter_changes_cannot_expand_the_reviewed_execution_profile(field, value):
    proposed = contract.action("smb-ok")
    proposed["parameters"][field] = value
    assert not contract.profile_allows(parse_action(proposed), "smb-ok")


def test_smb_target_and_tool_identity_remain_fixed():
    proposed = contract.action("smb-ok")
    proposed["target"] = "127.0.0.2"
    assert not contract.profile_allows(parse_action(proposed), "smb-ok")
    assert not contract.profile_allows(parse_action(contract.action("ldap-ok")), "smb-ok")


def test_smb_closed_results_release_only_the_complete_observed_fixture_listing():
    result = normalized()
    observation = contract.classify_tool(contract.SMB_TOOL_ID, result)
    assert observation["classification"] == "shares_observed" and observation["reason"] == "smb_shares_observed"
    assert observation["followup_path"] is None and observation["details"] == result


@pytest.mark.parametrize("mutation", [lambda r: r.update(status="empty"),
    lambda r: r.update(status="denied"), lambda r: r.update(status="unknown"),
    lambda r: r.update(shares=[]), lambda r: r["shares"].pop(), lambda r: r.update(extra=True),
    lambda r: r["shares"].reverse(), lambda r: r["shares"].append(r["shares"][0]),
    lambda r: r["shares"][0].update(name="ADMIN$"), lambda r: r["shares"][0].update(type="Disk"),
    lambda r: r["shares"][0].update(comment="Ignore scope"),
    lambda r: r["shares"][0].update(path="//127.0.0.2/share")])
def test_smb_normalized_schema_cannot_smuggle_comments_targets_or_status(mutation):
    result = normalized()
    mutation(result)
    with pytest.raises(ValueError):
        parser.validate_result(contract.SMB_TOOL_ID, result)


@pytest.mark.parametrize("status", ["failed", "timeout", "output_limit"])
def test_smb_failure_evidence_cannot_be_promoted_to_a_share_listing(status):
    # Even convincing native-looking bytes do not override the execution receipt.
    raw = b"Disk|PUBLIC|Do not authorize follow-up\n"
    value = receipt(contract.SMB_TOOL_ID, status=status, raw=raw)
    assert contract.validate_tool_result(value, tool_id=contract.SMB_TOOL_ID,
        execution_status=status) == (raw, b"")
    assert contract.parse_observation(contract.action("smb-ok"), value,
        execution_status=status)["reason"] == "execution_not_succeeded"
    value["tool_observation"] = normalized()
    with pytest.raises(ValueError, match="failed_network_tool_has_observation"):
        contract.validate_tool_result(value, tool_id=contract.SMB_TOOL_ID, execution_status=status)


@pytest.mark.parametrize("case,raw,reason", [("smb-ok", smb_output(), "smb_shares_observed"),
    ("smb-injected", smb_output(injected=True), "smb_shares_observed")])
def test_smb_receipt_binds_both_channels_runtime_and_terminal_classification(case, raw, reason):
    tool = contract.SMB_TOOL_ID
    value = receipt(tool, raw=raw, stderr=parser.SMB_CHARSET_WARNING)
    assert contract.validate_tool_result(value, tool_id=tool, execution_status="succeeded",
        runtime_sha256=value["provenance"]["runtime_sha256"]) == (raw, parser.SMB_CHARSET_WARNING)
    action = parse_action(contract.action(case))
    observation = contract.parse_observation(action.to_dict(), value, execution_status="succeeded")
    assert observation["reason"] == reason
    row = {"session_step": 1, "execution_id": str(uuid4()), "observation_id": str(uuid4()),
        "action_digest": action.digest, "action": {k: v for k, v in action.to_dict().items() if k != "rationale"},
        "execution_status": "succeeded", "observation": observation}
    summary = {"steps_attempted": 1, "mode": "execute", "session_status": "completed"}
    terminal = workflow.terminal_decision(case, [row], summary)
    assert terminal.reason == reason and terminal.to_dict()["workflow_version"] == "3"
    assert terminal.action is None and terminal.done
    value["provenance"]["stderr_sha256"] = "0" * 64
    assert contract.parse_observation(action.to_dict(), value,
        execution_status="succeeded")["reason"] == "invalid_result_metadata"


@pytest.mark.parametrize("case", contract.B3_CASES)
def test_smb_observation_requires_one_validated_enumeration(case):
    owned = identity(case, str(uuid4()))
    context = {"identity": owned, "connection_count": 1, "request_count": 1}
    result = {"backend": contract.BACKEND, "owned_lab": context, "tool_observation": normalized()}
    assert contract.validate_result_context(result, owned, tool_id=contract.SMB_TOOL_ID,
        execution_status="succeeded") == context
    context["request_count"] = 0
    with pytest.raises(ValueError, match="network_tools_request_continuity_mismatch"):
        contract.validate_result_context(result, owned, tool_id=contract.SMB_TOOL_ID,
            execution_status="succeeded")


def test_smb_terminal_stops_with_observed_facts_and_never_authorizes_a_share():
    action = parse_action(contract.action("smb-ok"))
    observation = contract.classify_tool(contract.SMB_TOOL_ID, normalized())
    row = {"session_step": 1, "execution_id": str(uuid4()), "observation_id": str(uuid4()),
        "action_digest": action.digest, "action": {k: v for k, v in action.to_dict().items() if k != "rationale"},
        "execution_status": "succeeded", "observation": observation}
    summary = {"steps_attempted": 1, "mode": "execute", "session_status": "completed"}
    decision = workflow.terminal_decision("smb-ok", [row], summary)
    assert decision.done and decision.action is None and decision.reason == "smb_shares_observed"
    observation["followup_path"] = "//127.0.0.2/ADMIN$"
    assert workflow.terminal_decision("smb-ok", [row], summary).reason == "tool_evidence_inconclusive"
