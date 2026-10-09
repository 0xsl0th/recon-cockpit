"""Adversarial saved-evidence cases; these are not native execution claims."""

import hashlib
import json
from copy import deepcopy

import pytest

from recon_cockpit.secure_agent import network_tools_tls_posture_parser as parser
from recon_cockpit.secure_agent import nmap_evidence as evidence
from test_network_tools_tls_posture_parser import sample
from test_network_tools_tls_posture_evidence import complete, portable_worker


VERSIONS = ("tls1", "tls1_1", "tls1_2", "tls1_3")


def _parse(tool, stdout, stderr, extra, owner=None):
    if owner is not None:
        extra = {**extra, "owner_raw": json.dumps(owner).encode("ascii")}
    return parser.parse_input(parser.encode_input(tool, stdout, stderr, **extra))


def _alter_record_body(row, offset=12):
    raw = bytearray.fromhex(row["raw_hex"])
    raw[offset] ^= 1
    row["raw_hex"] = raw.hex()
    return bytes(raw)


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("rejection", (False, True))
def test_coherent_client_wire_ledgers_must_match_actual_client_hello(version, rejection):
    tool, stdout, stderr, extra = sample(version, rejection=rejection)
    owner = json.loads(extra["owner_raw"])
    assert _parse(tool, stdout, stderr, extra)["useful_task_completed"] is True
    # The three raw ledgers agree with one another, but disagree with the
    # client trace and independent peer handshake callback. Header checks alone
    # cannot detect this contradiction because record lengths remain identical.
    for rows in (owner["diagnostic"]["received_records"],
                 owner["mediation"]["client_ingress_records"],
                 owner["mediation"]["client_forwarded_records"]):
        _alter_record_body(rows[0])
    with pytest.raises(ValueError, match="plaintext_handshake_mismatch"):
        _parse(tool, stdout, stderr, extra, owner)


@pytest.mark.parametrize("version", VERSIONS)
def test_coherent_server_wire_commitments_must_match_client_received_server_hello(version):
    tool, stdout, stderr, extra = sample(version)
    owner = json.loads(extra["owner_raw"])
    raw = _alter_record_body(owner["diagnostic"]["sent_records"][0])
    for field in ("server_ingress_records", "server_forwarded_records"):
        owner["mediation"][field][0]["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="plaintext_handshake_mismatch"):
        _parse(tool, stdout, stderr, extra, owner)


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("rejection", (False, True))
@pytest.mark.parametrize("change", (
    "partial_stdout", "invalid_utf8", "contradictory_protocol", "contradictory_cipher",
    "missing_peer_bytes", "changed_peer_hash", "missing_mediator_records",
    "peer_incomplete", "peer_error", "application_activity", "partial_send",
    "deadline_expired", "unjoined_owner", "extra_peer_stream",
))
def test_incomplete_or_contradictory_evidence_never_becomes_useful(version, rejection, change):
    tool, stdout, stderr, extra = sample(version, rejection=rejection)
    owner = json.loads(extra["owner_raw"])
    if change == "partial_stdout":
        stdout = stdout[:len(stdout) // 2]
    elif change == "invalid_utf8":
        stderr += b"\xff"
    elif change == "contradictory_protocol":
        stderr += b"Protocol version: TLSv9\n"
    elif change == "contradictory_cipher":
        stderr += b"Ciphersuite: NONE\n"
    elif change == "missing_peer_bytes":
        owner["diagnostic"]["received_records"] = []
        owner["diagnostic"]["received_bytes"] = 0
    elif change == "changed_peer_hash":
        owner["diagnostic"]["handshake_messages"][0]["sha256"] = "0" * 64
    elif change == "missing_mediator_records":
        owner["mediation"]["server_forwarded_records"] = []
        owner["mediation"]["server_forwarded_bytes"] = 0
    elif change == "peer_incomplete":
        owner["diagnostic"]["completed"] = False
    elif change == "peer_error":
        owner["diagnostic"]["error"] = "ConnectionResetError"
    elif change == "application_activity":
        owner["diagnostic"]["application_bytes"] = 1
    elif change == "partial_send":
        owner["mediation"]["client_transmitted_bytes"] -= 1
    elif change == "deadline_expired":
        owner["mediation"]["connection_deadline_expired"] = True
    elif change == "unjoined_owner":
        owner["mediation"]["threads_joined"] = False
    elif change == "extra_peer_stream":
        owner["mediation"]["peer_streams_admitted"] = 2
    with pytest.raises(ValueError):
        _parse(tool, stdout, stderr, extra, owner)


@pytest.mark.parametrize("change", ("not_attempted", "not_forwarded_prefix", "not_peer_eof",
                                     "retry_peer_received", "client_claims_success"))
def test_retry_safety_claim_requires_attempt_and_independent_prevention(change):
    tool, stdout, stderr, extra = sample(hrr=True)
    owner = json.loads(extra["owner_raw"])
    assert _parse(tool, stdout, stderr, extra)["extra_client_hello_prevented"] is True
    if change == "not_attempted":
        removed = owner["mediation"]["client_ingress_records"].pop()
        owner["mediation"]["client_ingress_bytes"] -= 5 + removed["payload_length"]
    elif change == "not_forwarded_prefix":
        _alter_record_body(owner["mediation"]["client_ingress_records"][0])
    elif change == "not_peer_eof":
        owner["diagnostic"]["error"] = "ConnectionResetError"
    elif change == "retry_peer_received":
        retry = deepcopy(owner["mediation"]["client_ingress_records"][-1])
        owner["diagnostic"]["received_records"].append(retry)
        owner["diagnostic"]["received_bytes"] += 5 + retry["payload_length"]
        owner["diagnostic"]["client_hellos"] = 2
    elif change == "client_claims_success":
        stderr += b"CONNECTION ESTABLISHED\n"
    with pytest.raises(ValueError):
        _parse(tool, stdout, stderr, extra, owner)


@pytest.mark.parametrize("change", ("world_readable", "directory", "hardlink", "filename", "representation"))
def test_owner_artifact_filesystem_and_reference_confusion_stays_inconclusive(tmp_path, change):
    directory = tmp_path / "bundle"
    complete(directory, rejection=True)
    owner = next(directory.glob("tls-owner-*.json"))
    if change == "world_readable":
        owner.chmod(0o644)
    elif change == "directory":
        owner.unlink()
        owner.mkdir(mode=0o700)
    elif change == "hardlink":
        (tmp_path / "second-link.json").hardlink_to(owner)
    else:
        artifact = next(directory.glob("result-*.json"))
        result = json.loads(artifact.read_bytes())
        result["tls_posture_owner"][change] = "untrusted"
        artifact.write_text(json.dumps(result))
    report = evidence.inspect_evidence(directory)
    assert report["outcome"] == "inconclusive"
    assert report["integrity_issues"]
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["tested_unauthorized_actions_blocked"] == 0


@pytest.mark.parametrize("version", VERSIONS)
def test_uninterpretable_owner_cannot_be_silently_dropped_from_failed_result(version, monkeypatch):
    from test_network_tools_tls_posture_evidence import receipt
    from recon_cockpit.secure_agent import network_tools_contract as contract

    tool, result = receipt(version, rejection=True)
    result["tls_posture_owner"]["raw_base64"] = "e30="
    result["tool_observation"] = None
    with pytest.raises(ValueError):
        contract.validate_tool_result(result, tool_id=tool, execution_status="failed")
