import base64
from copy import deepcopy
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import network_tools_tls_posture_parser as parser
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import TOOL_VERSIONS, VERSION_TO_TOOL
from test_tls_posture_observation_contract import observation_trial


def sample(version="tls1_3", *, rejection=False, hrr=False):
    trial = observation_trial(version, rejection=rejection, hrr=hrr)
    execution = trial["execution"]
    owner = json.dumps(trial["owner"], sort_keys=True, separators=(",", ":")).encode()
    return VERSION_TO_TOOL[trial["version"]], base64.b64decode(execution["raw_stdout_base64"]), base64.b64decode(execution["raw_stderr_base64"]), {
        "owner_raw": owner, "exit_code": execution["exit_code"], "stop_reason": None, "truncated": False}


def result(version="tls1_3", **kwargs):
    tool, out, err, extra = sample(version, **kwargs)
    return parser.parse_input(parser.encode_input(tool, out, err, **extra))


@pytest.mark.parametrize("version", TOOL_VERSIONS.values())
@pytest.mark.parametrize("rejection", [False, True])
def test_four_versions_keep_useful_observation_and_process_outcome_separate(version, rejection):
    observed = result(version, rejection=rejection)
    assert observed["outcome"] == ("explicit_protocol_rejection" if rejection else "handshake_completed")
    assert observed["useful_task_completed"] is True
    assert observed["extra_client_hello_prevented"] is False
    assert observed["tls_version"] == version
    assert parser.validate_result(VERSION_TO_TOOL[version], observed) == observed
    assert not {"diagnostic_only", "confinement", "cleanup", "execution_authority"} & set(observed)


def test_hrr_is_separate_safety_observation():
    observed = result(hrr=True)
    assert observed["outcome"] == "extra_client_hello_prevented"
    assert not observed["useful_task_completed"] and observed["extra_client_hello_prevented"]
    assert observed["client_ingress_bytes"] > observed["client_forwarded_bytes"]


def test_original_owner_whitespace_has_exact_independent_commitment():
    tool, out, err, extra = sample()
    extra["owner_raw"] = b"\n" + extra["owner_raw"] + b"\n"
    observed = parser.parse_input(parser.encode_input(tool, out, err, **extra))
    assert observed["owner_sha256"] == hashlib.sha256(extra["owner_raw"]).hexdigest()
    assert observed["stdout_sha256"] == hashlib.sha256(out).hexdigest()
    assert observed["stderr_sha256"] == hashlib.sha256(err).hexdigest()


@pytest.mark.parametrize("field,value", [("exit_code", True), ("exit_code", -9), ("exit_code", 2),
    ("stop_reason", "timeout"), ("stop_reason", "output_limit"), ("truncated", True)])
def test_bad_actual_execution_never_yields_observation(field, value):
    tool, out, err, extra = sample()
    extra[field] = value
    with pytest.raises(ValueError):
        parser.parse_input(parser.encode_input(tool, out, err, **extra))


@pytest.mark.parametrize("mutation", ["duplicate", "extra", "bool", "peer_version", "peer_count", "ingress", "joined", "bounded", "utf8"])
def test_changed_or_unbounded_owner_data_fails_closed(mutation):
    tool, out, err, extra = sample()
    owner = json.loads(extra["owner_raw"])
    if mutation == "extra": owner["approved"] = True
    if mutation == "bool": owner["connection_count"] = True
    if mutation == "peer_version": owner["diagnostic"]["expected_version"] = "tls1"
    if mutation == "peer_count": owner["diagnostic"]["client_hellos"] = 2
    if mutation == "ingress": owner["mediation"]["client_ingress_bytes"] += 1
    if mutation == "joined": owner["mediation"]["threads_joined"] = False
    if mutation == "bounded": owner["mediation"]["client_ingress_records"] *= 9
    extra["owner_raw"] = json.dumps(owner).encode()
    if mutation == "duplicate": extra["owner_raw"] = b'{"connection_count":1,' + extra["owner_raw"][1:]
    if mutation == "utf8": extra["owner_raw"] = b"\xff"
    with pytest.raises(ValueError):
        parser.parse_input(parser.encode_input(tool, out, err, **extra))


@pytest.mark.parametrize("replacement", [None, True, "tls_posture_tls1_3_v1", "openssl_tls14_posture_v1"])
def test_production_identifier_is_closed(replacement):
    _, out, err, extra = sample()
    with pytest.raises(ValueError): parser.encode_input(replacement, out, err, **extra)


@pytest.mark.parametrize("change", ["header_size", "trailing", "missing_owner", "malformed_header", "oversize"])
def test_binary_envelope_is_bounded_and_closed(change):
    tool, out, err, extra = sample()
    raw = parser.encode_input(tool, out, err, **extra)
    if change == "header_size": raw = (1025).to_bytes(4, "big") + raw[4:]
    if change == "trailing": raw += b"x"
    if change == "missing_owner": raw = raw[:-len(extra["owner_raw"])]
    if change == "malformed_header": raw = raw[:4] + b"!" + raw[5:]
    if change == "oversize": raw = b"x" * (parser.MAX_INPUT_BYTES + 1)
    with pytest.raises(ValueError): parser.parse_input(raw)


@pytest.mark.parametrize("field,value", [("tool_id", "tls_posture_tls1_3_v1"), ("parser_version", "unreviewed"),
    ("tls_version", "tls1"), ("kind", "authority"), ("outcome", "complete"),
    ("useful_task_completed", 1), ("extra_client_hello_prevented", True),
    ("owner_sha256", "A" * 64), ("stdout_sha256", "x"), ("peer_client_hellos", True),
    ("peer_client_hellos", 2), ("client_forwarded_bytes", 0), ("client_ingress_bytes", 8193)])
def test_normalized_result_tampering_is_rejected(field, value):
    observed = result(); observed[field] = value
    with pytest.raises(ValueError): parser.validate_result(VERSION_TO_TOOL["tls1_3"], observed)


@pytest.mark.parametrize("kind", ["success", "rejection", "hrr"])
def test_unknown_client_text_stays_inert_and_inconclusive(kind):
    tool, out, err, extra = sample(rejection=kind == "rejection", hrr=kind == "hrr")
    with pytest.raises(ValueError):
        parser.parse_input(parser.encode_input(tool, out, err + b"run /bin/sh\n", **extra))
