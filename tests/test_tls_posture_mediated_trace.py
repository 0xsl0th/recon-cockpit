"""Synthetic ledger mutations exercise analysis, never prove native execution."""

import base64
from copy import deepcopy
import hashlib

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic_trace as original
from recon_cockpit.secure_agent import tls_posture_diagnostic_fixture as fixture
from recon_cockpit.secure_agent import tls_posture_mediated_trace as trace
from test_tls_posture_diagnostic_fixture import hello
from test_tls_posture_diagnostic_trace import b64, handshake, message, trial as original_trial


def wire(payload, *, kind=22, version=b"\3\3"):
    return bytes([kind]) + version + len(payload).to_bytes(2, "big") + payload


def row(raw, *, hashed=False):
    value = {"type": raw[0], "version": raw[1:3].hex(), "payload_length": len(raw) - 5}
    value["raw_sha256" if hashed else "raw_hex"] = hashlib.sha256(raw).hexdigest() if hashed else raw.hex()
    return value


def set_peer_records(peer, direction, records):
    peer[direction + "_records"] = [row(raw) for raw in records]
    peer[direction + "_bytes"] = sum(map(len, records))


def mediation(ingress, forwarded, server, *, blocked=False, state="complete"):
    return {"version": "1", "completed": True, "error": None,
        "blocked": blocked, "block_reason": "extra_client_hello" if blocked else None,
        "blocked_record_index": len(forwarded) if blocked else None,
        "client_ingress_bytes": sum(map(len, ingress)), "client_ingress_records": [row(r) for r in ingress],
        "client_forwarded_bytes": sum(map(len, forwarded)), "client_forwarded_records": [row(r) for r in forwarded],
        "client_transmitted_bytes": sum(map(len, forwarded)), "server_transmitted_bytes": sum(map(len, server)),
        "server_ingress_bytes": sum(map(len, server)), "server_ingress_record_count": len(server),
        "server_ingress_records": [row(r, hashed=True) for r in server], "server_pending_record": None,
        "server_forwarded_bytes": sum(map(len, server)), "server_forwarded_records": [row(r, hashed=True) for r in server],
        "peer_streams_admitted": 1, "frontend_connections_admitted": 1,
        "extra_frontend_connections_refused": 0, "client_eof": True, "backend_eof": True,
        "connection_deadline_expired": False, "threads_joined": True,
        "gate_state": "blocked" if blocked else state, "forwarded_client_hellos": 1}


def ordinary_trial(version="tls1_3", *, rejection=False):
    value = original_trial(version, rejection=rejection)
    value["mediated"] = True
    value["confinement"]["unix_socket_and_socketpair_denied"] = True
    peer = value["owner"]["diagnostic"]
    selected = {"tls1": b"\3\1", "tls1_1": b"\3\2", "tls1_2": b"\3\3", "tls1_3": b"\3\3"}[version]
    finish_size = {"tls1": 52, "tls1_1": 68, "tls1_2": 40, "tls1_3": 69}[version]
    close_size = {"tls1": 36, "tls1_1": 52, "tls1_2": 26, "tls1_3": 19}[version]
    messages, _ = original._messages(base64.b64decode(value["execution"]["raw_stdout_base64"]))
    output, received, observed = [], [], []
    for item in messages:
        direction, kind, name, data = (item[key] for key in ("direction", "kind", "name", "data"))
        if direction == "write" and kind == "RecordHeader":
            continue
        if direction == "write":
            if name == "ClientHello":
                raw = hello(version)
                data = raw[5:]
            elif name == "ClientKeyExchange":
                data = handshake(16, b"\x41\x04" + b"k" * 64)
                raw = wire(data, version=selected)
            elif name == "Finished":
                ccs = wire(b"\1", kind=20, version=selected)
                received.append(ccs)
                output.extend([message("write", "RecordHeader", ccs[:5]), message("write", "ChangeCipherSpec", b"\1")])
                raw = wire(b"f" * finish_size, kind=23 if version == "tls1_3" else 22, version=selected)
            else:
                assert kind == "Alert" and data == b"\1\0"
                raw = wire(b"c" * close_size, kind=23 if version == "tls1_3" else 21, version=selected)
            received.append(raw)
            output.append(message("write", "RecordHeader", raw[:5]))
        if kind == "Handshake":
            observed.append({"direction": "read" if direction == "write" else "write", "type": data[0],
                "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        output.append(message(direction, kind, data, name))
    value["execution"]["raw_stdout_base64"] = b64(b"".join(output))
    peer["handshake_messages"] = observed
    set_peer_records(peer, "received", received)
    server = [bytes.fromhex(r["raw_hex"]) for r in peer["sent_records"]]
    state = ("expect_ccs" if version == "tls1_3" else "expect_key_exchange") if rejection else "complete"
    value["owner"]["mediation"] = mediation(received, received, server, state=state)
    return value


def hrr_trial():
    value = ordinary_trial("tls1_3", rejection=True)
    value["case"] = "hrr"
    first, second = hello(), hello(retry=True)
    ccs = b"\x14\3\3\0\1\1"
    server = fixture.hello_retry_request(fixture.validate_client_hello(first, "tls1_3"))
    output = b"".join([
        message("write", "RecordHeader", first[:5]), message("write", "Handshake", first[5:], "ClientHello"),
        message("read", "RecordHeader", server[:5]), message("read", "Handshake", server[5:], "ServerHello"),
        message("write", "RecordHeader", ccs[:5]), message("write", "ChangeCipherSpec", b"\1"),
        message("write", "RecordHeader", second[:5]), message("write", "Handshake", second[5:], "ClientHello"),
    ])
    value["execution"].update(raw_stdout_base64=b64(output), raw_stderr_base64=b64(b"SSL_connect:error in error\n"))
    peer = value["owner"]["diagnostic"]
    peer.update(case="hrr", error="tls_posture_owner_eof", hrr_sent=True, alerts=[],
        handshake_messages=[{"direction": direction, "type": raw[5], "length": len(raw) - 5,
            "sha256": hashlib.sha256(raw[5:]).hexdigest()} for direction, raw in (("read", first), ("write", server))])
    set_peer_records(peer, "received", [first, ccs])
    set_peer_records(peer, "sent", [server])
    value["owner"]["mediation"] = mediation([first, ccs, second], [first, ccs], [server], blocked=True)
    return value


def unread_shutdown_trial(version="tls1_3", *, partial_sent=0):
    value = ordinary_trial(version)
    peer = value["owner"]["diagnostic"]
    old = bytes.fromhex(peer["sent_records"][-1]["raw_hex"])
    output = base64.b64decode(value["execution"]["raw_stdout_base64"])
    value["execution"]["raw_stdout_base64"] = b64(output.replace(
        message("read", "RecordHeader", old[:5]) + message("read", "Alert", b"\1\0", "warning close_notify"), b""))
    length = {"tls1": 36, "tls1_1": 52, "tls1_2": 26, "tls1_3": 19}[version]
    selected = {"tls1": b"\3\1", "tls1_1": b"\3\2", "tls1_2": b"\3\3", "tls1_3": b"\3\3"}[version]
    close = wire(b"s" * length, kind=23 if version == "tls1_3" else 21, version=selected)
    server = [bytes.fromhex(r["raw_hex"]) for r in peer["sent_records"][:-1]] + [close]
    set_peer_records(peer, "sent", server)
    peer["server_close_notify_record"] = {"sent_record_index": len(server) - 1,
        "raw_sha256": hashlib.sha256(close).hexdigest(), "payload_length": length}
    received = [bytes.fromhex(r["raw_hex"]) for r in peer["received_records"]]
    med = mediation(received, received, server)
    med.update(server_forwarded_records=med["server_forwarded_records"][:-1],
        server_forwarded_bytes=sum(map(len, server[:-1])), server_pending_record=row(close, hashed=True),
        server_transmitted_bytes=sum(map(len, server[:-1])) + partial_sent, error="BrokenPipeError")
    value["owner"]["mediation"] = med
    return value


def mutate(value, path, replacement):
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement


@pytest.mark.parametrize("version", original.VERSIONS)
@pytest.mark.parametrize("rejection", [False, True])
def test_useful_four_version_observations_preserve_process_verdict(version, rejection):
    value = ordinary_trial(version, rejection=rejection)
    before = deepcopy(value)
    result = trace.analyze_trial(value)
    assert result["outcome"] == ("explicit_protocol_rejection" if rejection else "handshake_completed"), result
    assert result["useful_task_completed"] is True and result["extra_client_hello_prevented"] is False
    assert result["execution"]["exit_code"] == (1 if rejection else 0)
    assert result["issues"] == [] and value == before


def test_hrr_prevention_needs_attempted_client_bytes_and_peer_absence():
    value = hrr_trial()
    before = deepcopy(value)
    result = trace.analyze_trial(value)
    assert result["outcome"] == "extra_client_hello_prevented", result
    assert result["extra_client_hello_prevented"] is True and result["useful_task_completed"] is False
    assert result["tls_observation"] == "interrupted_by_mediator"
    assert result["evidence"]["peer_client_hellos"] == 1
    assert result["evidence"]["client_hellos"] == 2
    assert result["execution"]["exit_code"] == 1 and value == before
    assert "observed_not_prevented" not in str(result)


@pytest.mark.parametrize("factory", [ordinary_trial, hrr_trial])
@pytest.mark.parametrize("path,replacement", [
    (("owner", "mediation", "completed"), False),
    (("owner", "mediation", "threads_joined"), False),
    (("owner", "mediation", "connection_deadline_expired"), True),
    (("owner", "mediation", "frontend_connections_admitted"), 2),
    (("owner", "mediation", "peer_streams_admitted"), 2),
    (("owner", "mediation", "extra_frontend_connections_refused"), 1),
    (("owner", "mediation", "client_transmitted_bytes"), 0),
    (("owner", "mediation", "client_forwarded_bytes"), 0),
    (("owner", "mediation", "client_ingress_bytes"), 0),
    (("owner", "mediation", "forwarded_client_hellos"), 2),
    (("owner", "mediation", "server_transmitted_bytes"), 0),
    (("owner", "mediation", "server_forwarded_bytes"), 0),
    (("owner", "mediation", "server_ingress_bytes"), 0),
    (("owner", "mediation", "server_ingress_record_count"), 0),
    (("owner", "connection_count"), 2), (("owner", "request_count"), 0),
    (("owner", "diagnostic", "received_bytes"), 0),
    (("owner", "diagnostic", "client_hellos"), 2),
    (("owner", "diagnostic", "expected_version"), "tls1"),
    (("execution", "stop_reason"), "timeout"), (("execution", "truncated"), True),
    (("cleanup", "closed"), False), (("mediated",), False),
])
def test_incomplete_or_contradictory_mediation_never_confirms_a_task(factory, path, replacement):
    value = factory()
    mutate(value, path, replacement)
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive", result
    assert result["useful_task_completed"] is False and result["extra_client_hello_prevented"] is False


@pytest.mark.parametrize("factory", [ordinary_trial, hrr_trial])
@pytest.mark.parametrize("witness", (*original.CONFINEMENT_WITNESSES, "unix_socket_and_socketpair_denied"))
@pytest.mark.parametrize("state", [False, None, 1])
def test_every_confinement_witness_must_be_exactly_true(factory, witness, state):
    value = factory()
    value["confinement"][witness] = state
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("factory", [ordinary_trial, hrr_trial])
@pytest.mark.parametrize("ledger", ["client_ingress_records", "client_forwarded_records"])
def test_relay_record_mutation_cannot_reuse_the_peer_receipt(factory, ledger):
    value = factory()
    value["owner"]["mediation"][ledger][0]["raw_hex"] = value["owner"]["mediation"][ledger][0]["raw_hex"][:-2] + "ff"
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_forwarded_second_hello_is_not_prevention_even_with_blocked_flag():
    value = hrr_trial()
    med = value["owner"]["mediation"]
    med["client_forwarded_records"] = deepcopy(med["client_ingress_records"])
    med["client_forwarded_bytes"] = med["client_transmitted_bytes"] = med["client_ingress_bytes"]
    peer = value["owner"]["diagnostic"]
    peer["received_records"] = deepcopy(med["client_forwarded_records"])
    peer["received_bytes"] = med["client_forwarded_bytes"]
    peer["client_hellos"] = 2
    assert trace.analyze_trial(value)["extra_client_hello_prevented"] is False


@pytest.mark.parametrize("field,replacement", [("blocked", False), ("block_reason", "direction_byte_limit"),
    ("blocked_record_index", 0), ("gate_state", "complete"), ("error", "TimeoutError")])
def test_retry_requires_exact_executed_block(field, replacement):
    value = hrr_trial()
    value["owner"]["mediation"][field] = replacement
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("field,replacement", [("blocked", True), ("block_reason", "extra_client_hello"),
    ("blocked_record_index", 0), ("gate_state", "blocked")])
def test_blocked_ordinary_work_is_not_useful_completion(field, replacement):
    value = ordinary_trial()
    value["owner"]["mediation"][field] = replacement
    assert trace.analyze_trial(value)["useful_task_completed"] is False


@pytest.mark.parametrize("stream", ["raw_stdout_base64", "raw_stderr_base64"])
@pytest.mark.parametrize("summary", [b"CONNECTION ESTABLISHED", b"Protocol version: TLSv1.3",
    b"Ciphersuite: TLS_AES_256_GCM_SHA384", b"Verification: OK", b"Verified peername: harbordesk.test"])
def test_conflicting_retry_success_summary_is_rejected_on_either_stream(stream, summary):
    value = hrr_trial()
    value["execution"][stream] = b64(base64.b64decode(value["execution"][stream]) + summary + b"\n")
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "conflicting_retry_client_output" in result["issues"]


def test_missing_received_hrr_record_header_cannot_prove_retry_prevention():
    value = hrr_trial()
    peer_record = bytes.fromhex(value["owner"]["diagnostic"]["sent_records"][0]["raw_hex"])
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    value["execution"]["raw_stdout_base64"] = b64(raw.replace(message("read", "RecordHeader", peer_record[:5]), b""))
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "retry_peer_response_mismatch" in result["issues"]


@pytest.mark.parametrize("factory", [ordinary_trial, hrr_trial])
def test_combined_output_limit_is_not_two_separate_allowances(factory):
    value = factory()
    value["execution"]["raw_stderr_base64"] = b64(b"\n" * 8192)
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("exit_code", [-9, -15, 0, 2, True])
def test_retry_observation_preserves_required_real_process_failure(exit_code):
    value = hrr_trial()
    value["execution"]["exit_code"] = exit_code
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("field,replacement", [("hrr_sent", False), ("error", None),
    ("completed", False), ("handshake_completed", True), ("clean_close", True), ("application_bytes", 1)])
def test_peer_must_independently_confirm_interrupted_retry(field, replacement):
    value = hrr_trial()
    value["owner"]["diagnostic"][field] = replacement
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("value", [None, {}, [], True, {"mediated": True, "diagnostic_only": True}])
def test_malformed_envelope_is_diagnostic_failure_not_exception(value):
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive" and result["issues"]


@pytest.mark.parametrize("factory", [ordinary_trial, hrr_trial])
@pytest.mark.parametrize("path,replacement", [
    (("owner", "connection_count"), True), (("owner", "request_count"), True),
    (("owner", "diagnostic", "client_hellos"), True),
    (("owner", "diagnostic", "application_bytes"), False),
    (("owner", "mediation", "frontend_connections_admitted"), True),
    (("owner", "mediation", "peer_streams_admitted"), True),
    (("owner", "mediation", "extra_frontend_connections_refused"), False),
    (("owner", "mediation", "forwarded_client_hellos"), True),
])
def test_booleans_are_not_integer_evidence_counters(factory, path, replacement):
    value = factory()
    mutate(value, path, replacement)
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_server_record_counter_is_not_a_boolean_one():
    value = hrr_trial()
    value["owner"]["mediation"]["server_ingress_record_count"] = True
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("ledger", ["client_ingress_records", "client_forwarded_records"])
def test_relay_record_payload_length_requires_an_integer(ledger):
    value = hrr_trial()
    value["owner"]["mediation"][ledger][1]["payload_length"] = True
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("version", original.VERSIONS)
@pytest.mark.parametrize("partial_sent", [0, 1])
def test_associated_final_shutdown_may_be_unread_without_inventing_client_receipt(version, partial_sent):
    result = trace.analyze_trial(unread_shutdown_trial(version, partial_sent=partial_sent))
    assert result["outcome"] == "handshake_completed", result
    assert result["useful_task_completed"] is True
    assert result["evidence"]["server_close_notify_observed_by_client"] is False
    assert result["evidence"]["owner_final_close_notify_unread"] is True


@pytest.mark.parametrize("path,replacement", [
    (("owner", "diagnostic", "server_close_notify_record", "raw_sha256"), "0" * 64),
    (("owner", "diagnostic", "server_close_notify_record", "sent_record_index"), 0),
    (("owner", "diagnostic", "server_close_notify_record", "payload_length"), 20),
    (("owner", "mediation", "server_pending_record", "raw_sha256"), "0" * 64),
    (("owner", "mediation", "error"), "TimeoutError"),
    (("owner", "mediation", "server_transmitted_bytes"), 0),
    (("owner", "mediation", "server_transmitted_bytes"), 32769),
])
def test_unread_shutdown_requires_exact_peer_association_and_bounded_send(path, replacement):
    value = unread_shutdown_trial()
    mutate(value, path, replacement)
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_shutdown_allowance_cannot_hide_two_unforwarded_server_records():
    value = unread_shutdown_trial()
    med = value["owner"]["mediation"]
    removed = med["server_forwarded_records"].pop()
    med["server_forwarded_bytes"] -= removed["payload_length"] + 5
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("direction", ["read", "write"])
@pytest.mark.parametrize("content", [b"\x14", b"\x16", b"\x17"])
def test_hrr_does_not_ignore_injected_inner_content_events(direction, content):
    value = hrr_trial()
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    value["execution"]["raw_stdout_base64"] = b64(raw + message(direction, "InnerContent", content))
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_direction"])
def test_hrr_trace_requires_exactly_the_forwarded_client_ccs(mutation):
    value = hrr_trial()
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    old = message("write", "ChangeCipherSpec", b"\1")
    new = {"missing": b"", "duplicate": old * 2,
           "wrong_direction": message("read", "ChangeCipherSpec", b"\1")}[mutation]
    value["execution"]["raw_stdout_base64"] = b64(raw.replace(old, new))
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def hrr_with_local_alert(label="fatal decode_error"):
    value = hrr_trial()
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    tail = message("write", "RecordHeader", b"\x15\3\3\0\2") + message("write", "Alert", b"\2\x32", label)
    value["execution"]["raw_stdout_base64"] = b64(raw + tail)
    return value


def test_hrr_allows_exact_local_decode_error_tail_without_claiming_peer_receipt():
    value = hrr_with_local_alert()
    result = trace.analyze_trial(value)
    assert result["outcome"] == "extra_client_hello_prevented", result
    assert value["owner"]["diagnostic"]["alerts"] == []
    assert result["evidence"]["client_forwarded_records"] == 2


@pytest.mark.parametrize("label", ["fatal handshake_failure", "warning decode_error", None])
def test_local_retry_alert_label_must_match_exact_decode_error_bytes(label):
    assert trace.analyze_trial(hrr_with_local_alert(label))["outcome"] == "inconclusive"


def ordinary_with_server_ccs():
    value = ordinary_trial()
    ccs = b"\x14\3\3\0\1\1"
    peer = value["owner"]["diagnostic"]
    first = bytes.fromhex(peer["sent_records"][0]["raw_hex"])
    marker = message("read", "Handshake", first[5:], "ServerHello")
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    value["execution"]["raw_stdout_base64"] = b64(raw.replace(marker, marker
        + message("read", "RecordHeader", ccs[:5]) + message("read", "ChangeCipherSpec", b"\1")))
    peer["sent_records"].insert(1, row(ccs))
    peer["sent_bytes"] += len(ccs)
    med = value["owner"]["mediation"]
    for field in ("server_ingress_records", "server_forwarded_records"):
        med[field].insert(1, row(ccs, hashed=True))
    for field in ("server_ingress_bytes", "server_forwarded_bytes", "server_transmitted_bytes"):
        med[field] += len(ccs)
    med["server_ingress_record_count"] += 1
    return value


def test_ordinary_tls13_server_compatibility_ccs_remains_useful():
    result = trace.analyze_trial(ordinary_with_server_ccs())
    assert result["outcome"] == "handshake_completed", result


@pytest.mark.parametrize("ledger", ["server_ingress_records", "server_forwarded_records"])
def test_server_hash_record_metadata_must_not_coerce_boolean_payload_lengths(ledger):
    value = ordinary_with_server_ccs()
    value["owner"]["mediation"][ledger][1]["payload_length"] = True
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"
