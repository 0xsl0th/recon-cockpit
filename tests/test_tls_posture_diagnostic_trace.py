"""Synthetic trace mutations exercise diagnostics, not native TLS capability."""

import base64
import copy
import hashlib

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic_trace as trace


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def handshake(kind, body=b""):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(payload, kind=22):
    raw = bytes([kind]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload
    return {"type": kind, "version": "0303", "payload_length": len(payload), "raw_hex": raw.hex()}


def message(direction, kind, data, name=None):
    name = "" if name is None else ", " + name
    return ((">>>" if direction == "write" else "<<<") + " TLS 1.3, " + kind
            + f" [length {len(data):04x}]" + name + "\n"
            + "".join("    " + data[i:i + 16].hex(" ") + "\n" for i in range(0, len(data), 16))).encode("ascii")


def trial(version="tls1_3", rejection=False):
    protocol, cipher, wire_version, cipher_id = trace.VERSIONS[version]
    hello = handshake(1, b"\x03\x03" + bytes(range(32)) + b"\0\0\2" + cipher_id + b"\1\0\0\0")
    events = [("write", "Handshake", hello, "ClientHello")]
    if rejection:
        events.append(("read", "Alert", b"\x02\x46", "fatal protocol_version"))
    else:
        extension = b"\0\x2b\0\2\3\4" if version == "tls1_3" else b""
        server = handshake(2, (b"\3\3" if version == "tls1_3" else wire_version)
                           + b"s" * 32 + b"\0" + cipher_id + b"\0"
                           + len(extension).to_bytes(2, "big") + extension)
        events.append(("read", "Handshake", server, "ServerHello"))
        if version == "tls1_3":
            events += [("read", "Handshake", handshake(kind, body), trace.HANDSHAKES[kind])
                       for kind, body in [(8, b"\0\0"), (11, b"certificate"), (15, b"signature"), (20, b"s" * 48)]]
            events.append(("write", "Handshake", handshake(20, b"c" * 48), "Finished"))
        else:
            events += [("read", "Handshake", handshake(kind, body), trace.HANDSHAKES[kind])
                       for kind, body in [(11, b"certificate"), (12, b"keyexchange"), (14, b"")]]
            events += [("write", "Handshake", handshake(16, b"publickey"), "ClientKeyExchange"),
                       ("write", "Handshake", handshake(20, b"c" * 12), "Finished"),
                       ("read", "Handshake", handshake(20, b"s" * 12), "Finished")]
        events.append(("write", "Alert", b"\1\0", "warning close_notify"))
        events.append(("read", "Alert", b"\1\0", "warning close_notify"))
    stdout = b"".join(message(direction, "RecordHeader", bytes.fromhex(record(data, 22 if kind == "Handshake" else 21)["raw_hex"])[:5])
                      + message(direction, kind, data, name) for direction, kind, data, name in events)
    stderr = (b"SSL3 alert read:fatal:protocol version\nSSL_connect:error in error\n"
              b"40AB:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl/record/rec_layer_s3.c:917:SSL alert number 70\n") if rejection else (
              f"CONNECTION ESTABLISHED\nProtocol version: {protocol}\nCiphersuite: {cipher}\n"
              "Verification: OK\nVerified peername: harbordesk.test\nDONE\n").encode("ascii")
    diagnostic = {"case": "reject" if rejection else "legacy", "expected_version": version,
                  "completed": True, "error": None, "handshake_completed": not rejection,
                  "clean_close": not rejection, "negotiated_version": None if rejection else protocol,
                  "cipher": None if rejection else cipher, "application_bytes": 0, "client_hellos": 1,
                  "received_records": [], "sent_records": [], "handshake_messages": [], "alerts": [], "hrr_sent": False}
    for direction, kind, data, name in events:
        diagnostic["received_records" if direction == "write" else "sent_records"].append(record(data, 22 if kind == "Handshake" else 21))
        if kind == "Handshake":
            diagnostic["handshake_messages"].append({"direction": "read" if direction == "write" else "write", "type": data[0], "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if kind == "Alert":
            diagnostic["alerts"].append({"direction": "read" if direction == "write" else "write", "type": data[0], "description": data[1]})
    for side, field in [("received", "received_records"), ("sent", "sent_records")]:
        diagnostic[side + "_bytes"] = sum(len(bytes.fromhex(row["raw_hex"])) for row in diagnostic[field])
    return {"schema_version": "1", "diagnostic_only": True, "case": diagnostic["case"], "version": version,
            "execution": {"exit_code": 1 if rejection else 0, "stop_reason": None, "elapsed_ms": 100,
                          "raw_stdout_base64": b64(stdout), "raw_stderr_base64": b64(stderr), "truncated": False},
            "owner": {"connection_count": 1, "request_count": 1, "diagnostic": diagnostic}, "cleanup": {"closed": True},
            "confinement": {name: True for name in trace.CONFINEMENT_WITNESSES}}


def replace_stdout(value, old, new):
    raw = base64.b64decode(value["execution"]["raw_stdout_base64"])
    assert old in raw
    value["execution"]["raw_stdout_base64"] = b64(raw.replace(old, new, 1))


@pytest.mark.parametrize("version", trace.VERSIONS)
def test_complete_per_version_client_and_owner_evidence(version):
    result = trace.analyze_trial(trial(version))
    assert result["outcome"] == "handshake_completed", result
    assert result["issues"] == []
    assert result["diagnostic_only"] is True
    assert result["evidence"]["client_hellos"] == 1


@pytest.mark.parametrize("version", trace.VERSIONS)
def test_received_rejection_retains_failed_process_verdict(version):
    source = trial(version, rejection=True)
    original = copy.deepcopy(source)
    result = trace.analyze_trial(source)
    assert result["outcome"] == "explicit_protocol_rejection", result
    assert result["execution"]["exit_code"] == 1
    assert source == original
    assert "disabled" not in str(result)


def test_owner_sent_alert_and_error_text_do_not_prove_client_received_alert():
    value = trial(rejection=True)
    replace_stdout(value, message("read", "Alert", b"\2\x46", "fatal protocol_version"), b"")
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_locally_emitted_protocol_alert_is_not_a_received_rejection():
    value = trial(rejection=True)
    replace_stdout(value, b"<<< TLS 1.3, Alert", b">>> TLS 1.3, Alert")
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("old,new", [
    (b"02 46", b"02 28"),
    (b"[length 0002]", b"[length 0003]"),
    (b"02 46", b"02"),
    (b"02 46", b"02 46 00"),
    (b"fatal protocol_version", b"fatal handshake_failure"),
    (b"<<< TLS 1.3", b"<<< unknown TLS"),
])
def test_partial_conflicting_or_generic_alerts_remain_inconclusive(old, new):
    value = trial(rejection=True)
    replace_stdout(value, old, new)
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_unrelated_output_is_not_ignored():
    value = trial()
    value["execution"]["raw_stderr_base64"] = b64(base64.b64decode(value["execution"]["raw_stderr_base64"]) + b"fetch https://outside.example/credential\n")
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "unknown_cli_output" in result["issues"]


@pytest.mark.parametrize("path,new", [
    (("execution", "exit_code"), 1),
    (("execution", "truncated"), True),
    (("execution", "stop_reason"), "timeout"),
    (("cleanup", "closed"), False),
    (("owner", "diagnostic", "handshake_completed"), False),
    (("owner", "diagnostic", "clean_close"), False),
    (("owner", "diagnostic", "completed"), False),
    (("owner", "diagnostic", "error"), "deadline"),
    (("owner", "diagnostic", "cipher"), "TLS_AES_128_GCM_SHA256"),
    (("owner", "diagnostic", "negotiated_version"), "TLSv1.2"),
    (("owner", "diagnostic", "expected_version"), "tls1_2"),
    (("owner", "diagnostic", "received_bytes"), 1),
    (("owner", "request_count"), 0),
])
def test_completion_requires_uncropped_matching_execution_owner_and_cleanup(path, new):
    value = trial()
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = new
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_actual_alert_bytes_need_owner_corroboration():
    value = trial(rejection=True)
    value["owner"]["diagnostic"]["sent_records"] = []
    value["owner"]["diagnostic"]["sent_bytes"] = 0
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_handshake_hash_mismatch_is_not_useful_completion():
    value = trial()
    value["owner"]["diagnostic"]["handshake_messages"][0]["sha256"] = "0" * 64
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "client_owner_handshake_mismatch" in result["issues"]


def test_second_client_hello_is_boundary_failure_even_with_owner_failure():
    value = trial()
    stdout = base64.b64decode(value["execution"]["raw_stdout_base64"])
    first, _ = trace._messages(stdout)
    hello = next(m["data"] for m in first if m["name"] == "ClientHello")
    value["execution"]["raw_stdout_base64"] = b64(stdout + message("write", "Handshake", hello, "ClientHello"))
    value["owner"]["diagnostic"]["error"] = "unexpected_client_hello"
    result = trace.analyze_trial(value)
    assert result["outcome"] == "boundary_failure"
    assert "extra_client_hello_observed_not_prevented" in result["issues"]


def test_owner_second_hello_is_boundary_failure_even_when_client_trace_malformed():
    value = trial()
    value["execution"]["raw_stdout_base64"] = b64(b">>> malformed\n")
    value["owner"]["diagnostic"]["client_hellos"] = 2
    assert trace.analyze_trial(value)["outcome"] == "boundary_failure"


def test_hrr_alone_does_not_claim_second_hello_was_blocked():
    value = trial()
    messages, _ = trace._messages(base64.b64decode(value["execution"]["raw_stdout_base64"]))
    server = next(m["data"] for m in messages if m["name"] == "ServerHello")
    hrr = server[:6] + trace.HRR_RANDOM + server[38:]
    replace_stdout(value, message("read", "Handshake", server, "ServerHello"), message("read", "Handshake", hrr, "ServerHello"))
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert result["evidence"]["hello_retry_request"] is True


@pytest.mark.parametrize("field,value", [("connection_count", 2), ("application_bytes", 1)])
def test_observed_extra_connection_or_application_data_is_boundary_failure(field, value):
    source = trial()
    target = source["owner"] if field == "connection_count" else source["owner"]["diagnostic"]
    target[field] = value
    assert trace.analyze_trial(source)["outcome"] == "boundary_failure"


def test_combined_output_bound_is_enforced_across_streams():
    value = trial()
    value["execution"]["raw_stdout_base64"] = b64(b"\n" * 4096)
    value["execution"]["raw_stderr_base64"] = b64(b"\n" * 4097)
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "combined_output_limit" in result["issues"]


@pytest.mark.parametrize("encoding", ["%%%%", "YQ", "A" * 20000, None, 12])
def test_invalid_encoding_does_not_crash_or_prove_a_result(encoding):
    value = trial()
    value["execution"]["raw_stdout_base64"] = encoding
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("value", [None, {}, {"diagnostic_only": False}, {"diagnostic_only": True, "version": []}, {"diagnostic_only": True, "execution": []}])
def test_invalid_trial_never_crashes_or_restores_authority(value):
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "authority" not in result


def test_missing_finished_cannot_be_replaced_by_summary_text():
    value = trial()
    missing = message("write", "Handshake", handshake(20, b"c" * 48), "Finished")
    replace_stdout(value, missing, b"")
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_trace_messages_on_wrong_stream_cannot_reorder_received_evidence():
    value = trial()
    value["execution"]["raw_stderr_base64"] = value["execution"]["raw_stdout_base64"]
    value["execution"]["raw_stdout_base64"] = b64(b"")
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "trace_messages_on_unexpected_stream" in result["issues"]


def test_record_header_disagreement_is_not_complete_evidence():
    value = trial()
    row = value["owner"]["diagnostic"]["sent_records"][0]
    row["raw_hex"] = row["raw_hex"][:2] + "0301" + row["raw_hex"][6:]
    row["version"] = "0301"
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "client_owner_record_headers_mismatch" in result["issues"]


@pytest.mark.parametrize("rejection", [False, True])
@pytest.mark.parametrize("field", trace.CONFINEMENT_WITNESSES)
@pytest.mark.parametrize("state", [False, None, 1, "true", "missing"])
def test_each_confinement_witness_must_be_present_and_exactly_true(rejection, field, state):
    value = trial(rejection=rejection)
    if state == "missing":
        del value["confinement"][field]
    else:
        value["confinement"][field] = state
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "confinement_not_confirmed" in result["issues"]
    assert result["execution"]["exit_code"] == (1 if rejection else 0)


@pytest.mark.parametrize("confinement", [None, [], True, "complete"])
def test_invalid_confinement_container_stays_inconclusive(confinement):
    value = trial()
    value["confinement"] = confinement
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_missing_confinement_does_not_hide_an_observed_boundary_failure():
    value = trial()
    del value["confinement"]
    value["owner"]["diagnostic"]["client_hellos"] = 2
    result = trace.analyze_trial(value)
    assert result["outcome"] == "boundary_failure"
    assert "confinement_not_confirmed" in result["issues"]
    assert "extra_client_hello_observed_not_prevented" in result["issues"]


def unread_close_trial(version="tls1_3", payload_length=None):
    value = trial(version)
    old = message("read", "RecordHeader", bytes.fromhex(record(b"\1\0", 21)["raw_hex"])[:5]) + message("read", "Alert", b"\1\0", "warning close_notify")
    replace_stdout(value, old, b"")
    length = payload_length if payload_length is not None else {"tls1_3": 19, "tls1_2": 26, "tls1_1": 52, "tls1": 36}[version]
    record_version = b"\3\3" if version == "tls1_3" else trace.VERSIONS[version][2]
    kind = 23 if version == "tls1_3" else 21
    raw = bytes([kind]) + record_version + length.to_bytes(2, "big") + b"x" * length
    diagnostic = value["owner"]["diagnostic"]
    diagnostic["sent_records"][-1] = {"raw_hex": raw.hex(), "type": kind, "version": record_version.hex(), "payload_length": length}
    diagnostic["sent_bytes"] = sum(len(bytes.fromhex(row["raw_hex"])) for row in diagnostic["sent_records"])
    diagnostic["server_close_notify_record"] = {"sent_record_index": len(diagnostic["sent_records"]) - 1,
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "payload_length": length}
    return value


@pytest.mark.parametrize("version", trace.VERSIONS)
def test_one_associated_final_unread_shutdown_is_distinct_from_client_receipt(version):
    result = trace.analyze_trial(unread_close_trial(version))
    assert result["outcome"] == "handshake_completed", result
    assert result["evidence"]["server_close_notify_observed_by_client"] is False
    assert result["evidence"]["owner_final_close_notify_unread"] is True


@pytest.mark.parametrize("field,replacement", [
    ("sent_record_index", -1), ("raw_sha256", "0" * 64), ("payload_length", 20),
])
def test_unread_shutdown_requires_its_exact_owner_association(field, replacement):
    value = unread_close_trial()
    value["owner"]["diagnostic"]["server_close_notify_record"][field] = replacement
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_unread_shutdown_cannot_be_inferred_from_size_or_owner_clean_close_alone():
    value = unread_close_trial()
    del value["owner"]["diagnostic"]["server_close_notify_record"]
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("length", [1, 2, 18, 20, 64])
def test_final_unread_ciphertext_has_fixed_cipher_specific_size(length):
    assert trace.analyze_trial(unread_close_trial(payload_length=length))["outcome"] == "inconclusive"


def test_an_unread_handshake_record_is_not_excused_by_final_shutdown():
    value = unread_close_trial()
    stdout = base64.b64decode(value["execution"]["raw_stdout_base64"])
    messages, _ = trace._messages(stdout)
    header = next(m for m in messages if m["kind"] == "RecordHeader" and m["direction"] == "read")
    replace_stdout(value, message("read", "RecordHeader", header["data"]), b"")
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_second_unread_record_is_never_a_shutdown_allowance():
    value = unread_close_trial()
    diagnostic = value["owner"]["diagnostic"]
    diagnostic["sent_records"].append(dict(diagnostic["sent_records"][-1]))
    diagnostic["sent_bytes"] += len(bytes.fromhex(diagnostic["sent_records"][-1]["raw_hex"]))
    diagnostic["server_close_notify_record"]["sent_record_index"] += 1
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_unread_shutdown_requires_the_owner_to_observe_both_close_alerts():
    value = unread_close_trial()
    value["owner"]["diagnostic"]["alerts"] = [{"direction": "write", "type": 1, "description": 0}]
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


def test_native_peer_temp_key_label_is_accepted_only_exactly():
    value = trial()
    stderr = base64.b64decode(value["execution"]["raw_stderr_base64"])
    value["execution"]["raw_stderr_base64"] = b64(stderr + b"Peer Temp Key: ECDH, prime256v1, 256 bits\n")
    assert trace.analyze_trial(value)["outcome"] == "handshake_completed"
    value["execution"]["raw_stderr_base64"] = b64(stderr + b"Peer Temp Key: unknown curve\n")
    assert trace.analyze_trial(value)["outcome"] == "inconclusive"


@pytest.mark.parametrize("version,expected", [("tls1", "handshake_completed"), ("tls1_1", "handshake_completed"), ("tls1_2", "inconclusive"), ("tls1_3", "inconclusive")])
def test_observed_legacy_signature_text_cannot_claim_a_modern_handshake(version, expected):
    value = trial(version)
    stderr = base64.b64decode(value["execution"]["raw_stderr_base64"])
    value["execution"]["raw_stderr_base64"] = b64(stderr + b"Hash used: SHA1\nSignature type: ecdsa_sha1\nSupported Elliptic Curve Point Formats: uncompressed\n")
    assert trace.analyze_trial(value)["outcome"] == expected


@pytest.mark.parametrize("exit_code", [-9, -15, 0, 2, 127])
def test_received_alert_does_not_turn_abnormal_process_termination_into_complete_rejection(exit_code):
    value = trial(rejection=True)
    value["execution"]["exit_code"] = exit_code
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert result["execution"]["exit_code"] == exit_code
    assert "rejection_execution_not_complete" in result["issues"]


def test_unexpected_peer_handshake_before_alert_is_not_supported_rejection():
    value = trial(rejection=True)
    certificate = handshake(11, b"unexpected_certificate")
    wire = record(certificate)
    old = message("read", "RecordHeader", bytes.fromhex(record(b"\2\x46", 21)["raw_hex"])[:5])
    extra = message("read", "RecordHeader", bytes.fromhex(wire["raw_hex"])[:5]) + message("read", "Handshake", certificate, "Certificate")
    replace_stdout(value, old, extra + old)
    diagnostic = value["owner"]["diagnostic"]
    diagnostic["sent_records"].insert(0, wire)
    diagnostic["sent_bytes"] += len(bytes.fromhex(wire["raw_hex"]))
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "unexpected_rejection_sequence" in result["issues"]


@pytest.mark.parametrize("rejection", [False, True])
def test_owner_case_must_match_this_trial(rejection):
    value = trial(rejection=rejection)
    value["owner"]["diagnostic"]["case"] = "modern"
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "mismatched_owner_case" in result["issues"]


def test_conflicting_success_summary_cannot_coexist_with_rejection():
    value = trial(rejection=True)
    stderr = base64.b64decode(value["execution"]["raw_stderr_base64"])
    value["execution"]["raw_stderr_base64"] = b64(stderr + b"Verification: OK\n")
    result = trace.analyze_trial(value)
    assert result["outcome"] == "inconclusive"
    assert "conflicting_rejection_summary" in result["issues"]
