"""Corroborate an owned mediator trial, never issue production authority.

Useful TLS observations retain the original strict client/peer parser. Retry
prevention additionally needs actual attempted client bytes, the relay ledger,
and independent peer records proving those bytes were not forwarded.
"""
import hashlib

from . import tls_posture_diagnostic_trace as trace
from . import tls_posture_diagnostic_fixture as fixture
from .tls_posture_mediator import ClientGate, MediatorViolation


def _raw_rows(rows, total, *, maximum=8192, records=8):
    if type(rows) is not list or len(rows) > records or type(total) is not int:
        raise ValueError("invalid_mediator_records")
    result = []
    for row in rows:
        if type(row) is not dict or type(row.get("raw_hex")) is not str or len(row["raw_hex"]) > maximum * 2:
            raise ValueError("invalid_mediator_record")
        raw = bytes.fromhex(row["raw_hex"])
        if (len(raw) < 6 or len(raw) - 5 != int.from_bytes(raw[3:5], "big")
                or row.get("type") != raw[0] or row.get("version") != raw[1:3].hex()
                or row.get("payload_length") != len(raw) - 5):
            raise ValueError("inconsistent_mediator_record")
        result.append(raw)
    if sum(map(len, result)) != total or not 0 <= total <= maximum:
        raise ValueError("inconsistent_mediator_byte_count")
    return result


def _description(raw):
    return {"type": raw[0], "version": raw[1:3].hex(), "payload_length": len(raw) - 5,
            "raw_sha256": hashlib.sha256(raw).hexdigest()}


def _check_server(mediation, peer, ordinary):
    rows = trace._owner_records(peer, "sent_records")
    expected = [_description(raw) for raw in rows]
    if (mediation.get("server_ingress_records") != expected
            or mediation.get("server_ingress_record_count") != len(rows)
            or mediation.get("server_ingress_bytes") != sum(map(len, rows))):
        raise ValueError("mediator_peer_server_mismatch")
    forwarded = mediation.get("server_forwarded_records")
    pending = mediation.get("server_pending_record")
    if forwarded == expected and pending is None:
        if mediation.get("error") is not None:
            raise ValueError("mediator_error")
        transmitted = sum(map(len, rows))
        if mediation.get("server_transmitted_bytes") != transmitted:
            raise ValueError("mediator_server_send_mismatch")
    elif (ordinary.get("outcome") == "handshake_completed"
          and ordinary.get("evidence", {}).get("owner_final_close_notify_unread") is True
          and rows and forwarded == expected[:-1] and pending == expected[-1]
          and mediation.get("error") in {"BrokenPipeError", "ConnectionResetError"}):
        # Only a final, independently associated close_notify may be undelivered.
        # Client handshake/Finished/verification remains mandatory through trace.
        association = peer.get("server_close_notify_record", {})
        if (association.get("sent_record_index") != len(rows) - 1
                or association.get("raw_sha256") != expected[-1]["raw_sha256"]):
            raise ValueError("unassociated_unread_server_close")
        transmitted = sum(map(len, rows[:-1]))
        value = mediation.get("server_transmitted_bytes")
        if type(value) is not int or not transmitted <= value <= transmitted + len(rows[-1]):
            raise ValueError("mediator_server_send_mismatch")
    else:
        raise ValueError("mediator_server_forward_mismatch")
    if mediation.get("server_forwarded_bytes") != sum(row["payload_length"] + 5 for row in forwarded):
        raise ValueError("mediator_server_forward_count")


def analyze_trial(trial):
    result = {"diagnostic_only": True, "mediated": True, "outcome": "inconclusive",
              "issues": [], "evidence": {}, "useful_task_completed": False,
              "extra_client_hello_prevented": False}
    try:
        if type(trial) is not dict or trial.get("diagnostic_only") is not True or trial.get("mediated") is not True:
            raise ValueError("not_a_mediated_diagnostic")
        ordinary = trace.analyze_trial(trial)
        result["execution"] = ordinary.get("execution", {})
        result["tls_observation"] = "inconclusive"
        result["evidence"] = dict(ordinary.get("evidence", {}))
        owner = trial["owner"]
        peer, mediation = owner["diagnostic"], owner["mediation"]
        if (type(peer) is not dict or type(mediation) is not dict or mediation.get("version") != "1"
                or trial.get("version") not in trace.VERSIONS
                or peer.get("expected_version") != trial["version"] or peer.get("case") != trial.get("case")):
            raise ValueError("invalid_mediated_owner")
        if (trial["confinement"].get("unix_socket_and_socketpair_denied") is not True
                or any(trial["confinement"].get(name) is not True for name in trace.CONFINEMENT_WITNESSES)
                or trial.get("cleanup", {}).get("closed") is not True
                or mediation.get("completed") is not True or mediation.get("threads_joined") is not True
                or mediation.get("connection_deadline_expired") is not False):
            raise ValueError("mediation_or_confinement_incomplete")
        if (owner.get("connection_count") != 1 or owner.get("request_count") != 1
                or mediation.get("frontend_connections_admitted") != 1
                or mediation.get("peer_streams_admitted") != 1
                or mediation.get("extra_frontend_connections_refused") != 0):
            raise ValueError("unexpected_mediated_connection_progress")
        ingress = _raw_rows(mediation.get("client_ingress_records"), mediation.get("client_ingress_bytes"))
        forwarded = _raw_rows(mediation.get("client_forwarded_records"), mediation.get("client_forwarded_bytes"))
        received = trace._owner_records(peer, "received_records")
        if forwarded != received or mediation.get("client_transmitted_bytes") != sum(map(len, forwarded)):
            raise ValueError("mediator_peer_client_mismatch")
        gate = ClientGate(trial["version"], fixture.validate_client_hello)
        for raw in forwarded:
            gate.check(raw)
            gate.forwarded(raw)
        if mediation.get("forwarded_client_hellos") != gate.forwarded_client_hellos or gate.forwarded_client_hellos != 1:
            raise ValueError("mediator_forwarded_hello_mismatch")
        result["evidence"].update(peer_client_hellos=peer.get("client_hellos"),
            client_ingress_records=len(ingress), client_forwarded_records=len(forwarded),
            client_forwarded_bytes=sum(map(len, forwarded)), private_backend_confirmed=True)
        _check_server(mediation, peer, ordinary)
        if ordinary["outcome"] in {"handshake_completed", "explicit_protocol_rejection"}:
            if (ordinary["issues"] or mediation.get("blocked") is not False
                    or mediation.get("block_reason") is not None or mediation.get("blocked_record_index") is not None
                    or ingress != forwarded or mediation.get("gate_state") != gate.state):
                raise ValueError("useful_observation_mediation_mismatch")
            result["outcome"] = ordinary["outcome"]
            result["useful_task_completed"] = True
            result["tls_observation"] = ordinary["outcome"]
            return result
        # Only this declared native challenge can establish retry prevention.
        if trial.get("case") != "hrr" or trial["version"] != "tls1_3":
            raise ValueError("tls_observation_inconclusive")
        if (mediation.get("blocked") is not True or mediation.get("block_reason") != "extra_client_hello"
                or mediation.get("blocked_record_index") != len(forwarded)
                or len(ingress) != len(forwarded) + 1 or ingress[:-1] != forwarded
                or mediation.get("gate_state") != "blocked"):
            raise ValueError("retry_block_not_corroborated")
        try:
            gate.check(ingress[-1])
        except MediatorViolation as error:
            if error.code != "extra_client_hello":
                raise ValueError("retry_block_reason_mismatch") from None
        else:
            raise ValueError("retry_record_was_permitted")
        if (peer.get("client_hellos") != 1 or peer.get("hrr_sent") is not True
                or peer.get("handshake_completed") is not False or peer.get("completed") is not True
                or peer.get("application_bytes") != 0 or peer.get("error") != "tls_posture_owner_eof"
                or peer.get("clean_close") is not False):
            raise ValueError("peer_did_not_confirm_prevented_retry")
        execution = trial["execution"]
        if (type(execution.get("exit_code")) is not int or execution["exit_code"] != 1
                or execution.get("stop_reason") is not None or execution.get("truncated") is not False):
            raise ValueError("retry_client_execution_incomplete")
        stdout, stderr = trace._decode(execution["raw_stdout_base64"]), trace._decode(execution["raw_stderr_base64"])
        if len(stdout) + len(stderr) > trace.MAX_OUTPUT_BYTES:
            raise ValueError("combined_output_limit")
        messages, stdout_text = trace._messages(stdout)
        stderr_messages, stderr_text = trace._messages(stderr)
        if stderr_messages or any(line.startswith(("CONNECTION ESTABLISHED", "Protocol version:", "Ciphersuite:", "Verification: OK", "Verified peername:")) for line in stdout_text + stderr_text):
            raise ValueError("conflicting_retry_client_output")
        hellos = [m for m in messages if m["kind"] == "Handshake" and m["name"] == "ClientHello"]
        server = [m for m in messages if m["kind"] == "Handshake" and m["name"] == "ServerHello"]
        if (len(hellos) != 2 or any(m["direction"] != "write" for m in hellos)
                or hellos[0]["data"] != ingress[0][5:] or hellos[1]["data"] != ingress[-1][5:]
                or len(server) != 1 or server[0]["direction"] != "read"
                or trace._server_hello(server[0]["data"]) != (b"\x03\x04", b"\x13\x02", True)):
            raise ValueError("retry_client_attempt_not_proven")
        sent = trace._owner_records(peer, "sent_records")
        if (len(sent) != 1 or sent[0][5:] != server[0]["data"]
                or [m["data"] for m in messages if m["kind"] == "RecordHeader" and m["direction"] == "read"] != [sent[0][:5]]):
            raise ValueError("retry_peer_response_mismatch")
        fixture.validate_client_hello(ingress[-1], "tls1_3", retry=True)
        if forwarded != [ingress[0], b"\x14\x03\x03\x00\x01\x01"]:
            raise ValueError("unexpected_retry_forward_sequence")
        expected = [("write", "ClientHello"), ("read", "ServerHello"), ("write", "ClientHello")]
        if [(m["direction"], m["name"]) for m in messages if m["kind"] == "Handshake"] != expected:
            raise ValueError("unexpected_retry_handshake_sequence")
        headers = [m["data"] for m in messages if m["kind"] == "RecordHeader" and m["direction"] == "write"]
        alerts = [m for m in messages if m["kind"] == "Alert"]
        tail = [b"\x15\x03\x03\x00\x02"] if alerts else []
        if (headers != [r[:5] for r in ingress] + tail
                or len(alerts) > 1 or any(m["direction"] != "write" or m["data"] != b"\x02\x32" for m in alerts)):
            raise ValueError("unexpected_retry_trace_tail")
        result["outcome"] = "extra_client_hello_prevented"
        result["extra_client_hello_prevented"] = True
        result["tls_observation"] = "interrupted_by_mediator"
        result["evidence"]["blocked_record_sha256"] = hashlib.sha256(ingress[-1]).hexdigest()
    except (ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        result["issues"].append(str(error) if isinstance(error, ValueError) else "invalid_mediated_trial")
    return result
