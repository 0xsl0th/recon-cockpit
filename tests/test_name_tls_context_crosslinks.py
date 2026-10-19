"""Portable replay consistency tests; synthetic streams are not native proof."""

from copy import deepcopy
import hashlib

import pytest

from recon_cockpit.secure_agent import name_tls_context as context, name_tls_ledger as ledger
from recon_cockpit.secure_agent import name_tls_parser as parser, name_tls_public as public, name_tls_wire as wire
from test_name_tls_authority import Harness
from test_name_tls_wire_parser import dns_exchange, dig_output, client_hello, server_hello, brief


def recording(case="O1", configuration="A", *, operation="dns", failure=None, accepted=1):
    if operation != "dns":
        case = "O2" if operation == "http" else "O3"
    harness = Harness(case, configuration)
    if operation != "dns":
        assert harness.dns()["status"] == "ok"
        harness.clock = .3
    slot = "dns_1" if operation == "dns" else operation
    assert harness.arm(slot)["status"] == "ok"
    if operation == "dns":
        request, original = dns_exchange(configuration)
        delivered = wire.transformed_dns_response(configuration, case, request, original)
        stdout, stderr = (b"" if case == "N8" else dig_output(delivered, configuration)), b""
    elif operation == "http":
        request = wire.http_request(configuration, case)
        original = delivered = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        stdout, stderr = original, b""
    else:
        request = client_hello()
        original = delivered = server_hello() + b"\x17\3\3\0\x11" + b"x" * 17
        stdout, stderr = b"", brief(configuration)
    streams = {"request": request, "delivered_request": request, "original_response": original,
               "proposed_response": delivered, "delivered_response": delivered, "stdout": stdout, "stderr": stderr}
    if failure == "parser":
        streams["stdout"] = b"invalid native output\n"
    elif failure == "partial_request":
        streams.update(delivered_request=request[:7], original_response=b"", proposed_response=b"",
                       delivered_response=b"", stdout=b"", stderr=b"")
    elif failure == "partial_response":
        streams.update(delivered_response=delivered[:7], stdout=b"", stderr=b"")
    elif failure == "zero_admission":
        streams = dict.fromkeys(streams, b"")
    raw = parser.encode_input(operation, configuration=configuration, case=case, **streams,
                              exit_code=9 if case == "N8" or failure not in (None, "parser") else 0, stop_reason=None)
    if failure:
        with pytest.raises(ValueError):
            parser.parse_input(raw)
        parsed = None
    else:
        parsed = parser.parse_input(raw)
    admitted = int(failure != "zero_admission")
    reason = "complete" if failure in (None, "parser") else "extra_connection" if accepted == 2 else "io_failure"
    recorder = {"admitted_connections": admitted, "accepted_connections": accepted,
                "request_bytes_delivered": len(streams["delivered_request"]),
                "response_bytes_delivered": len(streams["delivered_response"]), "reason": reason}
    recorder["transcript_sha256"] = public.digest(recorder)
    if admitted:
        assert harness.connection()["status"] == "ok"
        # Fresh reservations remain charged even when fewer bytes are delivered.
        harness.reserve(request=len(request) + 5, response=max(len(original), len(delivered)) + 5)
        if operation == "dns" and case != "N8" and failure in (None, "parser"):
            assert harness.send("OBSERVE_DNS", "dns_frontend", lease=harness.lease,
                semantic=wire.parse_dns_response(delivered, request), request_sha256=hashlib.sha256(request).hexdigest(),
                original_answer_sha256=hashlib.sha256(original).hexdigest(),
                delivered_answer_sha256=hashlib.sha256(delivered).hexdigest(), response_bytes=len(delivered))["status"] == "ok"
        assert harness.send("FINISH_CONNECTION", operation + "_frontend", lease=harness.lease,
            delivered_request_bytes=len(streams["delivered_request"]),
            delivered_response_bytes=len(streams["delivered_response"]),
            transcript_sha256=recorder["transcript_sha256"])["status"] == "ok"
    observation = parsed["observation"] if parsed is not None and operation == "dns" and case != "N8" else None
    assert harness.send("FINISH_ACTION", output_bytes=len(streams["stdout"]) + len(streams["stderr"]),
        native_success=parsed is not None, observation=observation,
        parsed_result_sha256=public.digest(parsed), native_result_sha256="e" * 64)["status"] == "ok"
    return {"state": harness.ledger.snapshot(), "messages": harness.messages, "recorder": recorder,
            "streams": streams, "parsed": parsed, "operation": operation, "case": case}


def validate(value):
    state = ledger.validate_snapshot(value["state"], messages=value["messages"])
    if value["parsed"] is not None:
        parser.validate_result(value["parsed"])
    context._validate_owner_recording(state["actions"][-1], value["recorder"], value["streams"],
        value["parsed"], value["messages"], operation=value["operation"], case=value["case"])


def rewrite(value, mutate):
    """Regenerate coherent owner replies/events, without changing recorded bytes."""
    changed = deepcopy(value)
    old = changed["state"]
    owner = ledger.Ledger(old["selection"], old["identity"], started_at=0, clock=lambda: 0)
    messages = []
    for event, row in zip(old["events"], changed["messages"], strict=True):
        assert event["kind"] == "message"
        elapsed = event["elapsed_us"]
        owner._now = lambda elapsed=elapsed: elapsed
        owner._elapsed = elapsed
        message = deepcopy(row["message"])
        if message["action_sequence"] == old["actions"][-1]["sequence"]:
            mutate(message)
        reply = owner.apply(message, role=row["role"])
        assert reply["status"] == "ok", reply
        messages.append({"role": row["role"], "message": message, "reply": reply})
    owner._elapsed = old["elapsed_us"]
    changed.update(state=owner.snapshot(), messages=messages)
    assert changed["streams"] == value["streams"] and changed["parsed"] == value["parsed"]
    ledger.validate_snapshot(changed["state"], messages=changed["messages"])
    return changed


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", ("O1", "N6", "N7", "N8"))
def test_valid_dns_positive_and_negative_owner_recordings(configuration, case):
    value = recording(case, configuration)
    validate(value)
    assert value["parsed"]["expected_negative"] is (case != "O1")
    if case == "N8":
        assert value["state"]["actions"][-1]["observation"] is None
        assert value["messages"][-1]["message"]["observation"] is None


@pytest.mark.parametrize("failure", ("parser", "partial_request", "partial_response", "zero_admission"))
def test_failed_parser_and_partial_delivery_remain_data(failure):
    value = recording(failure=failure)
    validate(value)
    current = value["state"]["actions"][-1]
    assert current["native_success"] is False and value["parsed"] is None
    assert (current["observation"] is not None) is (failure == "parser")
    assert (current["connection"] is None) is (failure == "zero_admission")


def test_rejected_extra_accept_does_not_invent_a_second_admitted_connection():
    value = recording(failure="partial_response", accepted=2)
    validate(value)
    assert value["recorder"]["accepted_connections"] == 2
    assert value["state"]["actions"][-1]["counters"]["connections"] == 1
    assert value["recorder"]["reason"] == "extra_connection"


@pytest.mark.parametrize("field", ("request_sha256", "original_answer_sha256", "delivered_answer_sha256"))
@pytest.mark.parametrize("failure", (None, "parser"))
def test_replayed_owner_wire_hash_rewrite_cannot_replace_raw_bytes(field, failure):
    value = recording(failure=failure)
    def change(message):
        if message["operation"] == "OBSERVE_DNS":
            message[field] = "f" * 64
    changed = rewrite(value, change)
    with pytest.raises(ValueError, match="owner_dns_wire_commitment"):
        validate(changed)


@pytest.mark.parametrize("failure", (None, "parser"))
def test_replayed_owner_semantic_rewrite_cannot_replace_wire_or_parsed_observation(failure):
    value = recording(failure=failure)
    def change(message):
        semantic = message.get("semantic") if message["operation"] == "OBSERVE_DNS" else message.get("observation")
        if semantic is not None:
            semantic["transaction_id"] += 1
    changed = rewrite(value, change)
    with pytest.raises(ValueError, match="owner_dns_wire_observation"):
        validate(changed)


@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
@pytest.mark.parametrize("field", ("transcript_sha256", "delivered_request_bytes", "delivered_response_bytes"))
def test_replayed_connection_rewrite_cannot_replace_recorded_delivery(operation, field):
    value = recording(operation=operation)
    validate(value)
    def change(message):
        if message["operation"] == "FINISH_CONNECTION":
            message[field] = "f" * 64 if field == "transcript_sha256" else message[field] - 1
        elif message["operation"] == "OBSERVE_DNS" and field == "delivered_response_bytes":
            message["response_bytes"] -= 1
    changed = rewrite(value, change)
    with pytest.raises(ValueError, match="owner_recorder_(transcript|delivery)"):
        validate(changed)


def test_replayed_dns_response_count_alone_must_match_actual_stream():
    value = recording(failure="parser")
    def change(message):
        if message["operation"] == "OBSERVE_DNS":
            message["response_bytes"] -= 1
    with pytest.raises(ValueError, match="owner_dns_wire_observation"):
        validate(rewrite(value, change))


@pytest.mark.parametrize("failure", (None, "parser"))
def test_finish_action_must_carry_exact_parser_observation_or_none(failure):
    value = recording(failure=failure)
    def change(message):
        if message["operation"] == "FINISH_ACTION":
            message["observation"] = (None if failure is None else
                value["state"]["actions"][-1]["observation"]["semantic"])
    changed = rewrite(value, change)
    with pytest.raises(ValueError, match="owner_parser_observation"):
        validate(changed)


@pytest.mark.parametrize("admitted", (0, 2, True, None))
def test_recorder_admission_count_cannot_replace_owner_connections(admitted):
    value = recording()
    value["recorder"]["admitted_connections"] = admitted
    with pytest.raises(ValueError, match="owner_recorder_connections"):
        validate(value)


def test_complete_dns_recorder_requires_observation_even_when_native_parser_failed():
    value = recording(failure="partial_response")
    value["recorder"]["reason"] = "complete"
    with pytest.raises(ValueError, match="owner_dns_observation_missing"):
        validate(value)


def test_n8_cannot_attach_a_complete_dns_observation_to_truncated_delivery():
    value = recording("N8")
    value["state"]["actions"][-1]["observation"] = recording()["state"]["actions"][-1]["observation"]
    # Isolate this boundary rule; normal ledger replay also rejects this change.
    with pytest.raises(ValueError, match="owner_dns_observation"):
        context._validate_owner_recording(value["state"]["actions"][-1], value["recorder"], value["streams"],
            value["parsed"], value["messages"], operation="dns", case="N8")
