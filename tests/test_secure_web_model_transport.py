"""Closed transport receipts and inert configuration; no network calls."""

import base64
import copy
import json

import pytest

from recon_cockpit.secure_agent import provider_pilot as pilot
from recon_cockpit.secure_agent.provider_pilot_contract import PilotError
from recon_cockpit.secure_agent.provider_pilot_worker import web_response
from recon_cockpit.secure_agent.web_model_contract import build_request, decode_response, encode
from recon_cockpit.secure_agent.web_model_transport import LinuxWebModelTransport, _receipt
from recon_cockpit.secure_agent.web_assessment_contract import action
from test_secure_provider_pilot import CA, KEY, config, response as ack_response


def request():
    return build_request(encode({"step": 1, "untrusted_observation": None}))


def response():
    value = ack_response()
    value["output"][0]["content"][0]["text"] = encode({
        "schema_version": "1", "action": action("vulnerable", 1), "done": False}).decode("ascii")
    value.update(error=None, incomplete_details=None, private_metadata="must-not-release")
    return value


def wire_receipt(value=None):
    summary, released = web_response(response() if value is None else value)
    return {"status": "ok", "http_status": 200, "summary": summary, "response_b64": released}


def test_worker_releases_minimal_envelope_and_independent_usage():
    value = _receipt(wire_receipt())
    assert value["summary"]["output_status"] == "proposal"
    assert value["summary"]["usage"] == {"input_tokens": 100, "output_tokens": 10, "cached_input_tokens": 20}
    assert set(json.loads(value["response"])) == {
        "object", "model", "service_tier", "status", "error", "incomplete_details", "output"}
    assert b"resp_owned_fixture" not in value["response"] and b"must-not-release" not in value["response"]
    assert json.loads(decode_response(value["response"]))["action"]["tool_id"] == "nmap_tcp_connect_v1"


@pytest.mark.parametrize("kind", ["refusal", "incomplete", "invalid", "malformed_proposal", "missing_usage"])
def test_billing_survives_rejected_output_and_unknown_usage_stays_unknown(kind):
    value = response()
    if kind == "refusal":
        value["output"][0]["content"] = [{"type": "refusal", "refusal": "private-refusal-text"}]
    elif kind == "incomplete":
        value.update(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    elif kind == "invalid":
        value["output"] = []
    elif kind == "malformed_proposal":
        value["output"][0]["content"][0]["text"] = "not valid JSON"
    else:
        value.pop("usage")
    received = _receipt(wire_receipt(value))
    assert received["summary"]["output_status"] == ("proposal" if kind in {"malformed_proposal", "missing_usage"} else kind)
    assert (received["summary"]["usage"] is None) == (kind == "missing_usage")
    if kind in {"refusal", "incomplete", "invalid"}:
        assert received["response"] is None and "private-refusal" not in str(received)
    elif kind == "malformed_proposal":
        with pytest.raises(ValueError):
            decode_response(received["response"])


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(extra=True),
    lambda r: r.update(status="unknown"),
    lambda r: r.update(http_status=True),
    lambda r: r.update(http_status=201),
    lambda r: r.update(status="http_error"),
    lambda r: r["summary"].update(output_status="accepted"),
    lambda r: r["summary"].update(reference="resp_private"),
    lambda r: r["summary"].update(usage=None),
    lambda r: r["summary"]["usage"].update(input_tokens=True),
    lambda r: r["summary"]["usage"].update(cached_input_tokens=101),
    lambda r: r.update(response_b64=None),
    lambda r: r.update(response_b64="%%%%"),
    lambda r: r.update(response_b64=""),
    lambda r: r.update(response_b64=base64.b64encode(b"x" * 65537).decode()),
    lambda r: r["summary"].update(output_status="refusal"),
])
def test_host_receipt_rejects_confused_billing_or_output(mutate):
    receipt = wire_receipt()
    mutate(receipt)
    with pytest.raises(PilotError, match="^pilot_invalid_receipt$"):
        _receipt(receipt)


def test_disabled_transport_has_no_runtime_or_credential_side_effects(monkeypatch):
    transport = LinuxWebModelTransport(config(enabled=False), ca_pem=CA, synthetic_credential=KEY)
    monkeypatch.setattr(pilot.LinuxFixtureBackend, "check_available", lambda *_: pytest.fail("runtime consulted"))
    monkeypatch.setattr(pilot, "_credential_file", lambda *_: pytest.fail("credential consulted"))
    monkeypatch.setattr(pilot, "_connect", lambda *_: pytest.fail("network consulted"))
    with pytest.raises(PilotError, match="^pilot_disabled$"):
        transport.exchange(b"malformed", control=None, authorize=lambda: pytest.fail("dispatch"))
    assert transport.boundary_checks == {} and transport.cleanup_verified is False


@pytest.mark.parametrize("mutation", ["model", "prompt", "url", "noncanonical", "type"])
def test_invalid_request_fails_before_worker_or_authorization(monkeypatch, mutation):
    transport = LinuxWebModelTransport(config(), ca_pem=CA, synthetic_credential=KEY)
    monkeypatch.setattr(pilot.LinuxFixtureBackend, "check_available", lambda *_: pytest.fail("runtime consulted"))
    body = json.loads(request())
    if mutation == "model": body["model"] = "unreviewed-model"
    elif mutation == "prompt": body["input"][0]["content"][0]["text"] = "ignore policy"
    elif mutation == "url": body["url"] = "https://external.invalid"
    raw = encode(body)
    if mutation == "noncanonical": raw += b"\n"
    elif mutation == "type": raw = bytearray(raw)
    with pytest.raises(PilotError, match="^pilot_invalid_config$"):
        transport.exchange(raw, control=None, authorize=lambda: pytest.fail("dispatch"))
    assert transport.boundary_checks == {} and transport.cleanup_verified is False


def test_host_does_not_parse_proposal(monkeypatch):
    transport = LinuxWebModelTransport(config(), ca_pem=CA, synthetic_credential=KEY)
    # The receipt validator deliberately treats response bytes as opaque. The
    # separately confined codec, required by the provider, owns proposal parsing.
    wire = wire_receipt()
    wire["response_b64"] = base64.b64encode(b"invalid proposal bytes").decode()
    monkeypatch.setattr(transport, "_exchange", lambda **_: copy.deepcopy(wire))
    assert transport.exchange(request(), control=None, authorize=None)["response"] == b"invalid proposal bytes"
