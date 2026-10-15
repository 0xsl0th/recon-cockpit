"""Owner-sampled aggregate reservations; protocol doubles are not native evidence."""

from copy import deepcopy
from itertools import permutations

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from test_routing_contract import identity


class Harness:
    def __init__(self, case="ordinary"):
        self.now = 100.0
        self.selected = contract.selection(case)
        self.owner = identity(case)
        self.ledger = ledger.Ledger(self.selected, self.owner, started_at=self.now, clock=lambda: self.now)
        self.sequences = dict.fromkeys(ledger.ROLES, 0)
        self.action_sequence = 0
        self.selector = None
        self.action_digest = contract.digest(self.selected)
        self.lease = None

    def request(self, operation, role=None, **extra):
        role = role or ("launcher" if operation in ("ARM", "FINISH_ACTION", "STOP")
                        else contract.selector_role(self.selector))
        self.sequences[role] += 1
        return role, {"operation": operation, "sequence": self.sequences[role],
                      "action_sequence": self.action_sequence, "action_digest": self.action_digest, **extra}

    def call(self, operation, role=None, **extra):
        role, message = self.request(operation, role, **extra)
        reply = self.ledger.apply(message, role=role)
        ledger.validate_reply(reply, message, role=role)
        return reply

    def arm(self, selector):
        self.selector = selector
        self.action_sequence += 1
        self.action_digest = contract.digest(contract.action(self.selected, selector))
        return self.call("ARM", selector=selector, runtime_digests=self.owner["runtimes"][selector])

    def connect(self, local_id=1):
        reply = self.call("RESERVE_CONNECTION", local_id=local_id)
        if reply["status"] == "ok": self.lease = reply["lease"]
        return reply

    def request_unit(self):
        return self.call("RESERVE_REQUEST", lease=self.lease, kind="http" if self.selector.startswith("http_") else "kex")

    def bytes(self, direction, count):
        return self.call("RESERVE_BYTES", lease=self.lease, direction=direction, bytes=count)

    def finish_connection(self):
        return self.call("FINISH_CONNECTION", lease=self.lease)

    def finish_action(self, output=0):
        return self.call("FINISH_ACTION", output_bytes=output)

    def verify(self):
        snapshot = self.ledger.snapshot()
        assert ledger.validate_snapshot(snapshot, selected=self.selected, identity=self.owner) == snapshot
        return snapshot


@pytest.mark.parametrize("order", tuple(permutations(contract.SELECTORS)))
def test_all_operator_orders_complete_with_one_owner_and_no_budget_reset(order):
    h = Harness()
    for selector in order:
        assert h.arm(selector)["status"] == "ok"
        cap = contract.action_bounds(selector)
        for number in range(1, cap["connections"] + 1):
            h.now += .25
            assert h.connect(number)["status"] == "ok"
            if number == cap["connections"]:
                if cap["http_requests"] or cap["kex_exchanges"]:
                    assert h.request_unit()["status"] == "ok"
                if cap["request_bytes"]:
                    assert h.bytes("request", cap["request_bytes"])["status"] == "ok"
                assert h.bytes("response", cap["response_bytes"])["status"] == "ok"
            assert h.finish_connection()["status"] == "ok"
        assert h.finish_action(cap["output_bytes"])["status"] == "ok"
        h.verify()
    snapshot = h.verify()
    assert snapshot["counters"] == {"actions": 4, "connections": 8, "http_requests": 2,
        "kex_exchanges": 1, "request_bytes": 8466, "response_bytes": 14591, "output_bytes": 26624}
    assert snapshot["active_connection"] is None and snapshot["active_action_sequence"] is None
    assert h.call("STOP", reason="completed")["status"] == "ok"
    assert h.verify()["terminal_reason"] == "completed"
    with pytest.raises(ValueError, match="terminal"): h.connect()


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_each_action_can_be_a_complete_independent_subset(selector):
    h = Harness(); h.arm(selector)
    assert h.connect()["status"] == "ok"
    if selector != "ssh_nmap": h.request_unit()
    h.finish_connection(); h.finish_action()
    h.call("STOP", reason="completed")
    result = h.verify()
    assert result["counters"]["actions"] == result["counters"]["connections"] == 1


def test_connection_one_exhausts_across_actions_and_hosts_without_refund():
    h = Harness("connection_one"); h.arm("http_headers"); h.connect()
    h.finish_connection(); h.finish_action()  # Failed/empty work still consumes its reservation.
    h.now += .25; h.arm("ssh_nmap")
    assert h.connect()["reason"] == "aggregate_connections_limit"
    result = h.verify()
    assert result["counters"]["connections"] == 1 and result["counters"]["actions"] == 2
    assert result["terminal"]


def test_http_one_exhausts_across_separate_http_actions():
    h = Harness("http_one"); h.arm("http_nmap"); h.connect(); h.request_unit()
    h.finish_connection(); h.finish_action()
    h.now += .25; h.arm("http_headers"); h.connect()
    assert h.request_unit()["reason"] == "aggregate_http_requests_limit"
    result = h.verify()
    assert result["counters"]["http_requests"] == 1 and result["counters"]["request_bytes"] == 0


def test_ssh_zero_refuses_before_any_client_payload_is_reserved():
    h = Harness("ssh_zero"); h.arm("ssh_keys"); h.connect()
    assert h.request_unit()["reason"] == "aggregate_kex_exchanges_limit"
    assert h.verify()["counters"]["request_bytes"] == 0


def test_global_rate_reservation_waits_without_consuming_connection_or_resetting_roles():
    h = Harness(); h.arm("http_headers"); h.connect(); h.finish_connection(); h.finish_action()
    h.arm("ssh_nmap")
    first = h.connect()
    assert first["status"] == "wait" and first["retry_after_ms"] == 250 and first["lease"] is None
    h.now += .125
    second = h.connect()
    assert second["status"] == "wait" and second["retry_after_ms"] == 125
    assert h.verify()["counters"]["connections"] == 1
    h.now += .125
    assert h.connect()["status"] == "ok"
    assert h.verify()["last_admission_us"] == 250000


def test_concurrency_cannot_be_acquired_twice_even_by_same_action():
    h = Harness(); h.arm("ssh_nmap"); h.connect(); h.now += .25
    assert h.connect(2)["reason"] == "concurrency_limit"
    assert h.verify()["counters"]["connections"] == 1


@pytest.mark.parametrize("operation", ("RESERVE_REQUEST", "RESERVE_BYTES", "FINISH_CONNECTION"))
def test_finished_connection_lease_cannot_be_replayed(operation):
    h = Harness(); h.arm("http_nmap"); h.connect(); old = h.lease; h.finish_connection(); h.now += .25; h.connect(2)
    extras = {"lease": old}
    if operation == "RESERVE_REQUEST": extras["kind"] = "http"
    elif operation == "RESERVE_BYTES": extras.update(direction="response", bytes=1)
    assert h.call(operation, **extras)["reason"] == "connection_lease_changed"
    h.verify()


def test_request_replay_and_byte_reservation_fail_before_forwarding():
    h = Harness(); h.arm("http_nmap"); h.connect(); h.request_unit()
    assert h.request_unit()["reason"] == "request_replayed"
    assert h.verify()["counters"]["http_requests"] == 1
    h = Harness(); h.arm("http_nmap"); h.connect(); h.request_unit(); h.bytes("request", 18)
    assert h.bytes("request", 1)["reason"] == "action_request_bytes_limit"
    assert h.verify()["counters"]["request_bytes"] == 18


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_response_credits_are_not_refunded_after_failed_write_or_new_connection(selector):
    h = Harness(); h.arm(selector); h.connect()
    if selector.startswith("http_"): h.request_unit()
    cap = contract.action_bounds(selector)["response_bytes"]
    assert h.bytes("response", cap)["status"] == "ok"
    assert h.bytes("response", 1)["reason"] == "action_response_bytes_limit"
    assert h.verify()["counters"]["response_bytes"] == cap


@pytest.mark.parametrize("selector", contract.SELECTORS)
def test_client_payload_cannot_precede_request_or_kex_reservation(selector):
    h = Harness(); h.arm(selector); h.connect()
    assert h.bytes("request", 1)["reason"] == "request_not_reserved"
    assert h.verify()["counters"]["request_bytes"] == 0


def test_arm_cannot_replace_unsettled_action_or_repeat_a_finished_selector():
    h = Harness(); h.arm("http_headers")
    assert h.arm("ssh_keys")["reason"] == "action_unsettled"
    h.verify()
    h = Harness(); h.arm("http_headers"); h.finish_action()
    assert h.arm("http_headers")["reason"] == "selector_replayed"
    assert h.verify()["counters"]["actions"] == 1


def test_action_cannot_finish_with_outstanding_daemon_connection():
    h = Harness(); h.arm("ssh_keys"); h.connect()
    assert h.finish_action()["reason"] == "connection_unsettled"
    assert h.verify()["active_connection"] is not None


@pytest.mark.parametrize("trigger", ("timeout", "request_budget", "stop"))
def test_terminal_cleanup_settles_exact_leases_without_refunding_or_reopening(trigger):
    h = Harness("ssh_zero" if trigger == "request_budget" else "ordinary")
    h.arm("ssh_keys"); h.connect()
    if trigger == "timeout":
        h.now += 5
        assert not h.ledger.check_deadline()
        expected = "action_deadline"
    elif trigger == "request_budget":
        assert h.request_unit()["status"] == "denied"
        expected = "aggregate_kex_exchanges_limit"
    else:
        h.call("STOP", reason="cancelled")
        expected = "cancelled"
    before = h.verify()["counters"]
    assert h.finish_connection()["status"] == "ok"
    assert h.finish_action()["status"] == "ok"
    assert h.call("STOP", reason="completed")["status"] == "ok"
    final = h.verify()
    assert final["terminal_reason"] == expected and final["counters"] == before
    assert final["active_connection"] is None and final["active_action_sequence"] is None
    with pytest.raises(ValueError, match="terminal"): h.arm("http_headers")


def test_cleanup_can_detect_expiry_and_settle_in_one_request():
    h = Harness(); h.arm("http_headers"); h.connect(); h.now += 1
    assert h.finish_connection()["status"] == "ok"
    assert h.verify()["terminal_reason"] == "action_deadline"
    assert h.finish_action()["status"] == "ok"
    h.verify()


@pytest.mark.parametrize("elapsed,reason", ((1, "action_deadline"), (60, "session_deadline")))
def test_reservation_that_detects_expiry_consumes_sequence_for_exact_cleanup(elapsed, reason):
    h = Harness(); h.arm("http_headers"); h.connect(); h.request_unit()
    before = h.verify()["counters"]
    h.now += elapsed
    refused = h.bytes("request", 1)
    assert refused["status"] == "denied" and refused["reason"] == reason
    assert h.verify()["sequences"]["http_frontend"] == refused["sequence"]
    assert h.verify()["counters"] == before
    assert h.finish_connection()["status"] == "ok"
    assert h.finish_action()["status"] == "ok"
    final = h.verify()
    assert final["terminal_reason"] == reason and final["counters"] == before
    assert final["active_connection"] is None and final["active_action_sequence"] is None
    replies = ledger.replay_responses(final)
    assert next(row["reply"] for row in replies if row["reply"]["status"] == "denied") == refused
    with pytest.raises(ValueError, match="terminal"):
        h.arm("ssh_keys")


@pytest.mark.parametrize("field,value", (("lease", "f" * 64), ("action_digest", "f" * 64),
    ("action_sequence", 2), ("sequence", 1)))
def test_terminal_cleanup_cannot_accept_stale_binding_or_clear_original_refusal(field, value):
    h = Harness(); h.arm("ssh_keys"); h.connect(); h.call("STOP", reason="cancelled")
    role, message = h.request("FINISH_CONNECTION", lease=h.lease); message[field] = value
    assert h.ledger.apply(message, role=role)["status"] == "denied"
    final = h.verify()
    assert final["terminal_reason"] == "cancelled" and final["active_connection"] is not None


@pytest.mark.parametrize("field,value", (("sequence", 0), ("sequence", True), ("action_sequence", 2),
    ("action_sequence", True), ("action_digest", "b" * 64), ("runtime_digests", {}),
    ("selector", "http-client"), ("extra", True)))
def test_arm_identity_sequence_and_shape_mutations_stop_before_any_reservation(field, value):
    h = Harness(); h.action_sequence = 1; h.action_digest = contract.digest(contract.action(h.selected, "http_headers"))
    role, message = h.request("ARM", selector="http_headers", runtime_digests=h.owner["runtimes"]["http_headers"])
    message[field] = value
    reply = h.ledger.apply(message, role=role)
    assert reply["status"] == "denied"
    assert h.verify()["counters"]["actions"] == 0


@pytest.mark.parametrize("wrong_role", ("launcher", "ssh_frontend"))
def test_private_channel_role_is_bound_to_selected_action(wrong_role):
    h = Harness(); h.arm("http_headers")
    assert h.call("RESERVE_CONNECTION", role=wrong_role, local_id=1)["reason"] == "action_role_changed"
    h.verify()


def test_role_sequence_must_continue_after_action_worker_replacement():
    h = Harness(); h.arm("http_nmap"); h.connect(); h.finish_connection(); h.finish_action(); h.now += .25; h.arm("http_headers")
    role, message = h.request("RESERVE_CONNECTION", local_id=1); message["sequence"] = 1
    assert h.ledger.apply(message, role=role)["reason"] == "message_sequence_changed"
    h.verify()


@pytest.mark.parametrize("timeout,reason", ((1, "action_deadline"), (60, "session_deadline")))
def test_expired_deadlines_do_not_issue_lease(timeout, reason):
    h = Harness(); h.arm("http_headers"); h.now += timeout
    assert h.connect()["reason"] == reason
    assert h.verify()["counters"]["connections"] == 0


@pytest.mark.parametrize("time_value,reason", ((99, "owner_clock_invalid"), (float("nan"), "owner_clock_invalid"),
                                             (float("inf"), "owner_clock_invalid"), (100.125, "owner_clock_reversed")))
def test_clock_faults_are_terminal_and_preserve_reservations(time_value, reason):
    h = Harness(); h.arm("ssh_nmap"); h.now += .25; h.connect(); h.finish_connection(); h.now = time_value
    assert h.connect(2)["reason"] == reason
    assert h.verify()["counters"]["connections"] == 1


def test_idle_polls_are_bounded_and_cannot_extend_lifetime():
    h = Harness(); h.now += 30
    for _ in range(1000): assert h.ledger.check_deadline()
    assert h.verify()["events"] == []
    h.now += 30
    assert not h.ledger.check_deadline()
    assert h.verify()["terminal_reason"] == "session_deadline"


@pytest.mark.parametrize("fault", ("counter", "action", "role", "runtime", "lease", "timestamp", "reply", "drop", "append", "extra"))
def test_saved_evidence_recomputes_state_instead_of_trusting_claimed_counters(fault):
    h = Harness(); h.arm("http_headers"); h.connect(); h.request_unit(); h.bytes("request", 20)
    h.finish_connection(); h.finish_action(10); h.call("STOP", reason="completed")
    value = h.verify()
    if fault == "counter": value["counters"]["connections"] = 0
    elif fault == "action": value["actions"][0]["selector"] = "ssh_keys"
    elif fault == "role": value["events"][1]["role"] = "ssh_frontend"
    elif fault == "runtime": value["identity"]["runtimes"]["http_headers"]["daemon_runtime_sha256"] = "b" * 64
    elif fault == "lease": value["events"][2]["message"]["lease"] = "b" * 64
    elif fault == "timestamp": value["events"][2]["elapsed_us"] = 60000000
    elif fault == "reply": value["events"][1]["reply"]["status"] = "wait"
    elif fault == "drop": del value["events"][2]
    elif fault == "append": value["events"].append(deepcopy(value["events"][0]))
    else: value["extra"] = True
    with pytest.raises(ValueError): ledger.validate_snapshot(value, selected=h.selected, identity=h.owner)


@pytest.mark.parametrize("field,value", (("role", "ssh_frontend"), ("sequence", True), ("action_sequence", 4),
    ("action_digest", "b" * 64), ("snapshot_sha256", "invalid"), ("lease", None),
    ("retry_after_ms", 1), ("reason", "wrong"), ("extra", True)))
def test_frontend_reply_validator_rejects_swaps_and_missing_connection_lease(field, value):
    h = Harness(); h.arm("http_headers")
    role, message = h.request("RESERVE_CONNECTION", local_id=1)
    reply = h.ledger.apply(message, role=role)
    reply[field] = value
    with pytest.raises(ValueError): ledger.validate_reply(reply, message, role=role)


def test_malformed_channel_input_and_continuity_loss_cannot_resume():
    h = Harness()
    with pytest.raises(ValueError): h.ledger.apply({"padding": "x" * (ledger.MAX_MESSAGE_BYTES + 1)}, role="launcher")
    assert h.verify()["terminal_reason"] == "owner_protocol_error"
    h = Harness(); h.arm("ssh_keys"); h.connect(); h.ledger.terminate("continuity_lost")
    assert h.verify()["terminal_reason"] == "continuity_lost"
    with pytest.raises(ValueError): h.bytes("response", 1)


def test_event_capacity_stops_rate_retry_flood_without_new_reservations(monkeypatch):
    monkeypatch.setattr(ledger, "MAX_EVENTS", 12)
    h = Harness(); h.arm("http_headers"); h.connect(); h.finish_connection(); h.finish_action(); h.arm("ssh_nmap")
    for _ in range(3): assert h.connect()["status"] == "wait"
    with pytest.raises(ValueError, match="capacity"): h.connect()
    result = h.verify()
    assert result["terminal_reason"] == "ledger_limit" and result["counters"]["connections"] == 1


def test_replayed_replies_include_exact_prefix_hash_for_frontend_evidence():
    h = Harness(); h.arm("ssh_keys")
    role, request = h.request("RESERVE_CONNECTION", local_id=1)
    response = h.ledger.apply(request, role=role)
    h.lease = response["lease"]
    h.now += .125; h.request_unit(); h.bytes("request", 80); h.finish_connection(); h.finish_action()
    replies = ledger.replay_responses(h.verify(), identity=h.owner)
    assert replies[1] == {"role": role, "message": request, "reply": response}
    assert replies[1]["reply"]["snapshot_sha256"] != replies[-1]["reply"]["snapshot_sha256"]
