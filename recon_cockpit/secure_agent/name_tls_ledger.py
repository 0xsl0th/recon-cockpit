"""Surviving owner accounting and DNS binding; messages confer no authority.

Only inherited private channel roles select the caller. Every reservation is
irreversible. Native output and recorder observations remain separate inputs.
"""

from copy import deepcopy
import hashlib
import math
import time

from . import name_tls_contract as contract
from . import name_tls_public as public

ROLES = ("launcher", "dns_frontend", "http_frontend", "tls_frontend")
MAX_EVENTS = 1024
MAX_EVENT_BYTES = 384
CLEANUP_EVENT_RESERVE = 8
MAX_MESSAGE_BYTES = 4096
MAX_REPLY_BYTES = 2048
MAX_SNAPSHOT_BYTES = 524288
CLEANUP_OPERATIONS = frozenset({"FINISH_CONNECTION", "FINISH_ACTION", "STOP"})
EXTERNAL_STOP_REASONS = frozenset({"completed", "cancelled", "owner_channel_closed", "owner_protocol_error",
    "continuity_lost", "owner_cleanup", "execution_failed", "declared_probe_refused"})
_COMMON = {"operation", "sequence", "action_sequence", "action_digest", "owner_identity_sha256"}
_EXTRA = {
    "ARM": {"slot", "action"}, "RESERVE_CONNECTION": {"local_id"},
    "RESERVE_OPERATION": {"lease", "kind"}, "RESERVE_BYTES": {"lease", "direction", "bytes"},
    "OBSERVE_DNS": {"lease", "semantic", "request_sha256", "original_answer_sha256",
                    "delivered_answer_sha256", "response_bytes"},
    "FINISH_CONNECTION": {"lease", "delivered_request_bytes", "delivered_response_bytes", "transcript_sha256"},
    "FINISH_ACTION": {"output_bytes", "native_success", "observation", "parsed_result_sha256", "native_result_sha256"},
    "STOP": {"reason"},
}
_COUNTERS = ("actions", "connections", "dns_queries", "http_requests", "tls_handshakes",
             "request_bytes", "response_bytes", "output_bytes")
REPLY_FIELDS = {"role", "sequence", "action_sequence", "action_digest", "owner_identity_sha256",
                "status", "reason", "lease", "retry_after_ms", "snapshot_sha256", "binding"}


class Refused(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise Refused(reason)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate_reply(value, message, *, role):
    if (type(value) is not dict or set(value) != REPLY_FIELDS or role not in ROLES
            or value["role"] != role or any(type(value[k]) is not type(message.get(k))
                or value[k] != message.get(k) for k in ("sequence", "action_sequence", "action_digest", "owner_identity_sha256"))
            or value["status"] not in ("ok", "wait", "denied")
            or value["reason"] is not None and (type(value["reason"]) is not str or not 1 <= len(value["reason"]) <= 64)
            or not _integer(value["retry_after_ms"], 0, 250)
            or not contract._hash(value["snapshot_sha256"])
            or value["lease"] is not None and not contract._hash(value["lease"])):
        raise ValueError("invalid_name_tls_ledger_reply")
    public.encode(value, max_bytes=MAX_REPLY_BYTES)
    if value["status"] == "wait":
        if (message["operation"] != "RESERVE_CONNECTION" or value["reason"] != "admission_rate"
                or value["retry_after_ms"] == 0 or value["lease"] is not None):
            raise ValueError("invalid_name_tls_rate_reply")
    elif value["retry_after_ms"] != 0 or (value["reason"] is None) != (value["status"] == "ok"):
        raise ValueError("invalid_name_tls_ledger_reply")
    if value["status"] == "ok":
        op = message["operation"]
        if op == "RESERVE_CONNECTION" and value["lease"] is None:
            raise ValueError("missing_name_tls_connection_lease")
        if op in ("RESERVE_OPERATION", "RESERVE_BYTES", "OBSERVE_DNS", "FINISH_CONNECTION") and value["lease"] != message["lease"]:
            raise ValueError("name_tls_connection_lease_changed")
        if op in ("ARM", "FINISH_ACTION", "STOP") and value["lease"] is not None:
            raise ValueError("unexpected_name_tls_connection_lease")
    elif value["lease"] is not None:
        raise ValueError("invalid_name_tls_denial_lease")
    if value["binding"] is not None:
        if value["status"] != "ok" or message["operation"] != "FINISH_ACTION":
            raise ValueError("unexpected_name_tls_reply_binding")
        contract.validate_binding(value["binding"])
    return deepcopy(value)


class Ledger:
    """Live state has no restoration or caller-supplied observation clock API."""

    def __init__(self, selected, identity, *, started_at=None, clock=time.monotonic):
        self.selection = contract.validate_selection(selected)
        self.identity = contract.validate_identity(identity, selection=selected)
        if not callable(clock):
            raise ValueError("invalid_name_tls_owner_clock")
        self._clock = clock
        self._started = clock() if started_at is None else started_at
        if type(self._started) not in (int, float) or not math.isfinite(self._started) or self._started < 0:
            raise ValueError("invalid_name_tls_owner_clock")
        self._elapsed = 0
        self._caps = contract.budgets(selected)
        self._sequences = dict.fromkeys(ROLES, 0)
        self._counters = dict.fromkeys(_COUNTERS, 0)
        self._actions = []
        self._active = None
        self._connection = None
        self._last_admission = None
        self._binding = None
        self._generation = 0
        self._events = []
        self._terminal = False
        self._reason = None

    @property
    def terminal(self):
        return self._terminal

    def _now(self):
        now = self._clock()
        _require(type(now) in (int, float) and math.isfinite(now) and now >= self._started,
                 "owner_clock_invalid")
        elapsed = min(60000000, int((now - self._started) * 1000000))
        _require(elapsed >= self._elapsed, "owner_clock_reversed")
        self._elapsed = elapsed
        return elapsed

    def _stop(self, reason):
        if not self._terminal:
            self._terminal, self._reason = True, reason

    def _event(self, value):
        public.encode(value, max_bytes=MAX_EVENT_BYTES)
        _require(len(self._events) < MAX_EVENTS, "ledger_event_limit")
        self._events.append(value)

    def _time_check(self, elapsed):
        _require(elapsed < 60000000, "session_deadline")
        if self._active is not None:
            _require(elapsed < self._active["deadline_us"], "action_deadline")

    def _binding_check(self, elapsed):
        _require(self._binding is not None, "binding_missing")
        _require(elapsed < self._binding["expires_at_us"], "binding_expired")
        _require(self._active is None or self._active["binding_sha256"] == self._binding["binding_sha256"],
                 "binding_generation_changed")

    def check_deadline(self):
        if not self.terminal:
            try:
                self._time_check(self._now())
            except Refused as error:
                self._stop(str(error))
                self._event({"kind": "clock_stop", "elapsed_us": self._elapsed, "reason": str(error)})
        return not self.terminal

    def terminate(self, reason):
        if type(reason) is not str or reason not in EXTERNAL_STOP_REASONS:
            raise ValueError("invalid_name_tls_stop_reason")
        if not self.terminal:
            self.check_deadline()
        if not self.terminal:
            _require(reason != "completed" or self._active is None and self._connection is None,
                     "action_unsettled")
            self._stop(reason)
            self._event({"kind": "owner_stop", "elapsed_us": self._elapsed, "reason": reason})
        return self.snapshot()

    def _message(self, message, role):
        op = message.get("operation")
        _require(type(op) is str and op in _EXTRA, "invalid_operation")
        _require(set(message) == _COMMON | _EXTRA[op], "invalid_message_fields")
        _require(_integer(message["sequence"], 1, MAX_EVENTS)
                 and message["sequence"] == self._sequences[role] + 1, "message_sequence_changed")
        _require(_integer(message["action_sequence"], 0 if op == "STOP" else 1, 3), "invalid_action_sequence")
        _require(contract._hash(message["action_digest"]), "invalid_action_digest")
        _require(message["owner_identity_sha256"] == self.identity["owner_identity_sha256"], "owner_identity_changed")
        self._sequences[role] = message["sequence"]
        return op

    def _bound_action(self, message, role, *, frontend=False):
        _require(self._active is not None, "no_active_action")
        active = self._active
        _require(message["action_sequence"] == active["sequence"]
                 and message["action_digest"] == active["action_digest"], "action_binding_changed")
        _require(role == (contract.selector_role(active["slot"]) if frontend else "launcher"), "action_role_changed")
        return active

    def _bound_connection(self, message, role):
        active = self._bound_action(message, role, frontend=True)
        _require(self._connection is not None and type(message["lease"]) is str
                 and message["lease"] == self._connection["lease"], "connection_lease_changed")
        return active

    def _reserve(self, key, count, active):
        _require(self._counters[key] + count <= self._caps[key], "aggregate_" + key + "_limit")
        _require(active["counters"][key] + count <= contract.action_bounds(active["slot"])[key], "action_" + key + "_limit")
        self._counters[key] += count
        active["counters"][key] += count

    def _arm(self, message, role, elapsed):
        _require(role == "launcher", "arm_role_changed")
        _require(self._active is None and self._connection is None, "action_unsettled")
        slot = message["slot"]
        _require(type(slot) is str and slot in contract.SLOTS, "invalid_slot")
        if contract.operation(slot) != "dns":
            self._binding_check(elapsed)
        try:
            action = contract.validate_action(message["action"], self.selection, self.identity, self._binding)
        except (ValueError, TypeError, KeyError) as error:
            raise Refused("action_commitment_changed") from error
        _require(action["parameters"]["operation_slot"] == slot, "slot_changed")
        _require(message["action_digest"] == contract.digest(action), "action_digest_changed")
        _require(slot not in {row["slot"] for row in self._actions}, "slot_replayed")
        plan = contract.operation_plan(self.selection)
        _require(len(self._actions) < len(plan) and slot == plan[len(self._actions)], "operation_plan_changed")
        _require(message["action_sequence"] == self._counters["actions"] + 1, "action_sequence_changed")
        cap = contract.action_bounds(slot)
        _require(self._counters["actions"] < 3, "aggregate_actions_limit")
        _require(self._counters["output_bytes"] + cap["output_bytes"] <= self._caps["output_bytes"], "aggregate_output_bytes_limit")
        if contract.operation(slot) == "dns":
            self._generation += 1
            self._binding = None
        self._counters["actions"] += 1
        self._counters["output_bytes"] += cap["output_bytes"]
        active = {"slot": slot, "sequence": message["action_sequence"], "action_digest": message["action_digest"],
                  "binding_sha256": None if self._binding is None else self._binding["binding_sha256"],
                  "armed_us": elapsed, "deadline_us": min(60000000, elapsed + cap["hard_action_seconds"] * 1000000),
                  "status": "active", "output_bytes_retained": 0, "connections_finished": 0,
                  "native_success": None, "native_result_sha256": None, "parsed_result_sha256": None,
                  "observation": None, "connection": None,
                  "counters": {key: cap["output_bytes"] if key == "output_bytes" else 0 for key in _COUNTERS if key != "actions"}}
        self._actions.append(active)
        self._active = active

    def _observe(self, message, active, elapsed):
        _require(active["slot"].startswith("dns_") and active["observation"] is None, "dns_observation_replayed")
        _require(self._connection["operation_reserved"], "operation_not_reserved")
        _require(_integer(message["response_bytes"], 1, active["counters"]["response_bytes"]), "dns_response_not_reserved")
        for key in ("request_sha256", "original_answer_sha256", "delivered_answer_sha256"):
            _require(contract._hash(message[key]), "invalid_dns_wire_digest")
        from .name_tls_wire import validate_dns_semantic
        try:
            semantic = validate_dns_semantic(message["semantic"])
        except (ValueError, TypeError, KeyError) as error:
            raise Refused("invalid_dns_observation") from error
        _require(bool(semantic["flags"] & 0x8000), "dns_observation_not_response")
        active["observation"] = {"semantic": semantic, "observation_sha256": contract.digest(semantic),
            "observed_at_us": elapsed, "response_bytes": message["response_bytes"],
            **{key: message[key] for key in ("request_sha256", "original_answer_sha256", "delivered_answer_sha256")}}

    def _finish_action(self, message, role, elapsed):
        active = self._bound_action(message, role)
        _require(self._connection is None and active["connections_finished"] == active["counters"]["connections"], "connection_unsettled")
        _require(_integer(message["output_bytes"], 0, active["counters"]["output_bytes"]), "output_bytes_limit")
        _require(type(message["native_success"]) is bool, "invalid_native_success")
        _require(contract._hash(message["parsed_result_sha256"]) and contract._hash(message["native_result_sha256"]), "invalid_native_result_digest")
        observation = active["observation"]
        binding = None
        if contract.operation(active["slot"]) == "dns":
            if message["observation"] is not None:
                _require(observation is not None and public.encode(message["observation"]) == public.encode(observation["semantic"]), "dns_native_wire_disagreement")
            if message["native_success"] and message["observation"] is not None and not self.terminal:
                _require(active["connection"] is not None
                         and active["connection"]["delivered_response_bytes"] == observation["response_bytes"]
                         and active["connection"]["delivered_request_bytes"] > 0, "dns_delivery_incomplete")
                from .name_tls_wire import binding_candidate
                if binding_candidate(observation["semantic"], self.selection["configuration"], self.selection["case"]):
                    observed = observation["observed_at_us"]
                    ttl = observation["semantic"]["records"][0]["ttl"]
                    _require(elapsed < min(60000000, observed + min(ttl, 60) * 1000000), "binding_expired")
                    binding = {"version": "1", **{key: self.identity[key] for key in (
                        "owner_id", "owner_identity_sha256", "session_id", "runtime_identity_sha256")},
                        **{key: self.selection[key] for key in ("configuration", "case", "selection_sha256")},
                        "observation_generation": self._generation, "observation_sha256": observation["observation_sha256"],
                        "canonical_question": public.DNS_NAME + " IN A",
                        "original_answer_sha256": observation["original_answer_sha256"],
                        "delivered_answer_sha256": observation["delivered_answer_sha256"],
                        "singleton_allowed_ipv4": public.endpoints(self.selection["configuration"])["http"]["target"],
                        "observed_ttl_seconds": ttl, "observed_at_us": observed,
                        "expires_at_us": min(60000000, observed + min(ttl, 60) * 1000000)}
                    binding["binding_sha256"] = contract.digest(binding)
                    self._binding = contract.validate_binding(binding, selected=self.selection, identity=self.identity)
        else:
            _require(message["observation"] is None, "unexpected_dns_observation")
        active.update(status="finished", output_bytes_retained=message["output_bytes"], finished_us=elapsed,
                      native_success=message["native_success"], parsed_result_sha256=message["parsed_result_sha256"],
                      native_result_sha256=message["native_result_sha256"])
        self._active = None
        case = self.selection["case"]
        is_dns = contract.operation(active["slot"]) == "dns"
        negative_terminal = (case in ("N2", "N3", "N5", "N6", "N7", "N8") and is_dns
                             or case == "N1" and active["slot"] == "dns_2"
                             or case in ("N11", "N12", "N13", "N16") and active["slot"] == "tls")
        if negative_terminal:
            self._stop("declared_negative_completed")
        elif not message["native_success"] or is_dns and binding is None:
            self._stop("native_execution_failed")
        elif len(self._actions) == len(contract.operation_plan(self.selection)) and case not in contract.PROBE_CASES:
            self._stop("completed")
        return binding

    def _execute(self, op, message, role, elapsed):
        if op == "ARM":
            self._arm(message, role, elapsed)
            return None, 0, None
        if op == "STOP":
            _require(role == "launcher", "stop_role_changed")
            expected = self._actions[-1]["action_digest"] if self._actions else contract.digest(self.selection)
            _require(message["action_sequence"] == self._counters["actions"] and message["action_digest"] == expected, "action_binding_changed")
            _require(type(message["reason"]) is str and message["reason"] in EXTERNAL_STOP_REASONS, "invalid_stop_reason")
            _require(message["reason"] != "completed" or self._active is None and self._connection is None, "action_unsettled")
            self._stop(message["reason"])
            return None, 0, None
        if op == "FINISH_ACTION":
            return None, 0, self._finish_action(message, role, elapsed)
        if op == "RESERVE_CONNECTION":
            active = self._bound_action(message, role, frontend=True)
            _require(self._connection is None, "concurrent_connection_limit")
            if contract.operation(active["slot"]) != "dns":
                self._binding_check(elapsed)
            _require(_integer(message["local_id"], 1, 3), "invalid_connection_id")
            if self._last_admission is not None and elapsed - self._last_admission < 250000:
                return None, math.ceil((250000 - elapsed + self._last_admission) / 1000), None
            self._reserve("connections", 1, active)
            lease = contract.digest({"owner_identity_sha256": self.identity["owner_identity_sha256"],
                                     "action_digest": active["action_digest"], "number": self._counters["connections"],
                                     "local_id": message["local_id"], "elapsed_us": elapsed})
            self._connection = {"lease": lease, "local_id": message["local_id"], "operation_reserved": False,
                                "delivered_request_bytes": None, "delivered_response_bytes": None, "transcript_sha256": None}
            self._last_admission = elapsed
            return lease, 0, None
        active = self._bound_connection(message, role)
        lease = self._connection["lease"]
        if op not in CLEANUP_OPERATIONS and contract.operation(active["slot"]) != "dns":
            self._binding_check(elapsed)
        if op == "RESERVE_OPERATION":
            kind = contract.operation(active["slot"])
            _require(type(message["kind"]) is str and message["kind"] == kind, "operation_kind_changed")
            _require(not self._connection["operation_reserved"], "operation_replayed")
            self._reserve({"dns": "dns_queries", "http": "http_requests", "tls": "tls_handshakes"}[kind], 1, active)
            self._connection["operation_reserved"] = True
        elif op == "RESERVE_BYTES":
            _require(type(message["direction"]) is str and message["direction"] in ("request", "response"), "invalid_byte_direction")
            _require(_integer(message["bytes"], 1, 16384), "invalid_byte_count")
            _require(self._connection["operation_reserved"], "operation_not_reserved")
            self._reserve(message["direction"] + "_bytes", message["bytes"], active)
        elif op == "OBSERVE_DNS":
            self._observe(message, active, elapsed)
        elif op == "FINISH_CONNECTION":
            for direction in ("request", "response"):
                _require(_integer(message["delivered_" + direction + "_bytes"], 0, active["counters"][direction + "_bytes"]), "delivery_exceeds_reservation")
            _require(contract._hash(message["transcript_sha256"]), "invalid_transcript_digest")
            self._connection.update({key: message[key] for key in ("delivered_request_bytes", "delivered_response_bytes", "transcript_sha256")})
            active["connection"] = deepcopy(self._connection)
            active["connections_finished"] += 1
            self._connection = None
        else:
            raise Refused("invalid_operation")
        return lease, 0, None

    def apply(self, message, *, role):
        try:
            raw = public.encode(message, max_bytes=MAX_MESSAGE_BYTES)
            valid = type(message) is dict and type(role) is str and role in ROLES
        except (ValueError, TypeError, RecursionError):
            valid = False
        if not valid:
            self.terminate("owner_protocol_error")
            raise ValueError("invalid_name_tls_ledger_packet")
        cleanup = type(message.get("operation")) is str and message["operation"] in CLEANUP_OPERATIONS
        if self.terminal and not cleanup:
            raise ValueError("name_tls_ledger_terminal")
        if self.terminal and len(self._events) >= MAX_EVENTS:
            raise ValueError("name_tls_ledger_cleanup_capacity")
        if not self.terminal and len(self._events) >= MAX_EVENTS - CLEANUP_EVENT_RESERVE:
            self._stop("ledger_limit")
            self._event({"kind": "capacity_stop", "elapsed_us": self._elapsed, "reason": "ledger_limit"})
            raise ValueError("name_tls_ledger_capacity")
        lease, retry, binding, status, reason = None, 0, None, "ok", None
        try:
            elapsed = self._now()
            op = self._message(message, role)
            if not self.terminal:
                try:
                    self._time_check(elapsed)
                except Refused as error:
                    if not cleanup:
                        raise
                    self._stop(str(error))
            lease, retry, binding = self._execute(op, message, role, elapsed)
            if retry:
                status, reason = "wait", "admission_rate"
        except Refused as error:
            status, reason = "denied", str(error)
            self._stop(reason)
        event = {"kind": "message", "elapsed_us": self._elapsed, "role": role,
                 "message_sha256": hashlib.sha256(raw).hexdigest(),
                 "status": status, "reason": reason, "retry_after_ms": retry}
        self._event(event)
        reply = {"role": role, **{key: message.get(key) for key in (
            "sequence", "action_sequence", "action_digest", "owner_identity_sha256")},
            "status": status, "reason": reason, "lease": lease, "retry_after_ms": retry,
            "snapshot_sha256": contract.digest(self.snapshot()), "binding": binding}
        public.encode(reply, max_bytes=MAX_REPLY_BYTES)
        return reply

    def snapshot(self):
        value = {"schema_version": "1", "profile": contract.PROFILE, "identity": self.identity,
            "selection": self.selection, "budgets": self._caps, "elapsed_us": self._elapsed,
            "terminal": self._terminal, "terminal_reason": self._reason, "sequences": self._sequences,
            "counters": self._counters, "actions": self._actions, "observation_generation": self._generation,
            "active_action_sequence": None if self._active is None else self._active["sequence"],
            "active_connection": self._connection, "last_admission_us": self._last_admission,
            "binding": self._binding, "events": self._events}
        public.encode(value, max_bytes=MAX_SNAPSHOT_BYTES)
        return deepcopy(value)


def _replay(value, *, selected=None, identity=None, messages):
    if type(value) is not dict or type(messages) is not list or len(messages) > MAX_EVENTS:
        raise ValueError("invalid_name_tls_saved_ledger")
    public.encode(value, max_bytes=MAX_SNAPSHOT_BYTES)
    chosen = contract.validate_selection(value["selection"])
    owner = contract.validate_identity(value["identity"], selection=chosen)
    if selected is not None and chosen != contract.validate_selection(selected) or identity is not None and owner != contract.validate_identity(identity):
        raise ValueError("name_tls_saved_identity_changed")
    events = value["events"]
    if type(events) is not list or len(events) > MAX_EVENTS:
        raise ValueError("invalid_name_tls_saved_events")
    clock = [0.0]
    ledger = Ledger(chosen, owner, started_at=0, clock=lambda: clock[0])
    previous, index, responses = 0, 0, []
    for event in events:
        if type(event) is not dict or not _integer(event.get("elapsed_us"), previous, 60000000):
            raise ValueError("invalid_name_tls_saved_event")
        public.encode(event, max_bytes=MAX_EVENT_BYTES)
        elapsed = event["elapsed_us"]
        previous = elapsed
        ledger._now = lambda elapsed=elapsed: elapsed
        ledger._elapsed = elapsed
        if event.get("kind") == "message":
            if index >= len(messages):
                raise ValueError("missing_name_tls_message_transcript")
            item = messages[index]
            index += 1
            if type(item) is not dict or set(item) != {"role", "message", "reply"} or item["role"] != event["role"] or contract.digest(item["message"]) != event["message_sha256"]:
                raise ValueError("name_tls_message_transcript_changed")
            reply = ledger.apply(item["message"], role=item["role"])
            if public.encode(reply) != public.encode(item["reply"]):
                raise ValueError("name_tls_saved_reply_changed")
            responses.append(deepcopy(item))
        elif event.get("kind") == "owner_stop":
            ledger.terminate(event["reason"])
        elif event.get("kind") == "clock_stop":
            if event.get("reason") in ("owner_clock_invalid", "owner_clock_reversed"):
                ledger._stop(event["reason"])
                ledger._event(deepcopy(event))
            else:
                ledger.check_deadline()
        elif event.get("kind") == "capacity_stop":
            if len(ledger._events) < MAX_EVENTS - CLEANUP_EVENT_RESERVE or event.get("reason") != "ledger_limit":
                raise ValueError("invalid_name_tls_capacity_stop")
            ledger._stop("ledger_limit")
            ledger._event(deepcopy(event))
        else:
            raise ValueError("invalid_name_tls_saved_event")
        if ledger._events[-1] != event:
            raise ValueError("name_tls_saved_event_changed")
    if (index != len(messages) or not _integer(value["elapsed_us"], previous, 60000000)
            or ledger.terminal and value["elapsed_us"] != previous):
        raise ValueError("name_tls_message_transcript_count")
    if not ledger.terminal:
        ledger._time_check(value["elapsed_us"])
    ledger._elapsed = value["elapsed_us"]
    if public.encode(ledger.snapshot(), max_bytes=MAX_SNAPSHOT_BYTES) != public.encode(value, max_bytes=MAX_SNAPSHOT_BYTES):
        raise ValueError("name_tls_saved_ledger_changed")
    return deepcopy(value), responses


def validate_snapshot(value, *, selected=None, identity=None, messages):
    """Replay saved data with its complete transcript; cannot restore an owner."""
    try:
        return _replay(value, selected=selected, identity=identity, messages=messages)[0]
    except (KeyError, TypeError, RecursionError) as error:
        raise ValueError("invalid_name_tls_saved_ledger") from error


def replay_responses(value, *, selected=None, identity=None, messages):
    return _replay(value, selected=selected, identity=identity, messages=messages)[1]
