"""One owner-lifetime routing budget, reserved before daemon or payload delivery.

Channel roles are supplied by the owner, never read from a client message.
This accounting gate cannot replace policy, audit, approval or admission.
"""

from copy import deepcopy
import math
import time

from . import routing_contract as contract
from .stock_http_spec import encode

ROLES = ("launcher", "http_frontend", "ssh_frontend")
MAX_EVENTS = 1024
MAX_MESSAGE_BYTES = 1024
MAX_SNAPSHOT_BYTES = contract.EVIDENCE_BOUNDS["max_json_bytes"]
CLEANUP_OPERATIONS = frozenset({"FINISH_CONNECTION", "FINISH_ACTION", "STOP"})
CLEANUP_EVENT_RESERVE = 4
REPLY_FIELDS = frozenset({"role", "sequence", "action_sequence", "action_digest", "status", "reason",
                          "lease", "retry_after_ms", "snapshot_sha256"})
EXTERNAL_STOP_REASONS = frozenset({"completed", "cancelled", "owner_channel_closed", "owner_protocol_error",
                                  "continuity_lost", "owner_cleanup", "execution_failed"})
_COMMON = {"operation", "sequence", "action_sequence", "action_digest"}
_EXTRA = {"ARM": {"selector", "runtime_digests"}, "RESERVE_CONNECTION": {"local_id"},
          "RESERVE_REQUEST": {"lease", "kind"}, "RESERVE_BYTES": {"lease", "direction", "bytes"},
          "FINISH_CONNECTION": {"lease"}, "FINISH_ACTION": {"output_bytes"}, "STOP": {"reason"}}
_COUNTERS = ("actions", "connections", "http_requests", "kex_exchanges", "request_bytes", "response_bytes", "output_bytes")


class Refused(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise Refused(reason)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate_reply(value, message, *, role):
    if (type(value) is not dict or set(value) != REPLY_FIELDS or role not in ROLES
            or value["role"] != role
            or any(type(value[key]) is not type(message.get(key)) or value[key] != message.get(key)
                   for key in ("sequence", "action_sequence", "action_digest"))
            or type(value["status"]) is not str or value["status"] not in ("ok", "wait", "denied")
            or value["reason"] is not None and (type(value["reason"]) is not str or not 1 <= len(value["reason"]) <= 80)
            or not _integer(value["retry_after_ms"], 0, 250)
            or type(value["snapshot_sha256"]) is not str or not contract._HASH.fullmatch(value["snapshot_sha256"])
            or value["lease"] is not None and (type(value["lease"]) is not str or not contract._HASH.fullmatch(value["lease"]))):
        raise ValueError("invalid_routing_ledger_reply")
    if value["status"] == "wait":
        if (message.get("operation") != "RESERVE_CONNECTION" or value["reason"] != "admission_rate"
                or value["lease"] is not None or value["retry_after_ms"] == 0):
            raise ValueError("invalid_routing_rate_reply")
    elif value["retry_after_ms"] != 0 or (value["reason"] is None) != (value["status"] == "ok"):
        raise ValueError("invalid_routing_ledger_reply")
    if value["status"] == "ok":
        operation = message.get("operation")
        if operation == "RESERVE_CONNECTION" and value["lease"] is None:
            raise ValueError("missing_routing_connection_lease")
        if operation in ("RESERVE_REQUEST", "RESERVE_BYTES", "FINISH_CONNECTION") and value["lease"] != message.get("lease"):
            raise ValueError("routing_connection_lease_changed")
        if operation in ("ARM", "FINISH_ACTION", "STOP") and value["lease"] is not None:
            raise ValueError("unexpected_routing_connection_lease")
    elif value["lease"] is not None:
        raise ValueError("invalid_routing_denial_lease")
    return deepcopy(value)


class Ledger:
    """Cannot be resumed, refunded or reconstructed from a saved snapshot."""

    def __init__(self, selected, identity, *, started_at=None, clock=time.monotonic):
        self.selection = contract.validate_selection(selected)
        self.identity = contract.validate_identity(identity, selection=self.selection)
        if not callable(clock):
            raise ValueError("invalid_routing_owner_clock")
        self._clock = clock
        self._started = clock() if started_at is None else started_at
        if type(self._started) not in (int, float) or not math.isfinite(self._started) or self._started < 0:
            raise ValueError("invalid_routing_owner_clock")
        self._caps = contract.budgets(self.selection)
        self._elapsed = 0
        self._sequences = dict.fromkeys(ROLES, 0)
        self._counters = dict.fromkeys(_COUNTERS, 0)
        self._actions = []
        self._active = None
        self._connection = None
        self._last_admission = None
        self._events = []
        self._terminal = False
        self._reason = None

    @property
    def terminal(self):
        return self._terminal

    def _now(self):
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self._started:
            raise Refused("owner_clock_invalid")
        elapsed = min(60000000, int((now - self._started) * 1000000))
        _require(elapsed >= self._elapsed, "owner_clock_reversed")
        self._elapsed = elapsed
        return elapsed

    def _stop(self, reason):
        if not self._terminal:
            self._terminal, self._reason = True, reason

    def _time_check(self, elapsed):
        _require(elapsed < 60000000, "session_deadline")
        if self._active is not None:
            _require(elapsed < self._active["deadline_us"], "action_deadline")

    def check_deadline(self):
        if not self.terminal:
            try:
                self._time_check(self._now())
            except Refused as error:
                self._stop(str(error))
                self._events.append({"kind": "clock_stop", "elapsed_us": self._elapsed, "reason": str(error)})
        return not self.terminal

    def terminate(self, reason):
        if type(reason) is not str or reason not in EXTERNAL_STOP_REASONS:
            raise ValueError("invalid_routing_stop_reason")
        if not self.terminal:
            self.check_deadline()
        if not self.terminal:
            _require(reason != "completed" or self._active is None and self._connection is None,
                     "routing_action_unsettled")
            self._stop(reason)
            self._events.append({"kind": "owner_stop", "elapsed_us": self._elapsed, "reason": reason})
        return self.snapshot()

    def _message(self, message, role):
        _require(type(role) is str and role in ROLES, "unknown_channel_role")
        _require(type(message) is dict, "invalid_message")
        operation = message.get("operation")
        _require(type(operation) is str and operation in _EXTRA, "invalid_operation")
        _require(set(message) == _COMMON | _EXTRA[operation], "invalid_message_fields")
        _require(_integer(message["sequence"], 1, MAX_EVENTS)
                 and message["sequence"] == self._sequences[role] + 1, "message_sequence_changed")
        _require(_integer(message["action_sequence"], 0 if operation == "STOP" else 1, 4), "invalid_action_sequence")
        _require(type(message["action_digest"]) is str and bool(contract._HASH.fullmatch(message["action_digest"])),
                 "invalid_action_digest")
        self._sequences[role] = message["sequence"]
        return operation

    def _bound_action(self, message, role, *, frontend=False):
        _require(self._active is not None, "no_active_action")
        active = self._active
        _require(message["action_sequence"] == active["sequence"]
                 and message["action_digest"] == active["action_digest"], "action_binding_changed")
        _require(role == (contract.selector_role(active["selector"]) if frontend else "launcher"),
                 "action_role_changed")
        return active

    def _bound_connection(self, message, role):
        active = self._bound_action(message, role, frontend=True)
        _require(self._connection is not None and type(message["lease"]) is str
                 and message["lease"] == self._connection["lease"], "connection_lease_changed")
        return active

    def _reserve(self, key, count, active):
        _require(self._counters[key] + count <= self._caps[key], "aggregate_" + key + "_limit")
        _require(active["counters"][key] + count <= contract.action_bounds(active["selector"])[key],
                 "action_" + key + "_limit")
        self._counters[key] += count
        active["counters"][key] += count

    def _execute(self, operation, message, role, elapsed):
        if operation == "STOP":
            _require(role == "launcher", "stop_role_changed")
            _require(message["action_sequence"] == self._counters["actions"], "action_binding_changed")
            expected = self._actions[-1]["action_digest"] if self._actions else contract.digest(self.selection)
            _require(message["action_digest"] == expected, "action_binding_changed")
            _require(type(message["reason"]) is str and message["reason"] in EXTERNAL_STOP_REASONS,
                     "invalid_stop_reason")
            _require(message["reason"] != "completed" or self._active is None and self._connection is None,
                     "action_unsettled")
            self._stop(message["reason"])
            return None, 0
        if operation == "ARM":
            _require(role == "launcher", "arm_role_changed")
            _require(self._active is None and self._connection is None, "action_unsettled")
            selector = message["selector"]
            _require(type(selector) is str and selector in contract.SELECTORS, "invalid_selector")
            _require(selector not in {row["selector"] for row in self._actions}, "selector_replayed")
            _require(message["action_sequence"] == self._counters["actions"] + 1, "action_sequence_changed")
            _require(message["action_digest"] == contract.digest(contract.action(self.selection, selector)),
                     "action_digest_changed")
            _require(message["runtime_digests"] == self.identity["runtimes"][selector]
                     and encode(message["runtime_digests"]) == encode(self.identity["runtimes"][selector]),
                     "runtime_identity_changed")
            cap = contract.action_bounds(selector)
            _require(self._counters["actions"] < 4, "aggregate_actions_limit")
            _require(self._counters["output_bytes"] + cap["output_bytes"] <= self._caps["output_bytes"],
                     "aggregate_output_bytes_limit")
            self._counters["actions"] += 1
            self._counters["output_bytes"] += cap["output_bytes"]
            active = {"selector": selector, "sequence": message["action_sequence"],
                      "action_digest": message["action_digest"], "runtime_digests": deepcopy(message["runtime_digests"]),
                      "armed_us": elapsed, "deadline_us": min(60000000, elapsed + cap["timeout_seconds"] * 1000000),
                      "status": "active", "output_bytes_retained": 0, "connections_finished": 0,
                      "counters": {key: cap["output_bytes"] if key == "output_bytes" else 0
                                   for key in _COUNTERS if key != "actions"}}
            self._actions.append(active)
            self._active = active
            return None, 0
        if operation == "FINISH_ACTION":
            active = self._bound_action(message, role)
            _require(self._connection is None and active["connections_finished"] == active["counters"]["connections"],
                     "connection_unsettled")
            _require(_integer(message["output_bytes"], 0, active["counters"]["output_bytes"]), "output_bytes_limit")
            active.update(status="finished", output_bytes_retained=message["output_bytes"], finished_us=elapsed)
            self._active = None
            # The committed negative ends this owner's sequence even when its
            # native client exits successfully. Derive the stop here instead
            # of relying on a caller's runner or saved-evidence classification.
            # _stop preserves an earlier budget/deadline refusal during cleanup.
            if (self.selection.get("selection_version") == "3"
                    and contract.case_is_negative(active["selector"], self.selection)):
                self._stop("declared_negative_completed")
            return None, 0
        if operation == "RESERVE_CONNECTION":
            active = self._bound_action(message, role, frontend=True)
            _require(self._connection is None, "concurrency_limit")
            _require(_integer(message["local_id"], 1, 3)
                     and message["local_id"] == active["counters"]["connections"] + 1, "connection_id_changed")
            if self._last_admission is not None and elapsed - self._last_admission < 250000:
                return None, (250000 - (elapsed - self._last_admission) + 999) // 1000
            self._reserve("connections", 1, active)
            lease = contract.digest({"identity": self.identity, "selector": active["selector"],
                "action_sequence": active["sequence"], "action_digest": active["action_digest"],
                "local_id": message["local_id"]})
            self._connection = {"lease": lease, "local_id": message["local_id"],
                                "admitted_us": elapsed, "request_reserved": False}
            self._last_admission = elapsed
            return lease, 0
        active = self._bound_connection(message, role)
        lease = self._connection["lease"]
        if operation == "RESERVE_REQUEST":
            kind = "http" if role == "http_frontend" else "kex"
            _require(message["kind"] == kind and type(message["kind"]) is str, "request_kind_changed")
            _require(not self._connection["request_reserved"], "request_replayed")
            self._reserve("http_requests" if kind == "http" else "kex_exchanges", 1, active)
            self._connection["request_reserved"] = True
        elif operation == "RESERVE_BYTES":
            _require(type(message["direction"]) is str and message["direction"] in ("request", "response"),
                     "invalid_byte_direction")
            _require(_integer(message["bytes"], 1, 8192), "invalid_byte_count")
            if message["direction"] == "request" or role == "http_frontend":
                _require(self._connection["request_reserved"], "request_not_reserved")
            self._reserve(message["direction"] + "_bytes", message["bytes"], active)
        elif operation == "FINISH_CONNECTION":
            active["connections_finished"] += 1
            self._connection = None
        else:
            raise Refused("invalid_operation")
        return lease, 0

    def apply(self, message, *, role):
        """The owner must bind role to an inherited private channel, not a field."""
        # Reject unbounded or non-JSON objects without keeping attacker data.
        try:
            raw = encode(message)
            valid_packet = len(raw) <= MAX_MESSAGE_BYTES and type(message) is dict
        except (TypeError, ValueError, RecursionError):
            valid_packet = False
        if not valid_packet or type(role) is not str or role not in ROLES:
            self.terminate("owner_protocol_error")
            raise ValueError("invalid_routing_ledger_packet")
        cleanup = type(message.get("operation")) is str and message["operation"] in CLEANUP_OPERATIONS
        if self.terminal and not cleanup:
            raise ValueError("routing_ledger_terminal")
        if self.terminal and len(self._events) >= MAX_EVENTS:
            raise ValueError("routing_ledger_cleanup_capacity")
        if not self.terminal and (len(self._events) >= MAX_EVENTS - CLEANUP_EVENT_RESERVE
                or len(encode(self.snapshot())) > MAX_SNAPSHOT_BYTES - 8192):
            self._stop("ledger_limit")
            self._events.append({"kind": "capacity_stop", "elapsed_us": self._elapsed, "reason": "ledger_limit"})
            raise ValueError("routing_ledger_capacity")
        lease, retry, status, reason = None, 0, "ok", None
        try:
            elapsed = self._now()
            # Consume a valid channel sequence even when its reservation first
            # observes expiry. Cleanup must use the next sequence; this grants
            # no lease, bytes, request or action before the deadline check.
            operation = self._message(message, role)
            if not self.terminal:
                try:
                    self._time_check(elapsed)
                except Refused as error:
                    if not cleanup:
                        raise
                    self._stop(str(error))
                    self._events.append({"kind": "clock_stop", "elapsed_us": self._elapsed, "reason": str(error)})
            lease, retry = self._execute(operation, message, role, elapsed)
            if retry:
                status, reason = "wait", "admission_rate"
        except Refused as error:
            status, reason = "denied", str(error)
            self._stop(reason)
        reply = {"role": role, "sequence": message.get("sequence"),
                 "action_sequence": message.get("action_sequence"), "action_digest": message.get("action_digest"),
                 "status": status, "reason": reason, "lease": lease, "retry_after_ms": retry}
        if reason in ("owner_clock_invalid", "owner_clock_reversed"):
            self._events.append({"kind": "clock_stop", "elapsed_us": self._elapsed, "reason": reason})
        else:
            self._events.append({"kind": "message", "elapsed_us": self._elapsed,
                                 "role": role, "message": deepcopy(message), "reply": deepcopy(reply)})
        return {**reply, "snapshot_sha256": contract.digest(self.snapshot())}

    def snapshot(self):
        return deepcopy({"schema_version": "1", "profile": contract.PROFILE, "identity": self.identity,
            "selection": self.selection, "budgets": self._caps, "elapsed_us": self._elapsed,
            "terminal": self._terminal, "terminal_reason": self._reason, "sequences": self._sequences,
            "counters": self._counters, "actions": self._actions,
            "active_action_sequence": None if self._active is None else self._active["sequence"],
            "active_connection": self._connection, "last_admission_us": self._last_admission,
            "events": self._events})


def _replay_snapshot(value, *, selected=None, identity=None):
    """Read-only replay recomputes reservations; never constructs live authority."""
    if type(value) is not dict:
        raise ValueError("invalid_routing_ledger_snapshot")
    try:
        if len(encode(value)) > MAX_SNAPSHOT_BYTES:
            raise ValueError("routing_ledger_artifact_limit")
        chosen = contract.validate_selection(value["selection"])
        owner = contract.validate_identity(value["identity"], selection=chosen)
        if ((selected is not None and chosen != contract.validate_selection(selected))
                or (identity is not None and owner != contract.validate_identity(identity, selection=chosen))):
            raise ValueError("routing_ledger_identity_changed")
        events = value["events"]
        if type(events) is not list or len(events) > MAX_EVENTS:
            raise ValueError("routing_ledger_event_limit")
        instant = [0.0]
        rebuilt = Ledger(chosen, owner, started_at=0, clock=lambda: instant[0])
        previous = 0
        responses = []
        for event in events:
            if (type(event) is not dict or not _integer(event.get("elapsed_us"), previous, 60000000)
                    or rebuilt.terminal and not (event.get("kind") == "message"
                        and type(event.get("message")) is dict
                        and event["message"].get("operation") in CLEANUP_OPERATIONS)
                    and event.get("kind") != "clock_stop"):
                raise ValueError("invalid_routing_ledger_event")
            elapsed = event["elapsed_us"]
            previous = elapsed
            instant[0] = elapsed / 1000000
            # Replay exact owner integer times, avoiding float round-trip drift.
            rebuilt._now = lambda elapsed=elapsed: elapsed
            rebuilt._elapsed = elapsed
            if event.get("kind") == "message":
                if set(event) != {"kind", "elapsed_us", "role", "message", "reply"}:
                    raise ValueError("invalid_routing_ledger_event")
                reply = rebuilt.apply(event["message"], role=event["role"])
                if {key: item for key, item in reply.items() if key != "snapshot_sha256"} != event["reply"]:
                    raise ValueError("routing_ledger_reply_changed")
                responses.append({"role": event["role"], "message": deepcopy(event["message"]), "reply": reply})
            elif event.get("kind") == "owner_stop":
                if set(event) != {"kind", "elapsed_us", "reason"}:
                    raise ValueError("invalid_routing_ledger_event")
                rebuilt.terminate(event["reason"])
            elif event.get("kind") == "clock_stop":
                if set(event) != {"kind", "elapsed_us", "reason"} or event["reason"] not in (
                        "session_deadline", "action_deadline", "owner_clock_invalid", "owner_clock_reversed"):
                    raise ValueError("invalid_routing_ledger_event")
                if event["reason"].startswith("owner_clock_"):
                    rebuilt._stop(event["reason"])
                    rebuilt._events.append(deepcopy(event))
                else:
                    rebuilt.check_deadline()
            elif event.get("kind") == "capacity_stop":
                if (set(event) != {"kind", "elapsed_us", "reason"} or event["reason"] != "ledger_limit"
                        or len(rebuilt._events) < MAX_EVENTS - CLEANUP_EVENT_RESERVE
                        and len(encode(rebuilt.snapshot())) <= MAX_SNAPSHOT_BYTES - 8192):
                    raise ValueError("invalid_routing_ledger_capacity_stop")
                rebuilt._stop("ledger_limit")
                rebuilt._events.append(deepcopy(event))
            else:
                raise ValueError("invalid_routing_ledger_event")
        # Idle owner polling advances observed time without adding unbounded
        # heartbeat records. A live snapshot must still precede every deadline.
        observed = value["elapsed_us"]
        if not _integer(observed, previous, 60000000) or rebuilt.terminal and observed != previous:
            raise ValueError("invalid_routing_observed_time")
        if not rebuilt.terminal:
            rebuilt._time_check(observed)
        rebuilt._elapsed = observed
        if encode(rebuilt.snapshot()) != encode(value):
            raise ValueError("routing_ledger_replay_changed")
    except (KeyError, TypeError, RecursionError) as error:
        raise ValueError("invalid_routing_ledger_snapshot") from error
    return deepcopy(value), responses


def validate_snapshot(value, *, selected=None, identity=None):
    """Return only validated saved data, never a live owner or resumed budget."""
    return _replay_snapshot(value, selected=selected, identity=identity)[0]


def replay_responses(value, *, selected=None, identity=None):
    """Recompute every action-bound reply, including its intermediate state hash."""
    return _replay_snapshot(value, selected=selected, identity=identity)[1]
