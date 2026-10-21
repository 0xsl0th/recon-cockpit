"""Finite, nonsecret dispatch accounting. Every receipt is data, never authority."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from datetime import datetime
from functools import wraps

from . import engagement_contract as legacy
from . import configurable_contract
from .models import parse_action, parse_policy

MAX_ROE_BYTES = 4096
MAX_REQUEST_BYTES = 8192
MAX_RECEIPT_BYTES = 4096
MAX_SESSION_BYTES = 4096
MAX_RESERVATION_BYTES = 8192
MAX_COMPLETION_BYTES = 4096
MAX_EXPORT_BYTES = 2097152
MAX_REPORT_BYTES = 8192
MAX_DEPTH = 12
MAX_REVISIONS = MAX_SESSIONS = MAX_RESERVATIONS = MAX_COMPLETIONS = 64
MAX_EVENTS = 257
MAX_DATABASE = 8388608
MAX_JOURNAL = 16777216
MAX_PROGRESS_CALLBACKS = 4000
OPERATION_SECONDS = 2.0
INTEGER_MAX = 2**63 - 1
UTC_MIN = 946684800000000000
UTC_MAX = 4102444799999999999
CLOCK_TOLERANCE = 50000000
SESSION_NS = 60000000000
REQUEST_DOMAIN = b"recon-engagement-dispatch-request-v2\x00"
STATE_DOMAIN = b"recon-engagement-dispatch-state-v2\x00"
CONTRACT_SHA256 = "416f82759c29a8669208d6acea01d5b77998ae42cd956c75d6f1da57d939c68e"
INVENTORY_SHA256 = "ea0092a40cfd99ed299b3e51c43316708a58289fe07f9f7c067a1b86b9c6dac8"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_HASH = re.compile(r"[0-9a-f]{64}")
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_SLOTS = {"http_identify": (1, 3, 4096, 4096), "http_headers": (2, 1, 256, 2048)}
_CAPS = {"actions": "max_actions", "connections": "max_connections",
         "request_bytes": "max_request_bytes", "response_bytes": "max_response_bytes",
         "runtime_ms": "max_engagement_ms"}
_OPERATIONS = {"create", "revise", "revoke", "session", "reserve", "complete"}
_OUTCOMES = {"reported_success", "reported_failure", "cancelled", "unresolved"}


class DispatchLedgerError(ValueError):
    """Closed public error. Never include caller data or OS diagnostics."""

    def __init__(self, code):
        if type(code) is not str or code not in ERROR_CODES:
            raise ValueError("engagement_dispatch_invalid_error_code")
        self.code = code
        super().__init__(code)


def _fail(code="invalid_input"):
    raise DispatchLedgerError("engagement_dispatch_" + code)


def _map_v1(error, default="invalid_input"):
    suffix = error.code.removeprefix("engagement_")
    _fail(suffix if suffix in {"timeout", "limit_exceeded"} else default)


def _operation_deadline():
    return legacy._operation_deadline()


def _check_deadline(deadline):
    try:
        legacy._check_time(deadline)
    except legacy.EngagementError as error:
        _map_v1(error)


@contextmanager
def _deadline_context(deadline):
    try:
        with legacy._using_deadline(deadline) as effective:
            yield effective
    except legacy.EngagementError as error:
        _map_v1(error)


def _bounded(function):
    @wraps(function)
    def call(*args, **kwargs):
        with _deadline_context(_operation_deadline()):
            return function(*args, **kwargs)
    return call


def _validation(code):
    def decorate(function):
        @wraps(function)
        @_bounded
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except DispatchLedgerError as error:
                if error.code.endswith(("_timeout", "_limit_exceeded")):
                    raise
                _fail(code)
            except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
                _fail(code)
        return call
    return decorate


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()
    return value


def _integer(value, minimum=0, maximum=INTEGER_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _uuid(value):
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail()
    return value


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail()
    return value


def _member(value, choices):
    if type(value) is not str or value not in choices:
        _fail()
    return value


def _text(value):
    if _SURROGATE.search(value) is not None:
        _fail()


def _tree(value, deadline):
    units = calls = 0
    _check_deadline(deadline)

    def copy(current, depth):
        nonlocal units, calls
        calls += 1
        if calls % 128 == 0:
            _check_deadline(deadline)
        units += 1
        kind = type(current)
        if kind in (dict, list):
            depth += 1
            if depth > MAX_DEPTH or len(current) > MAX_EXPORT_BYTES:
                _fail("limit_exceeded")
            if kind is dict:
                result = {}
                for key, item in current.items():
                    if type(key) is not str:
                        _fail()
                    if len(key) > MAX_EXPORT_BYTES:
                        _fail("limit_exceeded")
                    _text(key)
                    units += len(key)
                    if units > MAX_EXPORT_BYTES:
                        _fail("limit_exceeded")
                    result[key] = copy(item, depth)
            else:
                result = [copy(item, depth) for item in current]
        elif kind is str:
            if len(current) > MAX_EXPORT_BYTES:
                _fail("limit_exceeded")
            _text(current)
            units += len(current)
            result = current
        elif kind is int:
            _integer(current)
            result = current
        elif current is None or kind is bool:
            result = current
        else:
            _fail()
        if units > MAX_EXPORT_BYTES:
            _fail("limit_exceeded")
        return result
    result = copy(value, 0)
    _check_deadline(deadline)
    return result


@_bounded
def canonical(value):
    """Bounded strict JSON bytes; no implicit engagement-clock observation."""
    deadline = _operation_deadline()
    try:
        value = _tree(value, deadline)
        # The checked tree bounds total nodes/characters and depth. Encode that
        # finite tree in the C encoder; millions of per-token clock syscalls
        # would consume the original work budget without adding a useful bound.
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
        _check_deadline(deadline)
        if len(encoded) > MAX_EXPORT_BYTES:
            _fail("limit_exceeded")
        result = encoded.encode("ascii")
    except DispatchLedgerError:
        raise
    except (TypeError, ValueError, OverflowError, RuntimeError, UnicodeError):
        _fail()
    _check_deadline(deadline)
    return result


def _detach(value, maximum):
    raw = canonical(value)
    if len(raw) > maximum:
        _fail("limit_exceeded")
    return json.loads(raw)


def _decode(raw, maximum):
    if type(raw) is not bytes:
        _fail()
    if len(raw) > maximum:
        _fail("limit_exceeded")
    deadline = _operation_deadline()
    depth, quoted, escaped = 0, False, False
    for index, byte in enumerate(raw):
        if index % 4096 == 0:
            _check_deadline(deadline)
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                _fail("limit_exceeded")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                _fail()
            result[key] = item
        return result

    def number(text):
        if len(text) > 19:
            _fail()
        return _integer(int(text))

    def refused(_):
        _fail()

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=number, parse_float=refused, parse_constant=refused)
    except DispatchLedgerError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail()
    _check_deadline(deadline)
    return value


def _roe(value):
    try:
        return legacy.validate_roe(value)
    except legacy.EngagementError as error:
        _map_v1(error, "invalid_roe")


def _roe_digest(value):
    try:
        return legacy.roe_digest(value)
    except legacy.EngagementError as error:
        _map_v1(error, "invalid_roe")


def _validated_roe_digest(value):
    # Only the transition engine uses this, after validate_request validated ROE.
    return hashlib.sha256(legacy.ROE_DOMAIN + canonical(value)).hexdigest()


@_validation("invalid_request")
def validate_clock(value):
    value = _detach(value, MAX_REQUEST_BYTES)
    _object(value, ("utc_ns", "mono_before_ns", "mono_after_ns"))
    _integer(value["utc_ns"], UTC_MIN, UTC_MAX)
    before = _integer(value["mono_before_ns"])
    after = _integer(value["mono_after_ns"])
    if not before <= after or after - before > CLOCK_TOLERANCE:
        _fail()
    return value


def _reference(value, kind):
    if kind == "approval":
        _object(value, ("broker_id", "consume_sequence", "witness_sha256"))
        _uuid(value["broker_id"])
        _integer(value["consume_sequence"], 1, 32)
        _hash(value["witness_sha256"])
    else:
        _object(value, ("writer_id", "audit_sequence", "event_sha256"))
        _uuid(value["writer_id"])
        _integer(value["audit_sequence"], 1, 1024)
        _hash(value["event_sha256"])


def _observation(value):
    _object(value, ("evidence_sha256", "connections", "request_bytes", "response_bytes"))
    _hash(value["evidence_sha256"])
    for key, maximum in (("connections", 3), ("request_bytes", 4096), ("response_bytes", 4096)):
        _integer(value[key], 0, maximum)


@_validation("invalid_request")
def validate_request(value):
    value = _detach(value, MAX_REQUEST_BYTES)
    _object(value, ("schema_version", "engagement_id", "event_id", "operation",
                    "expected_revision", "expected_generation", "body"))
    if value["schema_version"] != "2":
        _fail()
    _uuid(value["engagement_id"])
    _uuid(value["event_id"])
    operation = _member(value["operation"], _OPERATIONS)
    if operation in {"create", "complete"}:
        if value["expected_revision"] is not None or value["expected_generation"] is not None:
            _fail()
    else:
        _integer(value["expected_revision"], 1, 64)
        _integer(value["expected_generation"], 0, 64)
    body = value["body"]
    if operation in {"create", "revise"}:
        value["body"] = _roe(body)
    elif operation == "revoke":
        if body is not None:
            _fail()
    else:
        fields = {"session_id", "owner_id", "clock"}
        fields |= {"session": {"original_deadline_ns"},
                   "reserve": {"dispatch_id", "slot", "approval", "audit"},
                   "complete": {"dispatch_id", "outcome", "observation"}}[operation]
        _object(body, fields)
        _uuid(body["session_id"])
        _uuid(body["owner_id"])
        body["clock"] = validate_clock(body["clock"])
        if operation == "session":
            _integer(body["original_deadline_ns"], 1)
        else:
            _uuid(body["dispatch_id"])
        if operation == "reserve":
            _member(body["slot"], _SLOTS)
            _reference(body["approval"], "approval")
            _reference(body["audit"], "audit")
        if operation == "complete":
            _member(body["outcome"], _OUTCOMES)
            if body["observation"] is not None:
                _observation(body["observation"])
            if body["outcome"] == "reported_success" and (
                    body["observation"] is None or any(body["observation"][k] == 0
                    for k in ("connections", "request_bytes", "response_bytes"))):
                _fail()
    return value


@_validation("invalid_request")
def decode_request(raw):
    return validate_request(_decode(raw, MAX_REQUEST_BYTES))


@_bounded
def request_digest(value):
    return hashlib.sha256(REQUEST_DOMAIN + canonical(validate_request(value))).hexdigest()


def _supported(roe):
    if ("http" in roe["excluded_services"] or roe["scope"]["http"]["path"] != "/"
            or not {"configurable_nmap_service_v1", "configurable_http_headers_v1"}
            <= set(roe["allowed_profiles"])):
        _fail("unsupported_plan")


@_bounded
def policy_for_roe(roe):
    roe = _roe(roe)
    return _policy(roe)


def _policy(roe):
    _supported(roe)
    http = roe["scope"]["http"]
    return parse_policy({"schema_version": "1", "policy_version": "engagement-http-prefix-v1",
        "allowed_targets": [http["target"]],
        "allowed_tools": ["configurable_nmap_service_v1", "configurable_http_headers_v1"],
        "allowed_ports": [http["port"]], "allowed_methods": ["GET"],
        "max_timeout_seconds": 5, "max_output_bytes": 8192, "max_targets": 1,
        "require_approval": True, "approval_ttl_seconds": 60}).to_dict()


@_bounded
def reservation_for(roe, slot):
    roe = _roe(roe)
    return _reservation(roe, slot)


def _reservation(roe, slot):
    _supported(roe)
    _member(slot, _SLOTS)
    _, connections, request_bytes, response_bytes = _SLOTS[slot]
    return {"actions": 1, "connections": connections, "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            "runtime_ms": min(30000, roe["limits"]["max_action_ms"])}


def _window(roe):
    epoch = datetime(1970, 1, 1)
    result = []
    for field in ("start_utc", "end_utc"):
        delta = datetime.strptime(roe["window"][field], "%Y-%m-%dT%H:%M:%SZ") - epoch
        result.append((delta.days * 86400 + delta.seconds) * 1000000000)
    return result


def _add(a, b):
    value = a + b
    if not 0 <= value <= INTEGER_MAX:
        _fail("invalid_request")
    return value


def _window_end(roe, clock):
    start, end = _window(roe)
    before, after, utc = clock["mono_before_ns"], clock["mono_after_ns"], clock["utc_ns"]
    if utc < start or _add(utc, after - before) >= end:
        _fail("window_closed")
    return _add(before, end - utc)


@_bounded
def window_budget(roe, clock, *, original_deadline_ns, utc_high_water_ns=None):
    roe, clock = _roe(roe), validate_clock(clock)
    _integer(original_deadline_ns, 1)
    if utc_high_water_ns is not None:
        _integer(utc_high_water_ns, UTC_MIN, UTC_MAX)
    return _window_budget(roe, clock, original_deadline_ns, utc_high_water_ns)


def _window_budget(roe, clock, original_deadline_ns, utc_high_water_ns):
    end = _window_end(roe, clock)
    if utc_high_water_ns is not None and clock["utc_ns"] + CLOCK_TOLERANCE < utc_high_water_ns:
        _fail("clock_invalid")
    after = clock["mono_after_ns"]
    if original_deadline_ns <= after:
        _fail("deadline_expired")
    if original_deadline_ns > _add(after, SESSION_NS):
        _fail("invalid_request")
    return {"window_deadline_ns": end,
            "session_deadline_ns": min(original_deadline_ns, end)}


def _clock_status(roe, clock, previous, high_water, deadline):
    before, after, utc = clock["mono_before_ns"], clock["mono_after_ns"], clock["utc_ns"]
    if before < previous["mono_after_ns"]:
        return "nonmonotonic"
    start, end = _window(roe)
    if utc < start or _add(utc, after - before) >= end:
        return "window_closed"
    delta = utc - previous["utc_ns"]
    low = before - previous["mono_after_ns"] - CLOCK_TOLERANCE
    high = after - previous["mono_before_ns"] + CLOCK_TOLERANCE
    if (high_water is not None and utc + CLOCK_TOLERANCE < high_water) or not low <= delta <= high:
        return "clock_changed"
    if after >= deadline:
        return "deadline_elapsed"
    return "valid"


def _status_error(status):
    if status == "window_closed":
        _fail("window_closed")
    if status in {"nonmonotonic", "clock_changed"}:
        _fail("clock_invalid")
    if status == "deadline_elapsed":
        _fail("deadline_expired")


class _Engine:
    """One deterministic transition implementation shared by apply and replay."""

    def __init__(self):
        self.export = None
        self.events, self.sessions, self.reservations, self.completions = {}, {}, {}, {}
        self.slots, self.approvals, self.audits, self.clocks, self.roes = {}, set(), set(), {}, {}
        self.policies, self.actions = {}, {}

    def push(self, request):
        _check_deadline(_operation_deadline())
        event_id, operation, body = request["event_id"], request["operation"], request["body"]
        if event_id in self.events:
            _fail("conflict")
        if self.export is None:
            if operation != "create":
                _fail("conflict")
            roe_sha256 = _validated_roe_digest(body)
            self.export = {"schema_version": "2", "kind": "engagement_dispatch_ledger",
                "engagement_id": request["engagement_id"], "state": {
                "revision": 1, "generation": 0, "status": "recorded", "last_sequence": 1,
                "roe_sha256": roe_sha256, "usage": {key: 0 for key in _CAPS},
                "utc_high_water_ns": None}, "revisions": [{"revision": 1, "roe": body,
                "roe_sha256": roe_sha256}], "sessions": [], "reservations": [],
                "completions": [], "events": []}
            self.roes[1] = body
        else:
            if request["engagement_id"] != self.export["engagement_id"] or operation == "create":
                _fail("conflict")
            if len(self.export["events"]) >= MAX_EVENTS:
                _fail("limit_exceeded")
            state = self.export["state"]
            if operation != "complete":
                if state["status"] == "revoked":
                    _fail("revoked")
                if (request["expected_revision"], request["expected_generation"]) != (
                        state["revision"], state["generation"]):
                    _fail("conflict")
            if operation == "revise":
                if len(self.roes) >= MAX_REVISIONS:
                    _fail("limit_exceeded")
                state["revision"] += 1
                state["generation"] += 1
                state["roe_sha256"] = _validated_roe_digest(body)
                self.roes[state["revision"]] = body
                self.export["revisions"].append({"revision": state["revision"],
                    "roe": body, "roe_sha256": state["roe_sha256"]})
            elif operation == "revoke":
                state["generation"] += 1
                state["status"] = "revoked"
            elif operation == "session":
                self._session(body)
            elif operation == "reserve":
                self._reserve(body)
            elif operation == "complete":
                self._complete(body)
        state = self.export["state"]
        if operation in {"session", "reserve", "complete"}:
            utc = body["clock"]["utc_ns"]
            state["utc_high_water_ns"] = max(state["utc_high_water_ns"] or utc, utc)
            self.clocks[body["session_id"]] = body["clock"]
        sequence = len(self.export["events"]) + 1
        state["last_sequence"] = sequence
        receipt = {"schema_version": "2", "engagement_id": self.export["engagement_id"],
            "event_id": event_id, "sequence": sequence, "operation": operation,
            "revision": state["revision"], "generation": state["generation"],
            "status": state["status"],
            "session_id": body["session_id"] if operation in {"session", "reserve", "complete"} else None,
            "dispatch_id": body["dispatch_id"] if operation in {"reserve", "complete"} else None,
            "state_sha256": hashlib.sha256(STATE_DOMAIN + canonical(state)).hexdigest(),
            "usage": dict(state["usage"])}
        if len(canonical(receipt)) > MAX_RECEIPT_BYTES:
            _fail("limit_exceeded")
        event = {"sequence": sequence, "event_id": event_id,
            "request_sha256": hashlib.sha256(REQUEST_DOMAIN + canonical(request)).hexdigest(),
            "request": request, "receipt": receipt}
        self.export["events"].append(event)
        self.events[event_id] = event
        return receipt

    def _session(self, body):
        state = self.export["state"]
        if body["session_id"] in self.sessions:
            _fail("conflict")
        if len(self.sessions) >= MAX_SESSIONS:
            _fail("limit_exceeded")
        roe = self.roes[state["revision"]]
        if state["revision"] not in self.policies:
            self.policies[state["revision"]] = parse_policy(_policy(roe)).digest
        budget = _window_budget(roe, body["clock"], body["original_deadline_ns"],
                                state["utc_high_water_ns"])
        row = {"session_id": body["session_id"], "owner_id": body["owner_id"],
            "revision": state["revision"], "generation": state["generation"],
            "plan": "http-prefix-v1", "policy_sha256": self.policies[state["revision"]],
            "clock": body["clock"], "original_deadline_ns": body["original_deadline_ns"],
            "session_deadline_ns": budget["session_deadline_ns"]}
        self._append("sessions", row, MAX_SESSION_BYTES)
        self.sessions[row["session_id"]] = row

    def _owned_session(self, body):
        session = self.sessions.get(body["session_id"])
        if session is None:
            _fail("conflict")
        if session["owner_id"] != body["owner_id"]:
            _fail("foreign_owner")
        return session

    def _reserve(self, body):
        state = self.export["state"]
        session = self._owned_session(body)
        if (session["revision"], session["generation"]) != (state["revision"], state["generation"]):
            _fail("conflict")
        if len(self.reservations) >= MAX_RESERVATIONS:
            _fail("limit_exceeded")
        slot_key = body["session_id"], body["slot"]
        approval_key = body["approval"]["broker_id"], body["approval"]["consume_sequence"]
        audit_key = body["audit"]["writer_id"], body["audit"]["audit_sequence"]
        if (body["dispatch_id"] in self.reservations or slot_key in self.slots
                or approval_key in self.approvals or audit_key in self.audits):
            _fail("conflict")
        ready = session["clock"]["mono_after_ns"]
        if body["slot"] == "http_headers":
            predecessor = self.slots.get((body["session_id"], "http_identify"))
            complete = self.completions.get(predecessor)
            if complete is None or complete["continuation_eligible"] is not True:
                _fail("predecessor_required")
            ready = complete["clock"]["mono_after_ns"]
        roe = self.roes[session["revision"]]
        status = _clock_status(roe, body["clock"], self.clocks[body["session_id"]],
                               state["utc_high_water_ns"], session["session_deadline_ns"])
        _status_error(status)
        cost = _reservation(roe, body["slot"])
        deadline = min(session["session_deadline_ns"], _add(ready, cost["runtime_ms"] * 1000000),
                       _window_end(roe, body["clock"]))
        if body["clock"]["mono_after_ns"] >= deadline:
            _fail("deadline_expired")
        usage = {key: state["usage"][key] + cost[key] for key in _CAPS}
        if any(usage[key] > roe["limits"][_CAPS[key]] for key in _CAPS):
            _fail("allowance_exhausted")
        action_key = session["revision"], body["slot"]
        if action_key not in self.actions:
            action = configurable_contract.action(roe["scope"], _SLOTS[body["slot"]][0])
            self.actions[action_key] = action["action_id"], parse_action(action).digest
        action_id, action_digest = self.actions[action_key]
        row = {"dispatch_id": body["dispatch_id"], "session_id": body["session_id"],
            "owner_id": body["owner_id"], "revision": session["revision"],
            "generation": session["generation"], "slot": body["slot"],
            "action_id": action_id, "action_sha256": action_digest,
            "policy_sha256": session["policy_sha256"], "approval": body["approval"],
            "audit": body["audit"], "clock": body["clock"], "ready_at_ns": ready,
            "deadline_ns": deadline, "reservation": cost}
        self._append("reservations", row, MAX_RESERVATION_BYTES)
        self.reservations[row["dispatch_id"]] = row
        self.slots[slot_key] = row["dispatch_id"]
        self.approvals.add(approval_key)
        self.audits.add(audit_key)
        state["usage"] = usage

    def _complete(self, body):
        state = self.export["state"]
        session = self._owned_session(body)
        reserved = self.reservations.get(body["dispatch_id"])
        if reserved is None or reserved["session_id"] != body["session_id"]:
            _fail("conflict")
        if body["dispatch_id"] in self.completions:
            _fail("conflict")
        if len(self.completions) >= MAX_COMPLETIONS:
            _fail("limit_exceeded")
        if body["observation"] is not None and any(body["observation"][key] > reserved["reservation"][key]
                for key in ("connections", "request_bytes", "response_bytes")):
            _fail("invalid_request")
        status = _clock_status(self.roes[reserved["revision"]], body["clock"],
            self.clocks[body["session_id"]], state["utc_high_water_ns"],
            min(reserved["deadline_ns"], session["session_deadline_ns"]))
        eligible = (reserved["slot"] == "http_identify" and body["outcome"] == "reported_success"
            and state["status"] == "recorded" and status == "valid"
            and (reserved["revision"], reserved["generation"]) == (state["revision"], state["generation"]))
        row = {"dispatch_id": body["dispatch_id"], "session_id": body["session_id"],
            "owner_id": body["owner_id"], "outcome": body["outcome"],
            "observation": body["observation"], "clock": body["clock"],
            "clock_status": status, "continuation_eligible": eligible}
        self._append("completions", row, MAX_COMPLETION_BYTES)
        self.completions[row["dispatch_id"]] = row

    def _append(self, field, row, maximum):
        if len(canonical(row)) > maximum:
            _fail("limit_exceeded")
        self.export[field].append(row)


def _reconstruct(value):
    raw = canonical(value)
    value = json.loads(raw)
    _object(value, ("schema_version", "kind", "engagement_id", "state", "revisions",
                    "sessions", "reservations", "completions", "events"))
    if value["schema_version"] != "2" or value["kind"] != "engagement_dispatch_ledger":
        _fail("invalid_export")
    _uuid(value["engagement_id"])
    for field, minimum, maximum in (("revisions", 1, 64), ("sessions", 0, 64),
            ("reservations", 0, 64), ("completions", 0, 64), ("events", 1, 257)):
        if type(value[field]) is not list:
            _fail("invalid_export")
        if not minimum <= len(value[field]) <= maximum:
            _fail("limit_exceeded")
    engine = _Engine()
    for event in value["events"]:
        _object(event, ("sequence", "event_id", "request_sha256", "request", "receipt"))
        request = validate_request(event["request"])
        engine.push(request)
    # This exact comparison covers every event and derived row, including all
    # unknown/missing fields and bool-versus-int distinctions. Comparing each
    # event separately as well would duplicate the same full validation work.
    if raw != canonical(engine.export):
        _fail("invalid_export")
    return engine


@_validation("invalid_export")
def validate_export(value):
    """Reconstruct every transition, reference, counter and immutable row."""
    return _reconstruct(value).export


@_validation("invalid_export")
def decode_export(raw):
    return validate_export(_decode(raw, MAX_EXPORT_BYTES))


@_bounded
def _apply(snapshot_or_none, normalized_request):
    """New transition only. The store owns retry and current-handle custody."""
    engine = _Engine() if snapshot_or_none is None else _reconstruct(snapshot_or_none)
    request = validate_request(normalized_request)
    engine.push(request)
    result = _detach(engine.export, MAX_EXPORT_BYTES)
    return result, result["events"][-1]["receipt"]

SCHEMA_SQL = ("CREATE TABLE revisions (revision INTEGER PRIMARY KEY CHECK(typeof(revision)='integer' AND "
 "revision BETWEEN 1 AND 64), roe_json TEXT NOT NULL CHECK(typeof(roe_json)='text' AND "
 "length(roe_json) BETWEEN 1 AND 4096), roe_sha256 TEXT NOT NULL CHECK(typeof(roe_sha256)='text' "
 'AND length(roe_sha256) BETWEEN 64 AND 64))',
 "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(typeof(singleton)='integer' AND "
 "singleton BETWEEN 1 AND 1), engagement_id TEXT NOT NULL CHECK(typeof(engagement_id)='text' AND "
 'length(engagement_id) BETWEEN 36 AND 36), current_revision INTEGER NOT NULL REFERENCES '
 "revisions(revision) CHECK(typeof(current_revision)='integer' AND current_revision BETWEEN 1 AND "
 "64), generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 0 AND "
 "64), status TEXT NOT NULL CHECK(status IN ('recorded','revoked')), last_sequence INTEGER NOT "
 "NULL CHECK(typeof(last_sequence)='integer' AND last_sequence BETWEEN 1 AND 257), "
 "actions_reserved INTEGER NOT NULL CHECK(typeof(actions_reserved)='integer' AND actions_reserved "
 'BETWEEN 0 AND 64), connections_reserved INTEGER NOT NULL '
 "CHECK(typeof(connections_reserved)='integer' AND connections_reserved BETWEEN 0 AND 256), "
 "request_bytes_reserved INTEGER NOT NULL CHECK(typeof(request_bytes_reserved)='integer' AND "
 'request_bytes_reserved BETWEEN 0 AND 1048576), response_bytes_reserved INTEGER NOT NULL '
 "CHECK(typeof(response_bytes_reserved)='integer' AND response_bytes_reserved BETWEEN 0 AND "
 "1048576), runtime_ms_reserved INTEGER NOT NULL CHECK(typeof(runtime_ms_reserved)='integer' AND "
 'runtime_ms_reserved BETWEEN 0 AND 86400000), utc_high_water_ns INTEGER CHECK(utc_high_water_ns '
 "IS NULL OR (typeof(utc_high_water_ns)='integer' AND utc_high_water_ns BETWEEN 946684800000000000 "
 'AND 4102444799999999999)))',
 "CREATE TABLE sessions (session_id TEXT PRIMARY KEY NOT NULL CHECK(typeof(session_id)='text' AND "
 "length(session_id) BETWEEN 36 AND 36), owner_id TEXT NOT NULL CHECK(typeof(owner_id)='text' AND "
 'length(owner_id) BETWEEN 36 AND 36), revision INTEGER NOT NULL REFERENCES revisions(revision) '
 "CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 64), generation INTEGER NOT NULL "
 "CHECK(typeof(generation)='integer' AND generation BETWEEN 0 AND 64), session_json TEXT NOT NULL "
 "CHECK(typeof(session_json)='text' AND length(session_json) BETWEEN 1 AND 4096))",
 'CREATE TABLE reservations (dispatch_id TEXT PRIMARY KEY NOT NULL '
 "CHECK(typeof(dispatch_id)='text' AND length(dispatch_id) BETWEEN 36 AND 36), session_id TEXT NOT "
 "NULL REFERENCES sessions(session_id) CHECK(typeof(session_id)='text' AND length(session_id) "
 "BETWEEN 36 AND 36), slot TEXT NOT NULL CHECK(slot IN ('http_identify','http_headers')), "
 "approval_broker_id TEXT NOT NULL CHECK(typeof(approval_broker_id)='text' AND "
 'length(approval_broker_id) BETWEEN 36 AND 36), approval_consume_sequence INTEGER NOT NULL '
 "CHECK(typeof(approval_consume_sequence)='integer' AND approval_consume_sequence BETWEEN 1 AND "
 "32), audit_writer_id TEXT NOT NULL CHECK(typeof(audit_writer_id)='text' AND "
 'length(audit_writer_id) BETWEEN 36 AND 36), audit_sequence INTEGER NOT NULL '
 "CHECK(typeof(audit_sequence)='integer' AND audit_sequence BETWEEN 1 AND 1024), reservation_json "
 "TEXT NOT NULL CHECK(typeof(reservation_json)='text' AND length(reservation_json) BETWEEN 1 AND "
 '8192), UNIQUE(session_id,slot), UNIQUE(approval_broker_id,approval_consume_sequence), '
 'UNIQUE(audit_writer_id,audit_sequence))',
 'CREATE TABLE completions (dispatch_id TEXT PRIMARY KEY NOT NULL REFERENCES '
 "reservations(dispatch_id) CHECK(typeof(dispatch_id)='text' AND length(dispatch_id) BETWEEN 36 "
 "AND 36), completion_json TEXT NOT NULL CHECK(typeof(completion_json)='text' AND "
 'length(completion_json) BETWEEN 1 AND 4096))',
 "CREATE TABLE events (sequence INTEGER PRIMARY KEY CHECK(typeof(sequence)='integer' AND sequence "
 "BETWEEN 1 AND 257), event_id TEXT NOT NULL UNIQUE CHECK(typeof(event_id)='text' AND "
 'length(event_id) BETWEEN 36 AND 36), request_sha256 TEXT NOT NULL '
 "CHECK(typeof(request_sha256)='text' AND length(request_sha256) BETWEEN 64 AND 64), request_json "
 "TEXT NOT NULL CHECK(typeof(request_json)='text' AND length(request_json) BETWEEN 1 AND 8192), "
 "receipt_json TEXT NOT NULL CHECK(typeof(receipt_json)='text' AND length(receipt_json) BETWEEN 1 "
 'AND 4096))',
 'CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER sessions_no_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER sessions_no_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER reservations_no_update BEFORE UPDATE ON reservations BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER reservations_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER completions_no_update BEFORE UPDATE ON completions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER completions_no_delete BEFORE DELETE ON completions BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END",
 'CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, '
 "'engagement_dispatch_immutable'); END")
SQLITE_LIMITS = {'ATTACHED': 0,
 'COLUMN': 32,
 'EXPR_DEPTH': 32,
 'LENGTH': 2097152,
 'SQL_LENGTH': 32768,
 'TRIGGER_DEPTH': 8,
 'VARIABLE_NUMBER': 64}
ERROR_CODES = frozenset(['engagement_dispatch_invalid_input',
 'engagement_dispatch_invalid_roe',
 'engagement_dispatch_invalid_request',
 'engagement_dispatch_invalid_export',
 'engagement_dispatch_limit_exceeded',
 'engagement_dispatch_already_exists',
 'engagement_dispatch_store_unavailable',
 'engagement_dispatch_store_invalid',
 'engagement_dispatch_read_only',
 'engagement_dispatch_conflict',
 'engagement_dispatch_revoked',
 'engagement_dispatch_event_unknown',
 'engagement_dispatch_foreign_owner',
 'engagement_dispatch_unsupported_plan',
 'engagement_dispatch_window_closed',
 'engagement_dispatch_clock_invalid',
 'engagement_dispatch_deadline_expired',
 'engagement_dispatch_allowance_exhausted',
 'engagement_dispatch_predecessor_required',
 'engagement_dispatch_snapshot_changed',
 'engagement_dispatch_output_exists',
 'engagement_dispatch_timeout'])

SCHEMA_OBJECTS = (('table',
  'completions',
  'completions',
  'CREATE TABLE completions (dispatch_id TEXT PRIMARY KEY NOT NULL REFERENCES '
  "reservations(dispatch_id) CHECK(typeof(dispatch_id)='text' AND length(dispatch_id) BETWEEN 36 "
  "AND 36), completion_json TEXT NOT NULL CHECK(typeof(completion_json)='text' AND "
  'length(completion_json) BETWEEN 1 AND 4096))'),
 ('trigger',
  'completions_no_delete',
  'completions',
  'CREATE TRIGGER completions_no_delete BEFORE DELETE ON completions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('trigger',
  'completions_no_update',
  'completions',
  'CREATE TRIGGER completions_no_update BEFORE UPDATE ON completions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('table',
  'events',
  'events',
  "CREATE TABLE events (sequence INTEGER PRIMARY KEY CHECK(typeof(sequence)='integer' AND sequence "
  "BETWEEN 1 AND 257), event_id TEXT NOT NULL UNIQUE CHECK(typeof(event_id)='text' AND "
  'length(event_id) BETWEEN 36 AND 36), request_sha256 TEXT NOT NULL '
  "CHECK(typeof(request_sha256)='text' AND length(request_sha256) BETWEEN 64 AND 64), request_json "
  "TEXT NOT NULL CHECK(typeof(request_json)='text' AND length(request_json) BETWEEN 1 AND 8192), "
  "receipt_json TEXT NOT NULL CHECK(typeof(receipt_json)='text' AND length(receipt_json) BETWEEN 1 "
  'AND 4096))'),
 ('trigger',
  'events_no_delete',
  'events',
  'CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('trigger',
  'events_no_update',
  'events',
  'CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('table',
  'metadata',
  'metadata',
  "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(typeof(singleton)='integer' AND "
  "singleton BETWEEN 1 AND 1), engagement_id TEXT NOT NULL CHECK(typeof(engagement_id)='text' AND "
  'length(engagement_id) BETWEEN 36 AND 36), current_revision INTEGER NOT NULL REFERENCES '
  "revisions(revision) CHECK(typeof(current_revision)='integer' AND current_revision BETWEEN 1 AND "
  "64), generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 0 "
  "AND 64), status TEXT NOT NULL CHECK(status IN ('recorded','revoked')), last_sequence INTEGER "
  "NOT NULL CHECK(typeof(last_sequence)='integer' AND last_sequence BETWEEN 1 AND 257), "
  "actions_reserved INTEGER NOT NULL CHECK(typeof(actions_reserved)='integer' AND actions_reserved "
  'BETWEEN 0 AND 64), connections_reserved INTEGER NOT NULL '
  "CHECK(typeof(connections_reserved)='integer' AND connections_reserved BETWEEN 0 AND 256), "
  "request_bytes_reserved INTEGER NOT NULL CHECK(typeof(request_bytes_reserved)='integer' AND "
  'request_bytes_reserved BETWEEN 0 AND 1048576), response_bytes_reserved INTEGER NOT NULL '
  "CHECK(typeof(response_bytes_reserved)='integer' AND response_bytes_reserved BETWEEN 0 AND "
  "1048576), runtime_ms_reserved INTEGER NOT NULL CHECK(typeof(runtime_ms_reserved)='integer' AND "
  'runtime_ms_reserved BETWEEN 0 AND 86400000), utc_high_water_ns INTEGER CHECK(utc_high_water_ns '
  "IS NULL OR (typeof(utc_high_water_ns)='integer' AND utc_high_water_ns BETWEEN "
  '946684800000000000 AND 4102444799999999999)))'),
 ('table',
  'reservations',
  'reservations',
  'CREATE TABLE reservations (dispatch_id TEXT PRIMARY KEY NOT NULL '
  "CHECK(typeof(dispatch_id)='text' AND length(dispatch_id) BETWEEN 36 AND 36), session_id TEXT "
  "NOT NULL REFERENCES sessions(session_id) CHECK(typeof(session_id)='text' AND length(session_id) "
  "BETWEEN 36 AND 36), slot TEXT NOT NULL CHECK(slot IN ('http_identify','http_headers')), "
  "approval_broker_id TEXT NOT NULL CHECK(typeof(approval_broker_id)='text' AND "
  'length(approval_broker_id) BETWEEN 36 AND 36), approval_consume_sequence INTEGER NOT NULL '
  "CHECK(typeof(approval_consume_sequence)='integer' AND approval_consume_sequence BETWEEN 1 AND "
  "32), audit_writer_id TEXT NOT NULL CHECK(typeof(audit_writer_id)='text' AND "
  'length(audit_writer_id) BETWEEN 36 AND 36), audit_sequence INTEGER NOT NULL '
  "CHECK(typeof(audit_sequence)='integer' AND audit_sequence BETWEEN 1 AND 1024), reservation_json "
  "TEXT NOT NULL CHECK(typeof(reservation_json)='text' AND length(reservation_json) BETWEEN 1 AND "
  '8192), UNIQUE(session_id,slot), UNIQUE(approval_broker_id,approval_consume_sequence), '
  'UNIQUE(audit_writer_id,audit_sequence))'),
 ('trigger',
  'reservations_no_delete',
  'reservations',
  'CREATE TRIGGER reservations_no_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('trigger',
  'reservations_no_update',
  'reservations',
  'CREATE TRIGGER reservations_no_update BEFORE UPDATE ON reservations BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('table',
  'revisions',
  'revisions',
  "CREATE TABLE revisions (revision INTEGER PRIMARY KEY CHECK(typeof(revision)='integer' AND "
  "revision BETWEEN 1 AND 64), roe_json TEXT NOT NULL CHECK(typeof(roe_json)='text' AND "
  "length(roe_json) BETWEEN 1 AND 4096), roe_sha256 TEXT NOT NULL CHECK(typeof(roe_sha256)='text' "
  'AND length(roe_sha256) BETWEEN 64 AND 64))'),
 ('trigger',
  'revisions_no_delete',
  'revisions',
  'CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('trigger',
  'revisions_no_update',
  'revisions',
  'CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('table',
  'sessions',
  'sessions',
  "CREATE TABLE sessions (session_id TEXT PRIMARY KEY NOT NULL CHECK(typeof(session_id)='text' AND "
  "length(session_id) BETWEEN 36 AND 36), owner_id TEXT NOT NULL CHECK(typeof(owner_id)='text' AND "
  'length(owner_id) BETWEEN 36 AND 36), revision INTEGER NOT NULL REFERENCES revisions(revision) '
  "CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 64), generation INTEGER NOT NULL "
  "CHECK(typeof(generation)='integer' AND generation BETWEEN 0 AND 64), session_json TEXT NOT NULL "
  "CHECK(typeof(session_json)='text' AND length(session_json) BETWEEN 1 AND 4096))"),
 ('trigger',
  'sessions_no_delete',
  'sessions',
  'CREATE TRIGGER sessions_no_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('trigger',
  'sessions_no_update',
  'sessions',
  'CREATE TRIGGER sessions_no_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, '
  "'engagement_dispatch_immutable'); END"),
 ('index', 'sqlite_autoindex_completions_1', 'completions', None),
 ('index', 'sqlite_autoindex_events_1', 'events', None),
 ('index', 'sqlite_autoindex_reservations_1', 'reservations', None),
 ('index', 'sqlite_autoindex_reservations_2', 'reservations', None),
 ('index', 'sqlite_autoindex_reservations_3', 'reservations', None),
 ('index', 'sqlite_autoindex_reservations_4', 'reservations', None),
 ('index', 'sqlite_autoindex_sessions_1', 'sessions', None))
