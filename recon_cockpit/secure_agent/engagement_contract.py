"""Bounded, nonsecret engagement metadata. None of these values grants authority."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from functools import wraps

from .configurable_scope import validate_scope

MAX_ROE_BYTES = 4096
MAX_REQUEST_BYTES = 8192
MAX_EXPORT_BYTES = 524288
MAX_DEPTH = 12
MAX_REVISIONS = 64
MAX_EVENTS = 65
OPERATION_SECONDS = 2.0
ROE_DOMAIN = b"recon-engagement-roe-v1\x00"
REQUEST_DOMAIN = b"recon-engagement-request-v1\x00"
PROFILES = (
    "configurable_http_headers_v1",
    "configurable_nmap_service_v1",
    "configurable_ssh_host_keys_v1",
)
ERROR_CODES = frozenset({
    "engagement_invalid_input", "engagement_invalid_roe", "engagement_invalid_export",
    "engagement_limit_exceeded", "engagement_already_exists", "engagement_store_unavailable",
    "engagement_store_invalid", "engagement_read_only", "engagement_conflict",
    "engagement_revoked", "engagement_event_unknown", "engagement_snapshot_changed",
    "engagement_output_exists", "engagement_timeout",
})
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_HASH = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_ROE_FIELDS = {"schema_version", "mode", "scope", "allowed_profiles", "excluded_services", "window", "limits"}
_REQUEST_FIELDS = {"schema_version", "engagement_id", "event_id", "operation", "expected_revision", "expected_generation", "roe"}
_RECEIPT_FIELDS = {"schema_version", "engagement_id", "event_id", "sequence", "operation", "expected_revision", "expected_generation", "revision", "generation", "status", "roe_sha256", "request_sha256"}
_LIMITS = {"max_actions": 64, "max_connections": 256, "max_request_bytes": 1048576,
           "max_response_bytes": 1048576, "max_action_ms": 60000, "max_engagement_ms": 86400000}
_ACTIVE_DEADLINE = ContextVar("engagement_operation_deadline", default=None)


class EngagementError(ValueError):
    """A closed public error code; never include caller data or OS diagnostics."""

    def __init__(self, code):
        if type(code) is not str or code not in ERROR_CODES:
            raise ValueError("engagement_invalid_error_code")
        self.code = code
        super().__init__(code)


def _check_time(deadline):
    active = _active_deadline()
    if active is not None:
        deadline = min(deadline, active)
    if time.monotonic() >= deadline:
        raise EngagementError("engagement_timeout")


def _active_deadline():
    value = _ACTIVE_DEADLINE.get()
    # Fork copies ContextVars, but a fresh child operation is not part of the
    # parent's in-flight API call. Store handles enforce their own PID custody.
    return value[1] if value is not None and value[0] == os.getpid() else None


def _operation_deadline():
    """An outer operation's deadline is never extended by nested validation."""
    deadline = time.monotonic() + OPERATION_SECONDS
    active = _active_deadline()
    return deadline if active is None else min(deadline, active)


@contextmanager
def _using_deadline(deadline):
    """Share an existing store/file budget without changing any public API."""
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise EngagementError("engagement_invalid_input")
    active = _active_deadline()
    effective = deadline if active is None else min(deadline, active)
    token = _ACTIVE_DEADLINE.set((os.getpid(), effective))
    try:
        _check_time(effective)
        yield effective
        _check_time(effective)
    finally:
        _ACTIVE_DEADLINE.reset(token)


def _bounded_operation(function):
    @wraps(function)
    def bounded(*args, **kwargs):
        with _using_deadline(_operation_deadline()):
            return function(*args, **kwargs)
    return bounded


def _fail(code="engagement_invalid_input"):
    raise EngagementError(code)


def _tree(value, deadline):
    """Detach strict JSON data before encoding, with finite traversal work."""
    units = 0

    def copy(current, depth):
        nonlocal units
        _check_time(deadline)
        units += 1
        if units > MAX_EXPORT_BYTES:
            _fail("engagement_limit_exceeded")
        kind = type(current)
        if kind in (dict, list):
            depth += 1
            if depth > MAX_DEPTH or len(current) > MAX_EXPORT_BYTES:
                _fail("engagement_limit_exceeded")
            if kind is dict:
                result = {}
                for key, item in current.items():
                    if type(key) is not str:
                        _fail()
                    units += len(key)
                    if units > MAX_EXPORT_BYTES:
                        _fail("engagement_limit_exceeded")
                    if any(0xD800 <= ord(char) <= 0xDFFF for char in key):
                        _fail()
                    result[key] = copy(item, depth)
                return result
            return [copy(item, depth) for item in current]
        elif kind is str:
            units += len(current)
            if units > MAX_EXPORT_BYTES:
                _fail("engagement_limit_exceeded")
            # Surrogates are not valid Unicode input, even if JSON could escape them.
            if any(0xD800 <= ord(char) <= 0xDFFF for char in current):
                _fail()
        elif kind is int:
            if current.bit_length() > MAX_EXPORT_BYTES * 4:
                _fail("engagement_limit_exceeded")
        elif current is not None and kind is not bool:
            _fail()
        if units > MAX_EXPORT_BYTES:
            _fail("engagement_limit_exceeded")
        return current

    return copy(value, 0)


@_bounded_operation
def canonical(value):
    """Return bounded canonical ASCII JSON bytes, rejecting non-JSON types."""
    deadline = _operation_deadline()
    chunks = []
    size = 0
    try:
        value = _tree(value, deadline)
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False)
        for chunk in encoder.iterencode(value):
            _check_time(deadline)
            size += len(chunk)
            if size > MAX_EXPORT_BYTES:
                _fail("engagement_limit_exceeded")
            chunks.append(chunk)
        result = "".join(chunks).encode("ascii")
    except (TypeError, ValueError, OverflowError, RuntimeError, UnicodeError) as exc:
        if isinstance(exc, EngagementError):
            raise
        raise EngagementError("engagement_invalid_input") from None
    _check_time(deadline)
    return result


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        _fail()
    return value


def _literal(value, expected):
    if type(value) is not str or value != expected:
        _fail()


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail()
    return value


def _uuid(value):
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail()
    return value


def _digest(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail()
    return value


def _sequence(value, allowed, minimum, maximum):
    if (type(value) is not list or not minimum <= len(value) <= maximum
            or any(type(item) is not str or item not in allowed for item in value)
            or value != sorted(set(value))):
        _fail()
    return list(value)


def _instant(value):
    if type(value) is not str or _UTC.fullmatch(value) is None:
        _fail()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise EngagementError("engagement_invalid_input") from None


def _bounded(value, limit):
    encoded = canonical(value)
    if len(encoded) > limit:
        _fail("engagement_limit_exceeded")
    # Validation uses the detached bytes just checked, never a caller-owned tree
    # that another thread could change between field checks.
    return json.loads(encoded)


def _translate(error, code):
    if error.code in {"engagement_limit_exceeded", "engagement_timeout"}:
        raise error
    raise EngagementError(code) from None


@_bounded_operation
def validate_roe(value):
    """Validate the closed disconnected-fixture declaration, returning a copy."""
    deadline = _operation_deadline()
    try:
        value = _bounded(value, MAX_ROE_BYTES)
        _object(value, _ROE_FIELDS)
        _literal(value["schema_version"], "1")
        _literal(value["mode"], "disconnected_owned")
        try:
            scope = validate_scope(value["scope"])
        except (ValueError, TypeError, KeyError):
            _fail()
        profiles = _sequence(value["allowed_profiles"], PROFILES, 1, 3)
        exclusions = _sequence(value["excluded_services"], ("http", "ssh"), 0, 1)
        window = _object(value["window"], {"start_utc", "end_utc"})
        duration = int((_instant(window["end_utc"]) - _instant(window["start_utc"])).total_seconds())
        if not 0 < duration <= 86400:
            _fail()
        limits = _object(value["limits"], set(_LIMITS))
        limits = {key: _integer(limits[key], 1, high) for key, high in _LIMITS.items()}
        if not limits["max_action_ms"] <= limits["max_engagement_ms"] <= duration * 1000:
            _fail()
        result = {"schema_version": "1", "mode": "disconnected_owned", "scope": scope,
                  "allowed_profiles": profiles, "excluded_services": exclusions,
                  "window": dict(window), "limits": limits}
        _check_time(deadline)
        return result
    except EngagementError as exc:
        _translate(exc, "engagement_invalid_roe")


@_bounded_operation
def roe_digest(value):
    deadline = _operation_deadline()
    result = hashlib.sha256(ROE_DOMAIN + canonical(validate_roe(value))).hexdigest()
    _check_time(deadline)
    return result


@_bounded_operation
def validate_request(value):
    deadline = _operation_deadline()
    value = _bounded(value, MAX_REQUEST_BYTES)
    _object(value, _REQUEST_FIELDS)
    _literal(value["schema_version"], "1")
    engagement_id, event_id = _uuid(value["engagement_id"]), _uuid(value["event_id"])
    operation = value["operation"]
    if type(operation) is not str or operation not in {"create", "revise", "revoke"}:
        _fail()
    revision, generation = value["expected_revision"], value["expected_generation"]
    if operation == "create":
        if revision is not None or generation is not None:
            _fail()
    else:
        _integer(revision, 1, MAX_REVISIONS)
        _integer(generation, 0, MAX_REVISIONS)
    if operation == "revoke":
        if value["roe"] is not None:
            _fail()
        roe = None
    else:
        roe = validate_roe(value["roe"])
    result = {"schema_version": "1", "engagement_id": engagement_id, "event_id": event_id,
              "operation": operation, "expected_revision": revision,
              "expected_generation": generation, "roe": roe}
    _check_time(deadline)
    return result


@_bounded_operation
def request_digest(value):
    deadline = _operation_deadline()
    result = hashlib.sha256(REQUEST_DOMAIN + canonical(validate_request(value))).hexdigest()
    _check_time(deadline)
    return result


@_bounded_operation
def validate_export(value):
    """Reconstruct every request and transition; prove consistency, not freshness."""
    deadline = _operation_deadline()
    try:
        value = _bounded(value, MAX_EXPORT_BYTES)
        _object(value, {"schema_version", "kind", "engagement_id", "state", "revisions", "events"})
        _literal(value["schema_version"], "1")
        _literal(value["kind"], "engagement-record-export")
        engagement_id = _uuid(value["engagement_id"])
        revisions, events = value["revisions"], value["events"]
        if (type(revisions) is not list or not 1 <= len(revisions) <= MAX_REVISIONS
                or type(events) is not list or not 1 <= len(events) <= MAX_EVENTS):
            _fail()
        clean_revisions = []
        for index, row in enumerate(revisions, 1):
            _check_time(deadline)
            _object(row, {"revision", "roe", "roe_sha256"})
            if _integer(row["revision"], 1, MAX_REVISIONS) != index:
                _fail()
            roe = validate_roe(row["roe"])
            digest = roe_digest(roe)
            if _digest(row["roe_sha256"]) != digest:
                _fail()
            clean_revisions.append({"revision": index, "roe": roe, "roe_sha256": digest})
        clean_events = []
        seen = set()
        revision = generation = 0
        status = "recorded"
        for sequence, row in enumerate(events, 1):
            _check_time(deadline)
            _object(row, _RECEIPT_FIELDS)
            _literal(row["schema_version"], "1")
            _literal(row["engagement_id"], engagement_id)
            event_id = _uuid(row["event_id"])
            if event_id in seen or _integer(row["sequence"], 1, MAX_EVENTS) != sequence:
                _fail()
            seen.add(event_id)
            operation = row["operation"]
            if type(operation) is not str or status == "revoked":
                _fail()
            if sequence == 1:
                if operation != "create":
                    _fail()
                expected_revision = expected_generation = None
                revision, generation = 1, 0
            elif operation == "revise" and revision < MAX_REVISIONS:
                expected_revision, expected_generation = revision, generation
                revision += 1
                generation += 1
            elif operation == "revoke":
                expected_revision, expected_generation = revision, generation
                generation += 1
                status = "revoked"
            else:
                _fail()
            if revision > len(clean_revisions):
                _fail()
            revision_row = clean_revisions[revision - 1]
            # Rebuild the committed request from the immutable receipt and ROE.
            request = validate_request({
                "schema_version": "1", "engagement_id": engagement_id, "event_id": event_id,
                "operation": operation, "expected_revision": row["expected_revision"],
                "expected_generation": row["expected_generation"],
                "roe": None if operation == "revoke" else revision_row["roe"],
            })
            if (request["expected_revision"] != expected_revision
                    or request["expected_generation"] != expected_generation):
                _fail()
            # Explicit integer validation avoids True==1 and False==0 aliases.
            if (_integer(row["revision"], 1, MAX_REVISIONS) != revision
                    or _integer(row["generation"], 0, MAX_REVISIONS) != generation):
                _fail()
            _literal(row["status"], status)
            receipt = {"schema_version": "1", "engagement_id": engagement_id,
                       "event_id": event_id, "sequence": sequence, "operation": operation,
                       "expected_revision": expected_revision, "expected_generation": expected_generation,
                       "revision": revision, "generation": generation, "status": status,
                       "roe_sha256": revision_row["roe_sha256"], "request_sha256": request_digest(request)}
            if (_digest(row["roe_sha256"]) != receipt["roe_sha256"]
                    or _digest(row["request_sha256"]) != receipt["request_sha256"]):
                _fail()
            clean_events.append(receipt)
        state = _object(value["state"], {"revision", "generation", "status", "last_sequence"})
        if (_integer(state["revision"], 1, MAX_REVISIONS) != revision
                or _integer(state["generation"], 0, MAX_REVISIONS) != generation
                or _integer(state["last_sequence"], 1, MAX_EVENTS) != len(clean_events)
                or len(clean_revisions) != revision):
            _fail()
        _literal(state["status"], status)
        result = {"schema_version": "1", "kind": "engagement-record-export",
                  "engagement_id": engagement_id, "state": dict(state),
                  "revisions": clean_revisions, "events": clean_events}
        _check_time(deadline)
        return result
    except EngagementError as exc:
        _translate(exc, "engagement_invalid_export")


def _decode(raw, limit, code):
    deadline = _operation_deadline()
    if type(raw) not in (bytes, str):
        _fail(code)
    try:
        if len(raw) > limit:
            _fail("engagement_limit_exceeded")
        encoded = raw.encode("utf-8") if type(raw) is str else raw
        if len(encoded) > limit:
            _fail("engagement_limit_exceeded")
        text = encoded.decode("utf-8")
        # Reject excessive JSON container depth before json.loads recurses.
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    _fail("engagement_limit_exceeded")
            elif char in "]}":
                depth -= 1
        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    _fail(code)
                result[key] = item
            return result
        def bad_number(_):
            _fail(code)
        value = json.loads(text, object_pairs_hook=pairs, parse_float=bad_number,
                           parse_constant=bad_number)
        _tree(value, deadline)
        _check_time(deadline)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, EngagementError):
            _translate(exc, code)
        raise EngagementError(code) from None


@_bounded_operation
def decode_roe(raw):
    deadline = _operation_deadline()
    result = validate_roe(_decode(raw, MAX_ROE_BYTES, "engagement_invalid_roe"))
    _check_time(deadline)
    return result


@_bounded_operation
def decode_export(raw):
    deadline = _operation_deadline()
    value = validate_export(_decode(raw, MAX_EXPORT_BYTES, "engagement_invalid_export"))
    encoded = raw.encode("utf-8") if type(raw) is str else raw
    if canonical(value) != encoded:
        _fail("engagement_invalid_export")
    _check_time(deadline)
    return value
