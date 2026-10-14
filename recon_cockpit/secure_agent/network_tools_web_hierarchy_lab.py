"""Single bounded hierarchy-owner acknowledgement, separate from authority."""

import copy
import json

from .isolation import IsolationUnavailable
from .owned_lab import encode
from .network_tools_web_hierarchy_identity import validate_context
from .network_tools_web_hierarchy_receipt import (
    MAX_MANAGEMENT_BYTES, MAX_CONNECTIONS, encode_owner_receipt, validate_owner_selection,
    _unique, _not_number,
)


def read_message(lab):
    supervisor = lab._supervisor
    supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][lab._offset:])
    buffered = supervisor.buffers["lab_out"]
    end = buffered.index(b"\n", lab._offset) + 1
    raw = bytes(buffered[lab._offset:end])
    if len(raw) > MAX_MANAGEMENT_BYTES:
        raise IsolationUnavailable("Web hierarchy owner receipt exceeds its fixed bound")
    lab._offset = end
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_not_number,
                           parse_float=_not_number)
        if type(value) is not dict:
            raise ValueError("invalid_web_hierarchy_management_object")
        lab._web_hierarchy_management_raw = raw
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise IsolationUnavailable("Web hierarchy owner returned invalid management evidence") from error


def snapshot(lab, control, *, minimum_connections=None, minimum_requests=None):
    with lab._lock:
        try:
            lab._check(control)
            if not lab._started:
                raise IsolationUnavailable("Web hierarchy owner has not started")
            lab._verify_pins()
            minimum_connections = lab._counts["connection_count"] if minimum_connections is None else minimum_connections
            minimum_requests = lab._counts["request_count"] if minimum_requests is None else minimum_requests
            if any(type(value) is not int or not 0 <= value <= MAX_CONNECTIONS
                   for value in (minimum_connections, minimum_requests)):
                raise IsolationUnavailable("Web hierarchy owner counter barrier is invalid")
            if getattr(lab, "_web_hierarchy_snapshot", None) is None:
                if lab._sequence:
                    raise IsolationUnavailable("Web hierarchy owner receipt is single-use")
                lab._sequence = 1
                lab._supervisor.processes["lab"].stdin.write(encode({"sequence": 1,
                    "minimum_connections": minimum_connections, "minimum_requests": minimum_requests}) + b"\n")
                value = lab._read_message()
                raw = getattr(lab, "_web_hierarchy_management_raw", None)
                parsed = validate_owner_selection(raw, lab.identity["scenario"])
                if value != parsed:
                    raise IsolationUnavailable("Web hierarchy owner acknowledgement disagrees with original bytes")
                counters = {key: parsed[key] for key in ("connection_count", "request_count")}
                envelope = encode_owner_receipt(raw)
                validate_context({"identity": lab.identity, **counters,
                    "web_hierarchy_owner_sha256": envelope["sha256"]}, lab.identity)
                lab._web_hierarchy_snapshot = {**counters, "web_hierarchy_owner": envelope}
            result = lab._web_hierarchy_snapshot
            if (any(result[key] < lab._counts[key] for key in lab._counts)
                    or result["connection_count"] < minimum_connections or result["request_count"] < minimum_requests):
                raise IsolationUnavailable("Web hierarchy owner counters regressed or did not settle")
            lab._counts = {key: result[key] for key in lab._counts}
            lab._check(control)
            return copy.deepcopy(result)
        except BaseException:
            lab.close()
            raise
