"""Narrow owned-lab lifecycle additions for the larger TLS owner receipt.

Legacy management and result limits remain unchanged. The sole larger channel
is a single original peer/mediator receipt, never tool stdout or stderr.
"""

import copy
import json
import os
import subprocess

from .isolation import IsolationUnavailable, _namespaces
from .owned_lab import encode
from .routed import _Supervisor, _pin_namespaces
from .network_tools_tls_posture_identity import validate_context
from .network_tools_tls_posture_receipt import (
    MAX_MANAGEMENT_BYTES, decode_owner_receipt, receipt_counter_context, validate_owner_selection,
    _unique, _not_number,
)


def read_message(lab):
    supervisor = lab._supervisor
    supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][lab._offset:])
    buffered = supervisor.buffers["lab_out"]
    end = buffered.index(b"\n", lab._offset) + 1
    raw = bytes(buffered[lab._offset:end])
    if len(raw) > MAX_MANAGEMENT_BYTES:
        raise IsolationUnavailable("TLS posture owner receipt exceeds its fixed bound")
    lab._offset = end
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_not_number,
                           parse_float=_not_number)
        if type(value) is not dict:
            raise ValueError("invalid_tls_posture_management_object")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise IsolationUnavailable("TLS posture owner returned invalid management evidence") from error


def start(lab, control):
    """Same pinned-namespace startup, with a T02-only finite management cap."""
    with lab._lock:
        try:
            lab._check(control)
            if lab._started:
                lab._verify_pins()
                return
            if control.remaining() > lab.limits.max_runtime_seconds:
                raise IsolationUnavailable("Owned lab deadline exceeds its fixed lifetime")
            lab._control = control
            lab._check_available()
            host = _namespaces()
            stdlib, files = lab._runtime(control)
            lab._supervisor = _Supervisor(control.remaining(), MAX_MANAGEMENT_BYTES + 8192, control=control)
            info_r, info_w = lab._supervisor.pipe()
            lab._supervisor.watch(info_r, "info")
            process = lab._supervisor.launch("lab", lab._owner_command(stdlib, files, info_w),
                                             pass_fds=(info_w,), stdin=subprocess.PIPE)
            lab._supervisor.close_fd(info_w)
            process.stdin.write(encode(lab._owner_request(host, control)) + b"\n")
            ready = lab._read_message()
            lab._supervisor.wait_for(lambda: "info" in lab._supervisor.eof)
            if (type(ready) is not dict
                    or set(ready) != {"ready", "namespaces", "witness_baselines", "connection_count", "request_count"}
                    or ready["ready"] is not True or ready["witness_baselines"] is not True
                    or type(ready["connection_count"]) is not int or ready["connection_count"] != 0
                    or type(ready["request_count"]) is not int or ready["request_count"] != 0):
                raise IsolationUnavailable("TLS posture owner readiness was not confirmed")
            lab._namespace_fds = _pin_namespaces(bytes(lab._supervisor.buffers["info"]), host)
            lab._supervisor.fds.update(lab._namespace_fds)
            metadata = json.loads(bytes(lab._supervisor.buffers["info"]))
            observed = {name: os.readlink(f"/proc/{metadata['child-pid']}/ns/{name}") for name in host}
            if ready["namespaces"] != observed or any(observed[name] == host[name] for name in host):
                raise IsolationUnavailable("TLS posture owner namespace identity was not confirmed")
            lab._lab_namespaces = observed
            lab._started = True
            lab._verify_pins()
        except BaseException:
            lab.close()
            raise


def snapshot(lab, control, *, minimum_connections=None, minimum_requests=None):
    with lab._lock:
        try:
            lab._check(control)
            if not lab._started:
                raise IsolationUnavailable("TLS posture owner has not started")
            lab._verify_pins()
            minimum_connections = lab._counts["connection_count"] if minimum_connections is None else minimum_connections
            minimum_requests = lab._counts["request_count"] if minimum_requests is None else minimum_requests
            if (type(minimum_connections) is not int or not 0 <= minimum_connections <= 2
                    or type(minimum_requests) is not int or not 0 <= minimum_requests <= 1):
                raise IsolationUnavailable("TLS posture owner counter barrier is invalid")
            if getattr(lab, "_tls_posture_snapshot", None) is None:
                if lab._sequence:
                    raise IsolationUnavailable("TLS posture owner receipt is single-use")
                lab._sequence = 1
                lab._supervisor.processes["lab"].stdin.write(encode({"sequence": 1,
                    "minimum_connections": minimum_connections, "minimum_requests": minimum_requests}) + b"\n")
                value = lab._read_message()
                if (type(value) is not dict
                        or set(value) != {"sequence", "connection_count", "request_count", "tls_posture_owner"}
                        or type(value["sequence"]) is not int or value["sequence"] != 1):
                    raise IsolationUnavailable("TLS posture owner acknowledgement is invalid")
                raw = decode_owner_receipt(value["tls_posture_owner"])
                validate_owner_selection(raw, lab.identity["scenario"])
                counters = receipt_counter_context(raw)
                if any(type(value[key]) is not int or value[key] != counters[key] for key in counters):
                    raise IsolationUnavailable("TLS posture owner receipt counters disagree")
                validate_context({"identity": lab.identity, **counters,
                    "tls_posture_owner_sha256": value["tls_posture_owner"]["sha256"]}, lab.identity)
                lab._tls_posture_snapshot = {**counters, "tls_posture_owner": copy.deepcopy(value["tls_posture_owner"])}
            result = lab._tls_posture_snapshot
            if (any(result[key] < lab._counts[key] for key in lab._counts)
                    or result["connection_count"] < minimum_connections or result["request_count"] < minimum_requests):
                raise IsolationUnavailable("TLS posture owner counters regressed or did not settle")
            lab._counts = {key: result[key] for key in lab._counts}
            lab._check(control)
            return copy.deepcopy(result)
        except BaseException:
            lab.close()
            raise
