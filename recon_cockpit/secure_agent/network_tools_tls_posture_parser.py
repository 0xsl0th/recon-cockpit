"""Finite TLS client/peer corroboration, separate from execution authority."""

import base64
import hashlib
import json
import re

from .network_tools_tls_posture_spec import TOOL_VERSIONS, PARSER_VERSION, MAX_OWNER_BYTES
from .tls_posture_observation_contract import _object, _integer, _peer, _mediation, _unique, _not_number
from .tls_posture_mediated_trace import analyze_mediated_wire
from . import tls_posture_diagnostic_trace as wire_trace

MAX_OUTPUT_BYTES = 8192
MAX_RESULT_BYTES = 4096
MAX_INPUT_BYTES = MAX_OWNER_BYTES + 32768
_OUTCOMES = {"handshake_completed": (True, False), "explicit_protocol_rejection": (True, False),
             "extra_client_hello_prevented": (False, True)}


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_result(tool_id, value):
    keys = {"parser_version", "kind", "tool_id", "tls_version", "fixture_variant", "outcome", "useful_task_completed",
            "extra_client_hello_prevented", "owner_sha256", "stdout_sha256", "stderr_sha256",
            "client_ingress_bytes", "client_forwarded_bytes", "peer_client_hellos"}
    if (type(tool_id) is not str or tool_id not in TOOL_VERSIONS or type(value) is not dict
            or set(value) != keys or value["tool_id"] != tool_id or value["kind"] != "tls_posture"
            or value["parser_version"] != PARSER_VERSION or value["tls_version"] != TOOL_VERSIONS[tool_id]
            or type(value["fixture_variant"]) is not str or value["fixture_variant"] not in {"modern", "legacy", "reject", "hrr"}
            or (value["fixture_variant"] == "hrr") != (value["outcome"] == "extra_client_hello_prevented")
            or type(value["outcome"]) is not str or value["outcome"] not in _OUTCOMES
            or type(value["useful_task_completed"]) is not bool
            or type(value["extra_client_hello_prevented"]) is not bool
            or (value["useful_task_completed"], value["extra_client_hello_prevented"]) != _OUTCOMES[value["outcome"]]
            or any(not _digest(value[k]) for k in ("owner_sha256", "stdout_sha256", "stderr_sha256"))):
        raise ValueError("invalid_tls_posture_result")
    for key in ("client_ingress_bytes", "client_forwarded_bytes", "peer_client_hellos"):
        if type(value[key]) is not int:
            raise ValueError("invalid_tls_posture_counter")
    ingress, forwarded = value["client_ingress_bytes"], value["client_forwarded_bytes"]
    if (value["peer_client_hellos"] != 1 or not 6 <= forwarded <= ingress <= MAX_OUTPUT_BYTES
            or value["useful_task_completed"] and ingress != forwarded
            or value["extra_client_hello_prevented"] and (ingress == forwarded or value["tls_version"] != "tls1_3")):
        raise ValueError("invalid_tls_posture_progress")
    return value


def encode_input(tool_id, stdout, stderr, *, owner_raw, exit_code, stop_reason, truncated):
    """Frame original owner bytes without interpreting untrusted JSON on host."""
    if (type(tool_id) is not str or tool_id not in TOOL_VERSIONS
            or type(stdout) is not bytes or type(stderr) is not bytes
            or not 0 < len(stdout) + len(stderr) <= MAX_OUTPUT_BYTES
            or type(owner_raw) is not bytes or not 0 < len(owner_raw) <= MAX_OWNER_BYTES
            or type(exit_code) is not int or not -255 <= exit_code <= 255
            or stop_reason not in (None, "timeout", "output_limit") or type(truncated) is not bool):
        raise ValueError("invalid_tls_posture_input")
    value = {"tool_id": tool_id, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
             "exit_code": exit_code, "stop_reason": stop_reason, "truncated": truncated}
    header = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return len(header).to_bytes(4, "big") + header + stdout + stderr + owner_raw


def parse_input(raw):
    if type(raw) is not bytes or not 4 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError("invalid_tls_posture_input")
    size = int.from_bytes(raw[:4], "big")
    if not 1 <= size <= 1024 or len(raw) < size + 4:
        raise ValueError("invalid_tls_posture_header")
    value = json.loads(raw[4:4 + size].decode("ascii"), object_pairs_hook=_unique,
                       parse_constant=_not_number, parse_float=_not_number)
    _object(value, {"tool_id", "stdout_bytes", "stderr_bytes", "exit_code", "stop_reason", "truncated"})
    tool_id = value["tool_id"]
    if type(tool_id) is not str or tool_id not in TOOL_VERSIONS:
        raise ValueError("invalid_tls_posture_tool")
    for key in ("stdout_bytes", "stderr_bytes"):
        _integer(value[key], 0, MAX_OUTPUT_BYTES)
    output_size, error_size = value["stdout_bytes"], value["stderr_bytes"]
    start = 4 + size
    owner_start = start + output_size + error_size
    stdout, stderr = raw[start:start + output_size], raw[start + output_size:owner_start]
    owner_raw = raw[owner_start:]
    if not 0 < len(owner_raw) <= MAX_OWNER_BYTES:
        raise ValueError("invalid_tls_posture_owner_size")
    owner_digest = hashlib.sha256(owner_raw).hexdigest()
    value["owner"] = json.loads(owner_raw.decode("utf-8"), object_pairs_hook=_unique,
                               parse_constant=_not_number, parse_float=_not_number)
    # Validate actual captured process fields before interpreting transcript data.
    if (not 0 < len(stdout) + len(stderr) <= MAX_OUTPUT_BYTES
            or type(value["exit_code"]) is not int or value["exit_code"] not in (0, 1)
            or value["stop_reason"] is not None or value["truncated"] is not False):
        raise ValueError("incomplete_tls_posture_execution")
    owner = _object(value["owner"], {"connection_count", "request_count", "diagnostic", "mediation"})
    for key in ("connection_count", "request_count"):
        _integer(owner[key], 1, 1)
    _peer(owner["diagnostic"])
    _mediation(owner["mediation"])
    execution = {"exit_code": value["exit_code"], "stop_reason": value["stop_reason"],
                 "truncated": value["truncated"], "raw_stdout_base64": base64.b64encode(stdout).decode("ascii"),
                 "raw_stderr_base64": base64.b64encode(stderr).decode("ascii")}
    version, case = TOOL_VERSIONS[tool_id], owner["diagnostic"]["case"]
    if case == "hrr":
        # HRR closes locally with decode_error/EOF rather than a peer rejection.
        # Unknown text remains inert and cannot acquire a safety verdict either.
        for stream in (stdout, stderr):
            _, lines = wire_trace._messages(stream)
            if any(not (wire_trace._known_text(line, True, version)
                    or line == "SSL3 alert write:fatal:decode error"
                    or re.fullmatch(r"[0-9A-Fa-f]+:error:[0-9A-Fa-f]+:SSL routines::unexpected eof while reading:[A-Za-z0-9_./-]+:[0-9]+:", line))
                   for line in lines):
                raise ValueError("unknown_tls_posture_retry_output")
    finding = analyze_mediated_wire(version, case, execution, owner)
    if finding["issues"] or finding["outcome"] not in _OUTCOMES:
        raise ValueError("inconclusive_tls_posture_wire")
    result = {"parser_version": PARSER_VERSION, "kind": "tls_posture", "tool_id": tool_id,
              "tls_version": version, "fixture_variant": case, "outcome": finding["outcome"],
              "useful_task_completed": finding["useful_task_completed"],
              "extra_client_hello_prevented": finding["extra_client_hello_prevented"],
              "owner_sha256": owner_digest, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
              "client_ingress_bytes": owner["mediation"]["client_ingress_bytes"],
              "client_forwarded_bytes": owner["mediation"]["client_forwarded_bytes"],
              "peer_client_hellos": owner["diagnostic"]["client_hellos"]}
    return validate_result(tool_id, result)
