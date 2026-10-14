"""Bounded production corroboration of ffuf rows and independent owner bytes."""

import hashlib
import json
import re

from . import web_hierarchy_observation as diagnostic
from .network_tools_web_hierarchy_spec import TOOL_ID, PARSER_VERSION, MAX_OWNER_BYTES, CASE_PARTS
from .web_hierarchy_spec import PATHS, MAX_WIRE_BYTES

MAX_OUTPUT_BYTES = 8192
MAX_RESULT_BYTES = 4096
MAX_INPUT_BYTES = MAX_OWNER_BYTES + MAX_OUTPUT_BYTES + 1028
# The pinned ffuf -s/-json recipe still clears its progress line per result.
# Preserve these original bytes in the commitment; accept no other stderr.
_FFUF_CLEAR_LINE = b"\r\x1b[2K"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_web_hierarchy_field")
        value[key] = item
    return value


def _not_number(_):
    raise ValueError("invalid_web_hierarchy_number")


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_result(tool_id, value):
    keys = {"parser_version", "kind", "tool_id", "outcome", "useful_task_completed",
            "owner_sha256", "stdout_sha256", "stderr_sha256", "rows", "prefixes"}
    if (type(tool_id) is not str or tool_id != TOOL_ID or type(value) is not dict
            or set(value) != keys or value["tool_id"] != tool_id
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "web_hierarchy"
            or type(value["useful_task_completed"]) is not bool
            or any(not _digest(value[key]) for key in ("owner_sha256", "stdout_sha256", "stderr_sha256"))
            or type(value["rows"]) is not list or len(value["rows"]) != len(PATHS)
            or type(value["prefixes"]) is not list):
        raise ValueError("invalid_web_hierarchy_result")
    facts = []
    for path, row in zip(PATHS, value["rows"], strict=True):
        if (type(row) is not dict or set(row) != {"path", "status_code", "bytes", "classification"}
                or row["path"] != path or type(row["status_code"]) is not int
                or not 200 <= row["status_code"] <= 599 or type(row["bytes"]) is not int
                or not 0 <= row["bytes"] <= MAX_WIRE_BYTES):
            raise ValueError("invalid_web_hierarchy_row")
        facts.append({key: row[key] for key in ("path", "status_code", "bytes")})
    rows, prefixes, outcome = diagnostic._conclusions(facts)
    if (value["rows"] != rows or value["prefixes"] != prefixes or value["outcome"] != outcome
            or value["useful_task_completed"] != (outcome != "ambiguous")
            or len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")) > MAX_RESULT_BYTES):
        raise ValueError("inconsistent_web_hierarchy_conclusions")
    return value


def encode_input(tool_id, stdout, stderr, *, owner_raw, exit_code, stop_reason, truncated):
    """Frame bytes without interpreting raw client or owner JSON on the host."""
    if (type(tool_id) is not str or tool_id != TOOL_ID
            or type(stdout) is not bytes or type(stderr) is not bytes
            or not 0 < len(stdout) + len(stderr) <= MAX_OUTPUT_BYTES
            or type(owner_raw) is not bytes or not 0 < len(owner_raw) <= MAX_OWNER_BYTES
            or type(exit_code) is not int or not -255 <= exit_code <= 255
            or stop_reason not in (None, "timeout", "output_limit") or type(truncated) is not bool):
        raise ValueError("invalid_web_hierarchy_parser_input")
    header = json.dumps({"tool_id": tool_id, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
        "exit_code": exit_code, "stop_reason": stop_reason, "truncated": truncated},
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return len(header).to_bytes(4, "big") + header + stdout + stderr + owner_raw


def parse_input(raw):
    if type(raw) is not bytes or not 4 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError("invalid_web_hierarchy_parser_input")
    size = int.from_bytes(raw[:4], "big")
    if not 1 <= size <= 1024 or len(raw) < size + 4:
        raise ValueError("invalid_web_hierarchy_parser_header")
    try:
        value = json.loads(raw[4:4 + size].decode("ascii"), object_pairs_hook=_unique,
                           parse_constant=_not_number, parse_float=_not_number)
        if (type(value) is not dict or set(value) != {"tool_id", "stdout_bytes", "stderr_bytes",
                "exit_code", "stop_reason", "truncated"} or value["tool_id"] != TOOL_ID
                or any(type(value[key]) is not int or not 0 <= value[key] <= MAX_OUTPUT_BYTES
                       for key in ("stdout_bytes", "stderr_bytes"))):
            raise ValueError("invalid_web_hierarchy_parser_header")
        start = 4 + size
        output_size, error_size = value["stdout_bytes"], value["stderr_bytes"]
        owner_start = start + output_size + error_size
        stdout, stderr, owner_raw = raw[start:start + output_size], raw[start + output_size:owner_start], raw[owner_start:]
        if (not 0 < output_size + error_size <= MAX_OUTPUT_BYTES
                or len(stdout) != output_size or len(stderr) != error_size
                or stderr not in {_FFUF_CLEAR_LINE * count for count in range(len(PATHS) + 1)}
                or type(value["exit_code"]) is not int or value["exit_code"] != 0
                or value["stop_reason"] is not None or value["truncated"] is not False
                or not 0 < len(owner_raw) <= MAX_OWNER_BYTES):
            raise ValueError("incomplete_web_hierarchy_execution")
        owner = json.loads(owner_raw.decode("ascii"), object_pairs_hook=_unique,
                           parse_constant=_not_number, parse_float=_not_number)
        if (type(owner) is not dict
                or set(owner) != {"sequence", "connection_count", "request_count", "diagnostic"}
                or type(owner["sequence"]) is not int or owner["sequence"] != 1
                or type(owner["diagnostic"]) is not dict
                or type(owner["diagnostic"].get("case")) is not str
                or owner["diagnostic"]["case"] not in CASE_PARTS.values()
                or not owner_raw.endswith(b"\n")):
            raise ValueError("invalid_web_hierarchy_owner")
        from .network_tools_web_hierarchy_receipt import validate_owner_selection
        validate_owner_selection(owner_raw, "web-hierarchy-" + owner["diagnostic"]["case"])
        assessed = diagnostic.assess(stdout, {key: item for key, item in owner.items() if key != "sequence"},
            exit_code=value["exit_code"], stop_reason=value["stop_reason"], truncated=value["truncated"])
    except (TypeError, KeyError, RecursionError, UnicodeError) as error:
        raise ValueError("invalid_web_hierarchy_parser_input") from error
    if assessed["outcome"] == "inconclusive":
        raise ValueError("inconclusive_web_hierarchy_evidence")
    return validate_result(TOOL_ID, {"parser_version": PARSER_VERSION, "kind": "web_hierarchy",
        "tool_id": TOOL_ID, "outcome": assessed["outcome"],
        "useful_task_completed": assessed["useful_completion"],
        "owner_sha256": hashlib.sha256(owner_raw).hexdigest(),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "rows": assessed["rows"], "prefixes": assessed["prefixes"]})


def parse(tool_id, stdout, stderr, *, owner_raw, exit_code, stop_reason, truncated):
    """Pure portable entrypoint; production callers use the isolated runtime."""
    return parse_input(encode_input(tool_id, stdout, stderr, owner_raw=owner_raw,
        exit_code=exit_code, stop_reason=stop_reason, truncated=truncated))
