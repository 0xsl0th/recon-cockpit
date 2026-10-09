"""Bounded networkless HTTP parsing for execution and independent replay."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

from .execution import ExecutionControl
from .http_headers_parser import MAX_RESPONSE_BYTES, PARSER_VERSION, validate_result
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .planner_worker import BOUNDARY_NAMES


def _command(bootstrap):
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    for name in ("http_headers_parser", "http_headers_parser_worker", "planner_worker"):
        argv += ["--ro-bind", str(Path(__file__).with_name(name + ".py")), "/app/" + name + ".py"]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/http_headers_parser_worker.py", *_namespaces().values()]
    return argv


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_http_headers_parser_reply")
        result[key] = value
    return result


def _parse_isolated(raw, control, bootstrap):
    control.check()
    code, stdout, _, reason = _capture_bounded(
        _command(bootstrap), raw, min(2, control.remaining()), 1024, control=control)
    if code != 0 or reason is not None:
        raise IsolationUnavailable("HTTP headers parser isolation unavailable")
    try:
        value = json.loads(stdout, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {"profile", "boundary_checks", "status", "result"}
                or value["profile"] != PARSER_VERSION
                or type(value["boundary_checks"]) is not dict
                or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_http_headers_parser_reply")
        if value["status"] == "parsed":
            return validate_result(value["result"])
        if value["result"] is not None:
            raise ValueError("invalid_http_headers_parser_reply")
    except (ValueError, TypeError, RecursionError):
        raise IsolationUnavailable("HTTP headers parser reply invalid") from None
    raise ValueError("invalid_http_headers_response")


def parse_isolated_headers(raw: bytes, *, truncated=False, deadline=None, control=None, closure=None) -> dict:
    """Parse once under the inherited deadline/cancellation or a ten-second cap.

    A trusted pre-inspected closure allows execution inside the launcher without
    host runtime discovery. No closure is accepted from a tool response. The
    parser itself still verifies every namespace, syscall and filesystem check.
    """
    if (type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_http_headers_size")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("HTTP headers parsing requires unprivileged Linux isolation")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_http_headers_control")
    clock = time.monotonic if control is None else control.clock
    limits = [clock() + 10]
    if control is not None:
        control.check()
        limits.append(control.deadline)
    if deadline is not None:
        ExecutionControl(deadline, clock=clock).check()
        limits.append(deadline)
    bounded = ExecutionControl(min(limits), None if control is None else control.cancelled, clock)
    bounded.check()
    if closure is None:
        bootstrap = _runtime_files("/usr/bin/python3", None, control=bounded)
    else:
        if (type(closure) is not dict or type(closure.get("stdlib")) is not str
                or not closure["stdlib"].startswith("/") or type(closure.get("files")) is not list
                or not closure["files"] or any(type(path) is not str or not path.startswith("/")
                                               for path in closure["files"])):
            raise IsolationUnavailable("HTTP headers parser runtime closure invalid")
        bootstrap = closure["stdlib"], [(path, path) for path in closure["files"]]
    return _parse_isolated(raw, bounded, bootstrap)


# The replay spelling is intentionally the same implementation and boundary.
parse_isolated_response = parse_isolated_headers
