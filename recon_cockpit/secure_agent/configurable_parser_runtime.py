"""Networkless bounded endpoint-aware parsing for capture and later replay."""

import base64
import json
import os
from pathlib import Path
import sys
import time

from .configurable_parser import MAX_OUTPUT_BYTES, parser_version, validate_result, _selected
from .configurable_scope import validate_scope
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .models import load_json
from .planner_worker import BOUNDARY_NAMES

MODULES = ("configurable_parser", "configurable_parser_worker", "configurable_scope", "models",
           "tool_parameters", "tool_adapters", "network_tools_parser", "network_tools_nmap_parser",
           "http_headers_parser", "planner_worker")


def _command(tool_id, bootstrap):
    parser_version(tool_id)
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    forbidden = {"nft", "bwrap", "nsenter", "ip", "curl", "ffuf", "dig", "openssl", "ssh-keyscan",
                 "ldapsearch", "smbclient", "rpcinfo", "showmount", "nmap", "kerbrute"}
    for source, destination in files:
        if Path(destination).name not in forbidden:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/", "/usr/bin/python3", "-I", "-S",
             "/app/recon_cockpit/secure_agent/configurable_parser_worker.py", tool_id, *_namespaces().values()]
    return argv


def parse_isolated_tool_output(tool_id, raw, stderr=b"", *, scope, endpoint_id, truncated=False,
                               deadline=None, control=None, closure=None):
    version = parser_version(tool_id)
    scope = validate_scope(scope)
    _selected(tool_id, scope, endpoint_id)
    if (type(raw) is not bytes or type(stderr) is not bytes or not (raw or stderr)
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_configurable_output_size")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("Configurable parsing requires unprivileged Linux isolation")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_configurable_parser_control")
    clock = time.monotonic if control is None else control.clock
    bounds = [clock() + 10]
    if control is not None:
        control.check()
        bounds.append(control.deadline)
    if deadline is not None:
        ExecutionControl(deadline, clock=clock).check()
        bounds.append(deadline)
    bounded = ExecutionControl(min(bounds), None if control is None else control.cancelled, clock)
    bounded.check()
    if closure is None:
        bootstrap = _runtime_files("/usr/bin/python3", None, control=bounded)
    else:
        if (type(closure) is not dict or type(closure.get("stdlib")) is not str
                or not closure["stdlib"].startswith("/") or type(closure.get("files")) is not list
                or not closure["files"] or any(type(path) is not str or not path.startswith("/") for path in closure["files"])):
            raise IsolationUnavailable("Configurable parser runtime closure invalid")
        bootstrap = closure["stdlib"], [(path, path) for path in closure["files"]]
    payload = json.dumps({"scope": scope, "endpoint_id": endpoint_id,
        "raw": base64.b64encode(raw).decode("ascii"), "stderr": base64.b64encode(stderr).decode("ascii")},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    code, stdout, _, reason = _capture_bounded(_command(tool_id, bootstrap), payload,
        min(2, bounded.remaining()), 4096, control=bounded)
    if code != 0 or reason is not None:
        raise IsolationUnavailable("Configurable parser isolation unavailable")
    try:
        value = load_json(stdout)
        if (set(value) != {"profile", "tool_id", "boundary_checks", "status", "result"}
                or value["profile"] != version or value["tool_id"] != tool_id
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_configurable_parser_reply")
        if value["status"] == "parsed":
            return validate_result(tool_id, value["result"], scope, endpoint_id)
        if value["result"] is not None:
            raise ValueError("invalid_configurable_parser_reply")
    except (ValueError, TypeError, RecursionError):
        raise IsolationUnavailable("Configurable parser reply invalid") from None
    raise ValueError("invalid_configurable_tool_output")


parse_isolated_tool = parse_isolated_tool_output
