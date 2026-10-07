"""Networkless bounded parsing of retained fixed-profile network-tool output for capture/replay."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .planner_worker import BOUNDARY_NAMES
from .network_tools_parser import MAX_OUTPUT_BYTES, parser_version, validate_result


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_parser_reply_key")
        value[key] = item
    return value


def _command(tool_id, bootstrap):
    parser_version(tool_id)
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in {"nft", "bwrap", "nsenter", "curl", "ffuf", "dig", "openssl", "ssh-keyscan", "ldapsearch", "smbclient", "rpcinfo", "showmount", "nmap", "kerbrute", "redis-cli", "snmpget", "ruby3.3", "ruby", "whatweb"}:
            argv += ["--ro-bind", source, destination]
    for name in ("network_tools_parser", "network_tools_nmap_parser", "network_tools_kerberos_parser", "network_tools_redis_snmp_parser", "network_tools_whatweb_parser", "network_tools_dns_srv_parser", "network_tools_parser_worker", "planner_worker"):
        argv += ["--ro-bind", str(Path(__file__).with_name(name + ".py")), "/app/" + name + ".py"]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/network_tools_parser_worker.py", tool_id, *_namespaces().values()]
    return argv


def _parse_isolated(tool_id, raw, stderr, control, bootstrap):
    version = parser_version(tool_id)
    control.check()
    code, stdout, _, reason = _capture_bounded(
        _command(tool_id, bootstrap), len(raw).to_bytes(4, "big") + raw + stderr, min(2, control.remaining()), 4096, control=control)
    if code != 0 or reason is not None:
        raise IsolationUnavailable("Network tool parser isolation unavailable")
    try:
        value = json.loads(stdout, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {"profile", "tool_id", "boundary_checks", "status", "result"}
                or value["profile"] != version or value["tool_id"] != tool_id
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_network_tool_parser_reply")
        if value["status"] == "parsed":
            return validate_result(tool_id, value["result"])
        if value["result"] is not None:
            raise ValueError("invalid_network_tool_parser_reply")
    except (ValueError, TypeError, RecursionError):
        raise IsolationUnavailable("Network tool parser reply invalid") from None
    raise ValueError("invalid_network_tool_output")


def parse_isolated_tool_output(tool_id, raw: bytes, stderr: bytes = b"", *, truncated=False, deadline=None, control=None, closure=None):
    parser_version(tool_id)
    if (type(raw) is not bytes or type(stderr) is not bytes or not (raw or stderr)
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_network_tool_output_size")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("Network tool parsing requires unprivileged Linux isolation")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_network_tool_parser_control")
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
            raise IsolationUnavailable("Network tool parser runtime closure invalid")
        bootstrap = closure["stdlib"], [(path, path) for path in closure["files"]]
    return _parse_isolated(tool_id, raw, stderr, bounded, bootstrap)


parse_isolated_tool = parse_isolated_tool_output
