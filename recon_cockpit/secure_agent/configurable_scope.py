"""Closed operator scope for a disconnected, owned HTTP/SSH assessment.

This document selects literal fixture endpoints; it does not authorize access to
an existing network. Capability, approval and session limits remain separate
authority decisions. Validators return detached JSON data, never caller aliases.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

MAX_SCOPE_BYTES = 4096
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
_WITNESS_TARGETS = ("10.255.255.254", "172.31.255.254", "192.168.255.254")


def _target(value):
    if type(value) is not str:
        raise ValueError("invalid_configurable_scope_target")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError("invalid_configurable_scope_target") from None
    if str(address) != value or not any(address in network for network in _PRIVATE_NETWORKS):
        raise ValueError("invalid_configurable_scope_target")
    return value


def _endpoint(value, name):
    fields = {"target", "port", "path"} if name == "http" else {"target", "port"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid_configurable_scope_endpoint")
    target = _target(value["target"])
    port = value["port"]
    if type(port) is not int or not 1024 <= port <= 65534:
        raise ValueError("invalid_configurable_scope_port")
    result = {"target": target, "port": port}
    if name == "http":
        path = value["path"]
        if (type(path) is not str or not 1 <= len(path) <= 128
                or re.fullmatch(r"/[A-Za-z0-9._~/-]*", path) is None
                or "//" in path or any(part in {".", ".."} for part in path.split("/"))):
            raise ValueError("invalid_configurable_scope_path")
        result["path"] = path
    return result


def validate_scope(value):
    """Return a detached scope after exact field, type and endpoint validation.

    Scope IDs are lowercase ASCII words/digits separated by single hyphens.
    HTTP paths contain only slash and URI-unreserved ASCII characters, without
    empty interior segments, dot segments or URL-encoded alternatives.
    """
    if (type(value) is not dict or set(value) != {"schema_version", "scope_id", "http", "ssh"}
            or type(value["schema_version"]) is not str or value["schema_version"] != "1"):
        raise ValueError("invalid_configurable_scope")
    scope_id = value["scope_id"]
    if (type(scope_id) is not str or not 1 <= len(scope_id) <= 48
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", scope_id) is None):
        raise ValueError("invalid_configurable_scope_id")
    http = _endpoint(value["http"], "http")
    ssh = _endpoint(value["ssh"], "ssh")
    if (http["target"], http["port"]) == (ssh["target"], ssh["port"]):
        raise ValueError("configurable_scope_endpoints_collide")
    return {"schema_version": "1", "scope_id": scope_id, "http": http, "ssh": ssh}


def load_scope(raw):
    """Parse a bounded JSON string/bytes object; perform no filesystem I/O."""
    from .models import load_json

    if type(raw) not in (str, bytes):
        raise ValueError("invalid_configurable_scope_json")
    try:
        encoded = raw.encode("utf-8") if type(raw) is str else raw
    except UnicodeEncodeError:
        raise ValueError("invalid_configurable_scope_json") from None
    if len(encoded) > MAX_SCOPE_BYTES:
        raise ValueError("configurable_scope_json_limit")
    return validate_scope(load_json(encoded))


def encode(value):
    """Canonical bytes bind every validated operator-controlled scope field."""
    return json.dumps(validate_scope(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def scope_digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def endpoint(value, name):
    if type(name) is not str or name not in {"http", "ssh"}:
        raise ValueError("invalid_configurable_scope_service")
    return validate_scope(value)[name]


def witness_addresses(value, name):
    """Return other-service, wrong-IP and wrong-port pairs, all distinct.

    These addresses are only for owned witnesses in the disconnected namespace.
    The other declared service is deliberately forbidden to this single-action
    executor even though it belongs to the overall assessment scope.
    """
    scope = validate_scope(value)
    current = endpoint(scope, name)
    other = scope["ssh" if name == "http" else "http"]
    targets = {scope["http"]["target"], scope["ssh"]["target"]}
    wrong_ip = next(target for target in _WITNESS_TARGETS if target not in targets)
    ports = {scope["http"]["port"], scope["ssh"]["port"]}
    next_port = current["port"] + 1 if current["port"] < 65534 else 1024
    wrong_port = next(port for port in (next_port, 1024, 1025, 1026) if port not in ports)
    return ((other["target"], other["port"]), (wrong_ip, current["port"]),
            (current["target"], wrong_port))
