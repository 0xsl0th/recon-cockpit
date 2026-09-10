"""Strict, immutable messages at the untrusted planner / policy boundary.

Parsing does not authorize an action. Only a subsequent policy decision can do
that; expanding targets is deliberately bounded even outside the policy path.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID

MAX_JSON_BYTES = 32_768
MAX_TARGETS = 16
MAX_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 65_536
SUPPORTED_TOOLS = ("http_probe",)
SUPPORTED_METHODS = ("GET", "HEAD")
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ValidationError(ValueError):
    """A machine-readable rejection that never echoes untrusted input."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise ValidationError(code)


def _integer(value: Any, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(f"invalid_{name}")


def _string(value: Any, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _reject(f"invalid_{name}")
    # Reject surrogate code points, which are not valid UTF-8 text.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _reject(f"invalid_{name}")


def _fields(value: Any, names: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _reject(f"invalid_{name}")
    if set(value) - names:
        _reject(f"unknown_{name}_fields")
    if names - set(value):
        _reject(f"missing_{name}_fields")
    return value


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate_json_key")
        result[key] = value
    return result


def load_json(text: str | bytes) -> dict[str, Any]:
    """Decode a size-bounded JSON object, rejecting ambiguous JSON extensions."""
    if type(text) not in (str, bytes):
        _reject("invalid_json_type")
    try:
        raw = text.encode("utf-8") if type(text) is str else text
    except UnicodeEncodeError:
        _reject("invalid_json_encoding")
    if len(raw) > MAX_JSON_BYTES:
        _reject("json_too_large")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=lambda _: _reject("invalid_json_constant"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError("invalid_json") from exc
    if type(value) is not dict:
        _reject("invalid_json_object")
    return value


def _canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def target_network(value: str) -> Network:
    """Parse literal IP/CIDR only, without DNS or platform address shortcuts."""
    _string(value, "target", 1, 80)
    if "%" in value or value != value.strip():
        _reject("invalid_target")
    try:
        if "/" in value:
            address, prefix = value.split("/")
            if not re.fullmatch(r"0|[1-9][0-9]{0,2}", prefix):
                _reject("invalid_target")
            ipaddress.ip_address(address)
            network = ipaddress.ip_network(value, strict=True)
        else:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    except ValueError as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError("invalid_target") from exc

    # IPv6 zones and mapped addresses can make textual scope checks disagree
    # with socket destinations. Multicast/unspecified/broadcast are not hosts.
    forbidden = (
        ("0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")
        if network.version == 4
        else ("::/128", "::ffff:0:0/96", "ff00::/8", "fe80::/10")
    )
    if any(network.overlaps(ipaddress.ip_network(item)) for item in forbidden):
        _reject("unsupported_target_range")
    return network


def _canonical_target(value: str) -> str:
    network = target_network(value)
    return str(network) if "/" in value else str(network.network_address)


@dataclass(frozen=True, slots=True)
class HTTPParameters:
    port: int
    method: str
    path: str
    timeout_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _integer(self.port, "port", 1, 65_535)
        if type(self.method) is not str or self.method not in SUPPORTED_METHODS:
            _reject("unsupported_http_method")
        _string(self.path, "path", 1, 256)
        if not re.fullmatch(r"/[A-Za-z0-9/_.-]*", self.path) or "//" in self.path:
            _reject("invalid_path")
        if any(segment in (".", "..") for segment in self.path.split("/")):
            _reject("invalid_path")
        _integer(self.timeout_seconds, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Action:
    schema_version: str
    action_id: str
    tool_id: str
    target: str
    parameters: HTTPParameters
    rationale: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != "1":
            _reject("unsupported_action_schema")
        _string(self.action_id, "action_id", 36, 36)
        try:
            if str(UUID(self.action_id)) != self.action_id:
                _reject("invalid_action_id")
        except ValueError as exc:
            raise ValidationError("invalid_action_id") from exc
        if type(self.tool_id) is not str or self.tool_id not in SUPPORTED_TOOLS:
            _reject("unsupported_tool")
        object.__setattr__(self, "target", _canonical_target(self.target))
        if type(self.parameters) is not HTTPParameters:
            _reject("invalid_parameters")
        _string(self.rationale, "rationale", 0, 1_000)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def digest(self) -> str:
        return _canonical_digest(self.to_dict())

    @property
    def network(self) -> Network:
        return target_network(self.target)

    @property
    def targets(self) -> tuple[str, ...]:
        """Expand all addresses, including CIDR endpoints, with a hard ceiling."""
        network = self.network
        if network.num_addresses > MAX_TARGETS:
            _reject("too_many_targets")
        return tuple(str(address) for address in network)


@dataclass(frozen=True, slots=True)
class Decision:
    decision: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reasons": list(self.reasons)}


@dataclass(frozen=True, slots=True)
class Policy:
    schema_version: str
    policy_version: str
    allowed_targets: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_methods: tuple[str, ...]
    max_timeout_seconds: int
    max_output_bytes: int
    max_targets: int
    require_approval: bool
    approval_ttl_seconds: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != "1":
            _reject("unsupported_policy_schema")
        _string(self.policy_version, "policy_version", 1, 64)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", self.policy_version):
            _reject("invalid_policy_version")
        for name in ("allowed_targets", "allowed_tools", "allowed_ports", "allowed_methods"):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 64:
                _reject(f"invalid_{name}")
        normalized = tuple(_canonical_target(target) for target in self.allowed_targets)
        object.__setattr__(self, "allowed_targets", normalized)
        for tool in self.allowed_tools:
            if type(tool) is not str or tool not in SUPPORTED_TOOLS:
                _reject("unsupported_policy_tool")
        for port in self.allowed_ports:
            _integer(port, "policy_port", 1, 65_535)
        for method in self.allowed_methods:
            if type(method) is not str or method not in SUPPORTED_METHODS:
                _reject("unsupported_policy_method")
        for name in ("allowed_targets", "allowed_tools", "allowed_ports", "allowed_methods"):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                _reject(f"duplicate_{name}")
        _integer(self.max_timeout_seconds, "policy_timeout", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "policy_output_limit", 1, MAX_OUTPUT_BYTES)
        _integer(self.max_targets, "policy_max_targets", 1, MAX_TARGETS)
        if type(self.require_approval) is not bool:
            _reject("invalid_require_approval")
        _integer(self.approval_ttl_seconds, "approval_ttl_seconds", 1, 300)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for name in ("allowed_targets", "allowed_tools", "allowed_ports", "allowed_methods"):
            result[name] = list(result[name])
        return result

    @property
    def digest(self) -> str:
        return _canonical_digest(self.to_dict())

    def evaluate(self, action: Action) -> Decision:
        if type(action) is not Action:
            return Decision("deny", ("invalid_action",))
        reasons: list[str] = []
        if action.tool_id not in self.allowed_tools:
            reasons.append("tool_not_allowed")
        network = action.network
        allowed_networks = tuple(target_network(target) for target in self.allowed_targets)
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in allowed_networks
        ):
            reasons.append("target_out_of_scope")
        if network.num_addresses > self.max_targets:
            reasons.append("too_many_targets")
        if action.parameters.port not in self.allowed_ports:
            reasons.append("port_not_allowed")
        if action.parameters.method not in self.allowed_methods:
            reasons.append("method_not_allowed")
        if action.parameters.timeout_seconds > self.max_timeout_seconds:
            reasons.append("timeout_exceeds_policy")
        if action.parameters.max_output_bytes > self.max_output_bytes:
            reasons.append("output_limit_exceeds_policy")
        if reasons:
            return Decision("deny", tuple(reasons))
        if self.require_approval:
            return Decision("approval_required", ("human_approval_required",))
        return Decision("allow", ("policy_allows_action",))


def parse_action(value: dict[str, Any] | str | bytes) -> Action:
    if type(value) in (str, bytes):
        value = load_json(value)
    value = _fields(value, {
        "schema_version", "action_id", "tool_id", "target", "parameters", "rationale"
    }, "action")
    parameters = _fields(value["parameters"], {
        "port", "method", "path", "timeout_seconds", "max_output_bytes"
    }, "parameters")
    return Action(**{**value, "parameters": HTTPParameters(**parameters)})


def parse_policy(value: dict[str, Any] | str | bytes) -> Policy:
    if type(value) in (str, bytes):
        value = load_json(value)
    value = _fields(value, {
        "schema_version", "policy_version", "allowed_targets", "allowed_tools",
        "allowed_ports", "allowed_methods", "max_timeout_seconds", "max_output_bytes",
        "max_targets", "require_approval", "approval_ttl_seconds"
    }, "policy")
    result = value.copy()
    for name in ("allowed_targets", "allowed_tools", "allowed_ports", "allowed_methods"):
        if type(result[name]) is not list:
            _reject(f"invalid_{name}")
        result[name] = tuple(result[name])
    return Policy(**result)
