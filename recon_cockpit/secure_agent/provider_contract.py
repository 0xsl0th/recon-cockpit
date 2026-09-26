"""Closed R5a contracts for an owned TLS peer and synthetic reservations.

Importing this module performs no I/O and loads no application dependencies.
The fixed peer, fake credentials and tariffs do not enable real provider calls.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


MODEL = "owned-tls-fixture-model"
HOST = "127.0.0.1"
PORT = 8443
TLS_NAME = "provider.owned.invalid"
PATH = "/v1/responses"
METHOD = "POST"
PROFILE = "owned-status-v1"
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 65536
MAX_HEADER_BYTES = 8192
MAX_OUTPUT_TOKENS = 1024
SCENARIOS = frozenset({"success", "redirect", "oversized", "untrusted_certificate", "wrong_hostname",
                       "truncated", "slow", "rate_limit", "credential_echo", "escaped_credential_echo", "malformed"})
WORKER_STATUSES = frozenset({"ok", "tls_error", "http_error", "malformed_response", "response_too_large",
                             "credential_reflection", "deadline_exceeded", "transport_error"})
BOUNDARY_NAMES = frozenset({"namespaces_private", "lab_network_shared", "forbidden_ip_blocked",
                            "forbidden_port_blocked", "namespace_creation_blocked", "process_creation_blocked",
                            "capabilities_dropped", "no_new_privs", "root_read_only", "inherited_descriptors_closed"})
RELEASE_STATUSES = frozenset({"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled", "dry_run"})
ERROR_CODES = frozenset({
    "provider_invalid_limits", "provider_invalid_tariff", "provider_invalid_observation", "provider_invalid_request",
    "provider_request_mismatch", "provider_invalid_transport", "provider_invalid_control", "provider_control_changed",
    "provider_already_running", "provider_call_limit", "provider_token_limit", "provider_request_limit",
    "provider_cost_limit", "provider_transport_failed", "provider_receipt_invalid", "provider_isolation_failed",
    "provider_cleanup_failed", "provider_audit_unavailable", "provider_tls_error", "provider_http_error",
    "provider_malformed_response", "provider_response_too_large", "provider_credential_reflection",
    "provider_deadline_exceeded", "provider_transport_error", "provider_closed",
})


class ProviderError(RuntimeError):
    """A fixed local code, never text received from a peer or OS exception."""

    def __init__(self, code):
        if type(code) is not str or code not in ERROR_CODES:
            raise ValueError("invalid_provider_error")
        self.code = code
        super().__init__(code)


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    max_calls: int = 3
    max_reserved_output_tokens: int = 3072
    max_request_bytes: int = 49152
    max_synthetic_cost_units: int = 10000000

    def __post_init__(self):
        for name, maximum in (("max_calls", 16), ("max_reserved_output_tokens", 65536),
                              ("max_request_bytes", 262144), ("max_synthetic_cost_units", 10**12)):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= maximum:
                raise ProviderError("provider_invalid_limits")


@dataclass(frozen=True, slots=True)
class SyntheticTariff:
    fixed_attempt_units: int = 100
    input_byte_units: int = 1
    output_token_units: int = 2

    def __post_init__(self):
        for value in asdict(self).values():
            if type(value) is not int or not 1 <= value <= 1000000:
                raise ProviderError("provider_invalid_tariff")

    def reserve(self, request_bytes, output_tokens=MAX_OUTPUT_TOKENS):
        if (type(request_bytes) is not int or not 1 <= request_bytes <= MAX_REQUEST_BYTES
                or type(output_tokens) is not int or output_tokens != MAX_OUTPUT_TOKENS):
            raise ProviderError("provider_invalid_request")
        return self.fixed_attempt_units + request_bytes * self.input_byte_units + output_tokens * self.output_token_units


def release_profile():
    return {"id": PROFILE, "version": "1", "step_range": [1, 16],
            "execution_statuses": sorted(RELEASE_STATUSES), "body": "always_empty",
            "initial_observation": "none", "subsequent_observation": "status_only"}


def release_observation(raw):
    """Validate the bounded source, then drop every response-body byte.

    No secret detector or heuristic redactor is used. Only a step and an exact
    status enum can leave the host in this first explicit release profile.
    """
    from .openai_protocol import _observation

    try:
        value = json.loads(_observation(raw))
        feedback = value["untrusted_observation"]
        if (value["step"] == 1) != (feedback is None):
            raise ValueError("invalid_release_phase")
        if feedback is not None:
            if feedback["execution_status"] not in RELEASE_STATUSES:
                raise ValueError("invalid_release_status")
            value["untrusted_observation"] = {"execution_status": feedback["execution_status"], "body": ""}
        return encode(value)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ProviderError("provider_invalid_observation") from None


def build_request(observation):
    from .openai_protocol import OpenAIConfig, build_request as codec_request

    return codec_request(OpenAIConfig(MODEL, MAX_OUTPUT_TOKENS), release_observation(observation))


def validate_request(raw):
    """Independently reject any fixed-codec or approved-data substitution."""
    from .openai_protocol import _decode_object

    try:
        value = _decode_object(raw, MAX_REQUEST_BYTES)
        source = value["input"][1]["content"][0]["text"]
        if type(source) is not str:
            raise ValueError("invalid_release_text")
        expected = build_request(source.encode("utf-8"))
        if raw != expected:
            raise ValueError("request_substitution")
        return raw
    except (ValueError, RuntimeError, TypeError, KeyError, IndexError, RecursionError, UnicodeError):
        raise ProviderError("provider_invalid_request") from None


def success_response():
    """Fixed synthetic protocol response; no model inference or bill exists."""
    return encode({"object": "response", "status": "completed", "error": None, "incomplete_details": None,
                   "output": [{"type": "message", "role": "assistant", "status": "completed",
                               "content": [{"type": "output_text", "text": encode({
                                   "schema_version": "1", "action": None, "done": True}).decode("ascii")}]}]})
