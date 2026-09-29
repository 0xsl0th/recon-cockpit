"""Closed first-call profile. No engagement data, tools, URLs or free-form output."""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

from .cost_contract import CostError, PriceCard, TokenUsage


MODEL = "gpt-4.1-mini-2025-04-14"
INPUT_LIMIT = 1_047_576  # Entire documented context, deliberately conservative.
OUTPUT_LIMIT = 128
MAX_PACKET = 16384
CHECKS = frozenset({"namespaces_private", "witness_baselines", "forbidden_ip_blocked",
    "forbidden_port_blocked", "namespace_creation_blocked", "capabilities_dropped",
    "process_creation_blocked", "root_read_only", "no_new_privs", "descriptors_private",
    "socket_creation_blocked", "socket_reconnect_blocked"})


class PilotError(RuntimeError):
    """Only locally chosen, bounded codes may cross the operator boundary."""

    def __init__(self, code):
        if code not in {"pilot_disabled", "pilot_invalid_config", "pilot_invalid_credential",
                        "pilot_invalid_control", "pilot_reused", "pilot_transport_failed",
                        "pilot_invalid_receipt", "pilot_audit_failed", "pilot_unresolved",
                        "pilot_output_rejected", "pilot_call_cap", "pilot_mode_mismatch"}:
            code = "pilot_transport_failed"
        self.code = code
        super().__init__(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def request_bytes():
    return encode({"model": MODEL, "input": [{"role": "user", "content": [
        {"type": "input_text", "text": "Return the JSON object {\"ack\":true}."}]}],
        "max_output_tokens": OUTPUT_LIMIT, "store": False, "stream": False,
        "background": False, "tools": [], "tool_choice": "none", "truncation": "disabled",
        "service_tier": "default", "text": {"format": {"type": "json_schema",
        "name": "pilot_ack", "strict": True, "schema": {"type": "object",
        "properties": {"ack": {"type": "boolean", "enum": [True]}},
        "required": ["ack"], "additionalProperties": False}}}})


@dataclass(frozen=True)
class PilotConfig:
    """Trusted operator configuration; constructing it performs no I/O."""

    ip: str
    price: PriceCard
    max_call_microusd: int
    mode: str = "live"
    enabled: bool = False
    port: int = 443

    def __post_init__(self):
        try:
            address = ipaddress.IPv4Address(self.ip)
            if (type(self.ip) is not str or str(address) != self.ip
                    or type(self.enabled) is not bool or self.mode not in {"live", "owned"}
                    or type(self.port) is not int or not 1024 <= self.port <= 65535 and self.port != 443
                    or self.mode == "live" and (not address.is_global or address.is_multicast or self.port != 443)
                    or self.mode == "owned" and (self.ip != "127.0.0.1" or self.port < 1024)
                    or type(self.price) is not PriceCard
                    or self.price.provider != "openai" or self.price.model != MODEL
                    or min(self.price.input_microusd_per_million,
                           self.price.output_microusd_per_million) <= 0
                    or type(self.max_call_microusd) is not int or self.max_call_microusd <= 0):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise PilotError("pilot_invalid_config") from None

    @property
    def tls_name(self):
        return "api.openai.com" if self.mode == "live" else "provider.owned.invalid"

    @property
    def digest(self):
        return hashlib.sha256(encode({"profile": "synthetic-ack-v1", "ip": self.ip,
            "port": self.port, "tls_name": self.tls_name, "mode": self.mode,
            "price": self.price.digest, "max_call_microusd": self.max_call_microusd,
            "request": request_bytes().decode("ascii")})).hexdigest()


def validate_credential(value, mode):
    pattern = r"synthetic-[a-f0-9]{64}" if mode == "owned" else r"sk-[A-Za-z0-9_-]{16,500}"
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise PilotError("pilot_invalid_credential")
    return value


def response_summary(value):
    """Extract final priced usage independently of whether the ACK is valid.

    Unknown billing dimensions retain the hold. Raw output and provider IDs never
    escape; the ID is hashed for receipt deduplication, not treated as authority.
    """
    usage = None
    reference = None
    try:
        if (value.get("object") != "response" or value.get("model") != MODEL
                or value.get("status") not in {"completed", "incomplete"}
                or value.get("service_tier") != "default"
                or type(value.get("id")) is not str
                or re.fullmatch(r"resp_[A-Za-z0-9_-]{1,120}", value["id"]) is None):
            raise ValueError
        data = value["usage"]
        if type(data) is not dict or set(data) != {"input_tokens", "output_tokens", "total_tokens",
                                                 "input_tokens_details", "output_tokens_details"}:
            raise ValueError
        inputs, outputs = data["input_tokens_details"], data["output_tokens_details"]
        if (type(inputs) is not dict or set(inputs) not in ({"cached_tokens"}, {"cached_tokens", "cache_write_tokens"})
                or "cache_write_tokens" in inputs and (type(inputs["cache_write_tokens"]) is not int or inputs["cache_write_tokens"] != 0)
                or type(outputs) is not dict or set(outputs) != {"reasoning_tokens"}
                or type(outputs["reasoning_tokens"]) is not int or outputs["reasoning_tokens"] != 0):
            raise ValueError
        candidate = TokenUsage(data["input_tokens"], data["output_tokens"], inputs["cached_tokens"])
        if (type(data["total_tokens"]) is not int or data["total_tokens"] != candidate.input_tokens + candidate.output_tokens):
            raise ValueError
        usage = {"input_tokens": candidate.input_tokens, "output_tokens": candidate.output_tokens,
                 "cached_input_tokens": candidate.cached_input_tokens}
        reference = "response-" + hashlib.sha256(value["id"].encode("ascii")).hexdigest()
    except (CostError, ValueError, TypeError, KeyError, AttributeError):
        pass
    accepted = False
    try:
        output = value["output"]
        message = output[0]
        content = message["content"]
        # Exactly one completed assistant message containing the fixed ACK.
        if (usage is not None and value["status"] == "completed" and len(output) == 1
                and message["type"] == "message" and message["role"] == "assistant"
                and message["status"] == "completed" and len(content) == 1
                and content[0]["type"] == "output_text"
                and content[0]["text"].strip() in {'{"ack":true}', '{"ack": true}'}):
            accepted = True
    except (TypeError, KeyError, IndexError, AttributeError):
        pass
    return {"accepted": accepted, "usage": usage, "reference": reference}
