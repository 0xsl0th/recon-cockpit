"""Exact USD accounting contracts; no bundled prices or provider transport."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


MICROUSD_PER_USD = 1_000_000
MAX_AMOUNT = 10**15
MAX_TOKENS = 10**9


class CostError(RuntimeError):
    """Local accounting failure with a fixed, safe message."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def identifier(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", value) is None:
        raise CostError("cost_invalid_identifier")
    return value


def integer(value, maximum=MAX_AMOUNT):
    if type(value) is not int or not 0 <= value <= maximum:
        raise CostError("cost_invalid_amount")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Input includes cached input; output includes all billable output tokens."""

    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0

    def __post_init__(self):
        for value in asdict(self).values():
            integer(value, MAX_TOKENS)
        if self.cached_input_tokens > self.input_tokens:
            raise CostError("cost_invalid_usage")


@dataclass(frozen=True, slots=True)
class PriceCard:
    """Operator-supplied immutable prices, in microUSD per million tokens.

    The version identifies the source/date of the approved pricing. The fixed
    charge supports per-request fees. Unsupported charge categories must be
    rejected by the future provider adapter, not silently priced as zero.
    """

    provider: str
    model: str
    version: str
    input_microusd_per_million: int
    cached_input_microusd_per_million: int
    output_microusd_per_million: int
    request_microusd: int = 0
    currency: str = "USD"

    def __post_init__(self):
        for value in (self.provider, self.model, self.version):
            identifier(value)
        for value in (self.input_microusd_per_million, self.cached_input_microusd_per_million,
                      self.output_microusd_per_million, self.request_microusd):
            integer(value)
        if type(self.currency) is not str or self.currency != "USD":
            raise CostError("cost_unsupported_currency")

    @property
    def digest(self):
        return hashlib.sha256(canonical(asdict(self)).encode("ascii")).hexdigest()

    def cost(self, usage):
        if type(usage) is not TokenUsage:
            raise CostError("cost_invalid_usage")
        weighted = ((usage.input_tokens - usage.cached_input_tokens) * self.input_microusd_per_million
                    + usage.cached_input_tokens * self.cached_input_microusd_per_million
                    + usage.output_tokens * self.output_microusd_per_million)
        # Round the complete request upwards once, using integer arithmetic.
        return integer(self.request_microusd + (weighted + 999_999) // 1_000_000)

    def ceiling(self, input_token_limit, output_token_limit):
        integer(input_token_limit, MAX_TOKENS)
        integer(output_token_limit, MAX_TOKENS)
        cached = input_token_limit if self.cached_input_microusd_per_million > self.input_microusd_per_million else 0
        return self.cost(TokenUsage(input_token_limit, output_token_limit, cached))


def quote(price, usage, input_token_limit, output_token_limit):
    if type(price) is not PriceCard or type(usage) is not TokenUsage:
        raise CostError("cost_invalid_quote")
    ceiling = price.ceiling(input_token_limit, output_token_limit)
    if usage.input_tokens > input_token_limit or usage.output_tokens > output_token_limit:
        raise CostError("cost_estimate_exceeds_ceiling")
    return {"price": asdict(price), "price_digest": price.digest, "estimated_usage": asdict(usage),
            "input_token_limit": input_token_limit, "output_token_limit": output_token_limit,
            "estimated_microusd": price.cost(usage), "ceiling_microusd": ceiling}
