"""Exact price arithmetic and explicit conservative bounds."""

from dataclasses import replace

import pytest

from recon_cockpit.secure_agent.cost_contract import CostError, MAX_AMOUNT, PriceCard, TokenUsage, quote


PRICE = PriceCard("example", "example-model", "approved-v1", 1_250_000, 125_000, 10_000_000)


def test_exact_microdollar_arithmetic_with_cached_input_and_fixed_fee():
    price = replace(PRICE, request_microusd=7)
    assert price.cost(TokenUsage(1_000_000, 1_000_000, 200_000)) == 11_025_007
    assert price.cost(TokenUsage(1, 0)) == 9
    assert price.cost(TokenUsage(0, 0)) == 7
    assert price.cost(TokenUsage(1, 1, 1)) == 18


def test_ceiling_never_assumes_a_cache_discount():
    result = quote(PRICE, TokenUsage(1000, 10, 1000), 2000, 100)
    assert result["estimated_microusd"] == 225
    assert result["ceiling_microusd"] == 3500
    unusual = replace(PRICE, cached_input_microusd_per_million=2_500_000)
    assert unusual.ceiling(2000, 100) == 6000


def test_submicrodollar_components_are_rounded_up_once():
    price = PriceCard("example", "model", "v1", 1, 1, 1)
    assert price.cost(TokenUsage(1, 1)) == 1
    assert price.cost(TokenUsage(1_000_000, 1)) == 2


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens", "cached_input_tokens"])
@pytest.mark.parametrize("bad", [True, False, -1, 1.5, "1", None, 10**9 + 1])
def test_usage_requires_bounded_integers(field, bad):
    with pytest.raises(CostError):
        TokenUsage(**{**{"input_tokens": 10, "output_tokens": 10, "cached_input_tokens": 0}, field: bad})


@pytest.mark.parametrize("field", ["input_microusd_per_million", "cached_input_microusd_per_million",
                                  "output_microusd_per_million", "request_microusd"])
@pytest.mark.parametrize("bad", [True, -1, 0.1, "1", None, MAX_AMOUNT + 1])
def test_tariffs_require_bounded_integers(field, bad):
    with pytest.raises(CostError):
        replace(PRICE, **{field: bad})


@pytest.mark.parametrize("field", ["provider", "model", "version"])
@pytest.mark.parametrize("bad", [None, [], "", "x" * 129, "unsafe\nname"])
def test_tariff_identifiers_are_bounded_and_safe(field, bad):
    with pytest.raises(CostError):
        replace(PRICE, **{field: bad})


def test_missing_usage_unsupported_currency_and_underestimated_bounds_fail():
    with pytest.raises(CostError, match="cost_invalid_usage"):
        PRICE.cost(None)
    with pytest.raises(CostError, match="cost_invalid_usage"):
        TokenUsage(10, 10, 11)
    with pytest.raises(CostError, match="cost_unsupported_currency"):
        replace(PRICE, currency="EUR")
    with pytest.raises(CostError, match="cost_estimate_exceeds_ceiling"):
        quote(PRICE, TokenUsage(11, 10), 10, 10)
    with pytest.raises(CostError, match="cost_estimate_exceeds_ceiling"):
        quote(PRICE, TokenUsage(10, 11), 10, 10)
    with pytest.raises(CostError, match="cost_invalid_amount"):
        replace(PRICE, output_microusd_per_million=MAX_AMOUNT).cost(TokenUsage(0, 10**9))
