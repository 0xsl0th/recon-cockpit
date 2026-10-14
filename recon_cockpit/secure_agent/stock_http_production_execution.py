"""Independent inner validation for the separately bound production HTTP mode."""

from . import stock_http_production_contract as contract
from .stock_http_execution import _consume_launch


def consume_launch(raw, nonce, context_digest, *, now=None):
    return _consume_launch(raw, nonce, context_digest, now=now, selected_contract=contract)
