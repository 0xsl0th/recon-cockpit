"""Validate a one-use stock SSH launch without changing accepted HTTP behavior."""

from . import stock_ssh_contract as contract
from .stock_http_execution import _consume_launch


def consume_launch(raw, nonce, context_digest, *, now=None):
    request, deadline, namespaces, digest = _consume_launch(
        raw, nonce, context_digest, now=now, selected_contract=contract)
    request["endpoint_id"] = "ssh"
    return request, deadline, namespaces, digest
