"""Pinned local policy judgments over bounded, unauthenticated SSH advertisements.

This module opens no socket, reads no policy file and grants no authority.  The
accepted C14 wire parser remains the sole advertisement decoder.  A production
caller must separately require successful bounded execution and owner closure.
"""

import hashlib
import json

if __package__:
    from . import network_tools_ssh_algorithms_parser as advertisements
else:
    import network_tools_ssh_algorithms_parser as advertisements


TOOL_ID = "ssh_transport_policy_v1"
PARSER_VERSION = "ssh-policy-wire-v1"
POLICY_ID = "recon-ssh-advertisement-policy-v1"
SEMANTICS = "untrusted_ssh_advertisements_against_pinned_local_policy"
MAX_SUMMARY_BYTES = advertisements.MAX_SUMMARY_BYTES

# Immutable repository policy data.  Exact names only: no wildcard, inferred
# strength, banner-version inference, downloaded database or implicit fallback.
# Directional rules are separate even when their present choices coincide.
POLICY_RULES = (
    ("kex_algorithms", ("curve25519-sha256", "diffie-hellman-group14-sha256"),
        ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")),
    ("server_host_key_algorithms", ("ssh-ed25519", "rsa-sha2-256"), ("ssh-dss", "ssh-rsa")),
    ("encryption_algorithms_client_to_server", ("aes128-ctr", "aes256-ctr"),
        ("3des-cbc", "aes128-cbc", "aes256-cbc", "arcfour")),
    ("encryption_algorithms_server_to_client", ("aes128-ctr", "aes256-ctr"),
        ("3des-cbc", "aes128-cbc", "aes256-cbc", "arcfour")),
    ("mac_algorithms_client_to_server", ("hmac-sha2-256", "hmac-sha2-512"), ("hmac-md5", "hmac-sha1")),
    ("mac_algorithms_server_to_client", ("hmac-sha2-256", "hmac-sha2-512"), ("hmac-md5", "hmac-sha1")),
    ("compression_algorithms_client_to_server", ("none", "zlib@openssh.com"), ("zlib",)),
    ("compression_algorithms_server_to_client", ("none", "zlib@openssh.com"), ("zlib",)),
)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


POLICY_BYTES = _encode({"policy_id": POLICY_ID, "version": "1",
    "scope": "advertisements_only", "allow_known_subsets_and_reordering": True,
    "unknown_algorithm_outcome": "inconclusive", "preference_assessed": False,
    "rules": {field: {"allowed": list(allowed), "disallowed": list(disallowed)}
        for field, allowed, disallowed in POLICY_RULES}})
POLICY_SHA256 = hashlib.sha256(POLICY_BYTES).hexdigest()


def _assess(observed):
    rules = {}
    for field, allowed, disallowed in POLICY_RULES:
        names = observed["algorithms"][field]
        prohibited = [name for name in names if name in disallowed]
        unknown = [name for name in names if name not in allowed and name not in disallowed]
        # Unknown is never upgraded to an allowed or a known-disallowed name.
        # Preserve known deviations alongside unknown names, without claiming a
        # complete policy assessment for the mixed response.
        status = "inconclusive" if unknown else "deviation" if prohibited else "conforming"
        rules[field] = {"status": status, "disallowed": prohibited, "unknown": unknown}
    statuses = {row["status"] for row in rules.values()}
    status = ("inconclusive" if "inconclusive" in statuses else
        "deviation" if "deviation" in statuses else "conforming")
    result = {**observed, "parser_version": PARSER_VERSION, "kind": "ssh_policy_assessment",
        "semantics": SEMANTICS, "policy_id": POLICY_ID, "policy_sha256": POLICY_SHA256,
        "policy_status": status, "rules": rules}
    if len(_encode(result)) > MAX_SUMMARY_BYTES:
        raise ValueError("excess_ssh_policy_summary")
    return result


def assess_advertisements(value):
    """Evaluate a complete C14 observation; this does not validate execution."""
    return _assess(advertisements.validate_result(value))


def parse_output(raw, stderr=b""):
    """Reparse retained client bytes before applying the immutable snapshot."""
    return _assess(advertisements.parse_output(raw, stderr))


def validate_result(value):
    """Recompute every rule and policy binding, returning a detached result."""
    fields = {"parser_version", "kind", "semantics", "server_identification", "algorithms",
        "first_kex_packet_follows", "key_exchange_completed", "authenticated_session",
        "service_identity_verified", "policy_id", "policy_sha256", "policy_status", "rules"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid_ssh_policy_observation")
    observed = {key: item for key, item in value.items()
        if key not in ("policy_id", "policy_sha256", "policy_status", "rules")}
    observed.update(parser_version=advertisements.PARSER_VERSION,
        kind="ssh_algorithm_metadata", semantics=advertisements.SEMANTICS)
    expected = assess_advertisements(observed)
    # JSON equality also rejects bool-as-int values in nested supplied fields.
    try:
        same = _encode(value) == _encode(expected)
    except (TypeError, ValueError, OverflowError):
        same = False
    if not same:
        raise ValueError("invalid_ssh_policy_observation")
    return expected
