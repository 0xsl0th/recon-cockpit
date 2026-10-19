"""Finite negative proposals; these helpers never mint a grant or start a peer.

The N15 real-grant composite belongs to the explicitly scripted owned native
test harness. An ordinary product run must not invent its missing receipts.
"""

from copy import deepcopy
import time

from . import name_tls_contract as contract
from .execution import ExecutionControl


def _binding(outcomes, *, first=False):
    rows = outcomes if first else reversed(outcomes)
    for row in rows:
        result = row.get("untrusted_result") or {}
        state = result.get("name_tls_ledger") or {}
        if state.get("binding") is not None:
            return deepcopy(state["binding"])
    return None


def _unobserved_service_probe(selected, owner, slot):
    """Return only an invalid undeclared-name proposal, never a usable binding."""
    value = {"version": "1", **{key: owner[key] for key in (
        "owner_id", "owner_identity_sha256", "session_id", "runtime_identity_sha256")},
        **{key: selected[key] for key in ("configuration", "case", "selection_sha256")},
        "observation_generation": 1, "observation_sha256": "0" * 64,
        "canonical_question": contract.public.DNS_NAME + " IN A", "original_answer_sha256": "0" * 64,
        "delivered_answer_sha256": "0" * 64,
        "singleton_allowed_ipv4": contract.public.endpoints(selected["configuration"])["http"]["target"],
        "observed_ttl_seconds": 60, "observed_at_us": 0, "expires_at_us": 60000000}
    value["binding_sha256"] = contract.digest(value)
    raw = contract.service_action(selected, owner, slot, value)
    raw["parameters"]["canonical_name"] = contract.public.UNDECLARED_NAME
    raw["parameters"]["host" if slot == "http" else "sni"] = contract.public.UNDECLARED_NAME
    return raw


def proposals(selected, identity, outcomes):
    """Return the fixed attempts and their honest earliest expected guards."""
    selected = contract.validate_selection(selected)
    identity = contract.validate_identity(identity, selection=selected)
    case = selected["case"]
    if case not in contract.PROBE_CASES or case == "N15":
        return []
    if case == "N4":
        dns = contract.dns_action(selected, identity)
        dns["parameters"]["question_name"] = contract.public.UNDECLARED_NAME + "."
        return [("dns_1", dns, "typed_validation"),
                *( (slot, _unobserved_service_probe(selected, identity, slot), "typed_validation")
                   for slot in ("http", "tls"))]
    binding = _binding(outcomes, first=case == "N1")
    if binding is None:
        return []
    contract.validate_binding(binding, selected=selected, identity=identity)
    if case in ("N1", "N9"):
        raw = contract.service_action(selected, identity, "http", binding)
        if case == "N9":
            raw["parameters"]["host"] = contract.public.UNDECLARED_NAME + ":" + str(raw["parameters"]["port"])
        return [("http", raw, "static_profile" if case == "N1" else "typed_validation")]
    if case == "N10":
        raw = contract.service_action(selected, identity, "tls", binding)
        raw["parameters"]["sni"] = contract.public.UNDECLARED_NAME
        return [("tls", raw, "typed_validation")]
    return [(slot, contract.service_action(selected, identity, slot, binding), guard)
            for slot, guard in (("http", "owner_expiry"), ("tls", "owner_terminal"))]


def run_probe_cases(controller, backend, *, selected, identity, control, outcomes, execute=True):
    """Submit finite attempts through normal authority; never label them passed.

Native evidence grading checks the actual returned guards and owner transcript.
Sleeping until a timestamp is not itself evidence of owner-side TTL refusal.
"""
    selected = contract.validate_selection(selected)
    identity = contract.validate_identity(identity, selection=selected)
    if (type(control) is not ExecutionControl or control.clock is not time.monotonic
            or type(execute) is not bool or type(outcomes) is not list or controller.backend is not backend):
        raise ValueError("invalid_name_tls_probe_context")
    case = selected["case"]
    result = {"schema_version": "1", "selection_sha256": selected["selection_sha256"],
              "owner_identity_sha256": identity["owner_identity_sha256"], "case": case,
              "instrumented": True, "attempts": [], "waited_us": 0, "status": "not_required"}
    if case not in contract.PROBE_CASES:
        return result
    if case == "N15":
        result.update(status="incomplete", reason="requires_owned_scripted_real_grant_composite")
        return result
    attempts = proposals(selected, identity, outcomes)
    if not attempts:
        result.update(status="incomplete", reason="required_native_binding_missing")
        return result
    if case == "N14" and execute:
        binding = _binding(outcomes)
        # The production topology owner pins started_at to deadline - 60; this
        # wait only schedules an attempt. Its surviving ledger must prove expiry.
        expires = control.deadline - 60 + binding["expires_at_us"] / 1000000
        before = time.monotonic()
        while time.monotonic() <= expires:
            control.check()
            time.sleep(min(.01, max(.001, expires - time.monotonic() + .001)))
        result["waited_us"] = max(0, int((time.monotonic() - before) * 1000000))
    for index, (slot, raw, guard) in enumerate(attempts, len(outcomes) + 1):
        control.check()
        outcome = controller.submit(raw, execute=execute, execution_control=control, session_step=index)
        result["attempts"].append({"slot": slot, "proposal": raw, "proposal_sha256": contract.digest(raw),
                                   "expected_guard": guard, "outcome": outcome})
    result["status"] = "attempted" if execute else "dry_run"
    return result
