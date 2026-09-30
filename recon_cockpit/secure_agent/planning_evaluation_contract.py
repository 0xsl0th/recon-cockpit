"""Versioned offline evaluation of the accepted owned TLS planning profile."""

from dataclasses import asdict
import hashlib

from .assessment_planning_contract import DEFAULT_BUDGET_MICROUSD, PRICE
from .evaluation import RESERVATION as BASE_RESERVATION
from .evaluation_contract import FIXED_LIMITS, descriptor as baseline_descriptor
from .evidence import _encode


PROFILE = "owned-planning-evaluation-v1"
TRIAL_BUDGET = DEFAULT_BUDGET_MICROUSD
RESERVATION = {**BASE_RESERVATION, "simulation_microusd": TRIAL_BUDGET}
PLANNING_METRICS = ("owned_tls_exchanges", "planning_actual_microusd",
                    "planning_reserved_microusd", "planning_unresolved_attempts",
                    "planning_input_tokens", "planning_cached_input_tokens",
                    "planning_output_tokens", "actual_provider_calls")


def descriptor():
    baseline = baseline_descriptor()
    return {**baseline, "id": "owned-planning-evaluation", "version": "1",
            "profile": PROFILE, "grading": "saved-planning-tls-cost-replay-v1",
            "baseline": {"id": baseline["id"], "version": baseline["version"]},
            "planning": {"transport": "owned_tls", "scenario": "success", "mode": "simulation",
                         "price": asdict(PRICE), "trial_budget_microusd": TRIAL_BUDGET,
                         "actual_provider_calls": 0},
            "services": {"isolated_audit": True, "isolated_launcher": True,
                         "audit_gate": True, "approval_gate": True,
                         "approval_mode": "unattended_owned_policy", "human_acceptance": False}}


def evaluation_identity():
    value = descriptor()
    return {"id": value["id"], "version": value["version"],
            "sha256": hashlib.sha256(_encode(value)).hexdigest()}


def scope_ids(evaluation_id):
    return {"account_scope_id": "planning-evaluation-" + evaluation_id,
            "engagement_scope_id": "planning-engagement-" + evaluation_id}


def totals(count):
    return {key: value * count for key, value in RESERVATION.items()}
