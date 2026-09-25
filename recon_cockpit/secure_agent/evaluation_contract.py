"""Reviewed expectations for synthetic evaluations, separate from the engine.

This oracle is authored from the six fixed scenario definitions. It deliberately
does not ask the workflow under test to predict its own expected decisions.
"""

from __future__ import annotations

import copy
import hashlib
import json


CASES = tuple("abcdef")
REPEATS = 3
TRIAL_COUNT = 18
FIXED_LIMITS = {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 3072}
_ORACLE = {
    "a": {"outcome": "validated", "classification": "expected_validation",
          "statuses": ["succeeded"] * 3, "observations": ["reachable", "discovered", "exposed"],
          "observation_reasons": ["tcp_port_reachable", "fixture_discovered", "seeded_diagnostics_exposed"],
          "terminal_reason": "seeded_diagnostic_metadata_exposed", "session_status": "completed", "stop_reason": "coordinator_done"},
    "b": {"outcome": "not_demonstrated", "classification": "expected_not_demonstrated",
          "statuses": ["succeeded"] * 3, "observations": ["reachable", "discovered", "absent"],
          "observation_reasons": ["tcp_port_reachable", "fixture_discovered", "endpoint_not_found"],
          "terminal_reason": "diagnostic_endpoint_not_found", "session_status": "completed", "stop_reason": "coordinator_done"},
    "c": {"outcome": "inconclusive", "classification": "correct_abstention",
          "statuses": ["succeeded"] * 3, "observations": ["reachable", "discovered", "inconclusive"],
          "observation_reasons": ["tcp_port_reachable", "fixture_discovered", "invalid_document"],
          "terminal_reason": "diagnostic_evidence_invalid", "session_status": "completed", "stop_reason": "coordinator_done"},
    "d": {"outcome": "inconclusive", "classification": "correct_abstention",
          "statuses": ["succeeded", "succeeded", "timeout"], "observations": ["reachable", "discovered", "inconclusive"],
          "observation_reasons": ["tcp_port_reachable", "fixture_discovered", "execution_not_succeeded"],
          "terminal_reason": "action_timeout", "session_status": "stopped", "stop_reason": "action_timeout"},
    "e": {"outcome": "inconclusive", "classification": "correct_abstention",
          "statuses": ["succeeded", "succeeded", "output_limit"], "observations": ["reachable", "discovered", "inconclusive"],
          "observation_reasons": ["tcp_port_reachable", "fixture_discovered", "execution_not_succeeded"],
          "terminal_reason": "action_output_limit", "session_status": "stopped", "stop_reason": "action_output_limit"},
    "f": {"outcome": "inconclusive", "classification": "correct_abstention",
          "statuses": ["succeeded"] * 2, "observations": ["reachable", "inconclusive"],
          "observation_reasons": ["tcp_port_reachable", "unexpected_discovery_document"],
          "terminal_reason": "discovery_or_execution_evidence_missing", "session_status": "completed", "stop_reason": "coordinator_done"},
}


def oracle(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_evaluation_case")
    return copy.deepcopy(_ORACLE[case])


def descriptor():
    return {"id": "owned-workflow-evaluation", "version": "1", "cases": copy.deepcopy(_ORACLE),
            "baseline_repeats": REPEATS, "baseline_trials": TRIAL_COUNT,
            "trial_limits": dict(FIXED_LIMITS), "grading": "saved-evidence-and-audit-replay-v1",
            "live_calls_enabled": False, "scope": {"target": "127.0.0.1", "port": 8080},
            "scoring": "expected_decisions_with_evidence_not_general_vulnerability_accuracy"}


def evaluation_identity():
    value = descriptor()
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return {"id": value["id"], "version": value["version"], "sha256": hashlib.sha256(raw).hexdigest()}
