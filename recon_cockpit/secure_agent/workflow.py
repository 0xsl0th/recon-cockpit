"""One built-in, versioned assessment card and evidence-gated decision engine.

The card is reviewed repository data, never a user-supplied program. A decision
only proposes an existing fixture action. Policy, approvals, reservations and
execution authority remain with the Controller and AuthoritySession.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from uuid import UUID

from .assessment_contract import CASES, PARSER_VERSION as HTTP_PARSER, diagnostics_path
from .discovery_contract import PARSER_VERSION as TCP_PARSER, discovery_action
from .models import parse_action


WORKFLOW_ID = "owned-discovery-http-assessment"
WORKFLOW_VERSION = "1"
BLOCKED_REASONS = (
    "noninteractive_approval_required", "approval_missing", "approval_unknown_or_replayed",
    "approval_expired", "approval_action_changed", "approval_policy_changed", "isolation_unavailable",
)
_STOPS = (
    "output_limit", "step_limit", "proposal_denied", "action_blocked",
    "action_failed", "action_timeout", "action_output_limit", "action_cancelled",
    "session_cancelled", "session_timeout", "coordinator_protocol_error",
    "coordinator_failed", "provider_failed", "invalid_proposal",
    "session_component_failed",
    "broker_call_limit", "broker_token_limit", "broker_request_limit",
)


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def card():
    """Return a fresh descriptor of the single supported workflow.

    Ordered predecessor gates and proposal reasons are consumed by decide().
    The action digests bind all six cases to the existing reviewed contracts.
    This descriptor cannot grant permission or introduce another capability.
    """
    return {
        "schema_version": "1", "workflow_id": WORKFLOW_ID,
        "workflow_version": WORKFLOW_VERSION,
        "title": "Owned TCP discovery and diagnostic metadata assessment",
        "provenance": {"kind": "repository_authored",
                       "source": "recon_cockpit/secure_agent/workflow.py",
                       "contracts": ["discovery_contract.py", "assessment_contract.py"],
                       "external_content_adopted": False},
        "fixture_cases": list(CASES), "live_calls_enabled": False,
        "scope": {"target": "127.0.0.1", "port": 8080, "fixture_only": True},
        "prerequisites": ["operator_policy", "isolated_owned_fixture_executor",
                          "authority_session", "durable_private_evidence"],
        "authority_checks": ["scope", "approval", "deadline", "cancellation",
                             "step_budget", "output_budget", "provider_budget", "audit"],
        "effects": ["connect_owned_fixture_tcp", "read_owned_fixture_http"],
        "limits": {"max_actions": 3, "max_steps": 3, "max_output_bytes": 3072, "retries": 0},
        "action_parameters": {"timeout_seconds": 1, "max_output_bytes": 1024,
                              "http_method": "GET", "tcp_payload_bytes": 0},
        "cleanup": {"executor": "terminate_and_reap_each_action_namespace",
                    "artifacts": "private_until_operator_cleanup", "resume_execution": False},
        "steps": [
            {"step": 1, "capability": "tcp_connect", "requires": [],
             "reason": "initial_scoped_discovery", "done": False},
            {"step": 2, "capability": "http_probe", "requires": ["tcp_reachable"],
             "reason": "tcp_reachability_observed", "done": False},
            {"step": 3, "capability": "http_probe", "requires": ["tcp_reachable", "index_discovered"],
             "reason": "fixture_diagnostics_path_observed", "done": True},
        ],
        "evidence_requirements": ["exact_action_and_digest", "succeeded_execution",
                                  "canonical_execution_and_observation_ids",
                                  "reviewed_parser_observation", "latest_authority_observation_digest"],
        "gates": {
            "tcp_reachable": {"parser_version": TCP_PARSER, "kind": "tcp_discovery",
                              "classification": "reachable", "reason": "tcp_port_reachable",
                              "followup_path": None},
            "index_discovered": {"parser_version": HTTP_PARSER, "kind": "discovery",
                                 "classification": "discovered", "reason": "fixture_discovered",
                                 "followup_path": "{fixture_diagnostics_path}"},
        },
        "action_digests": {
            case: [parse_action(discovery_action(case, step)).digest for step in (1, 2, 3)]
            for case in CASES
        },
        "stop_rules": ["missing_or_unexpected_predecessor_evidence", "failed_execution",
                       "unreachable_tcp", "invalid_index", "authority_observation_mismatch",
                       "diagnostics_complete", "dry_run", *_STOPS, *BLOCKED_REASONS],
        "finding": {"condition": "seeded_diagnostic_metadata_exposed",
                    "positive": "exposed", "negative": "absent",
                    "otherwise": "inconclusive", "operator_review": "required"},
        "limitations": ["TCP reachability does not identify an HTTP service.",
                        "Every action recreates the owned topology; services do not persist between steps.",
                        "The card supplies neither authorization nor live-model evidence."],
    }


def card_digest():
    return hashlib.sha256(_encode(card())).hexdigest()


def card_identity():
    return {"id": WORKFLOW_ID, "version": WORKFLOW_VERSION, "sha256": card_digest()}


@dataclass(frozen=True, slots=True)
class WorkflowDecision:
    step: int
    decision_kind: str
    reason: str
    done: bool
    action_digest: str | None
    workflow_digest: str
    _action_bytes: bytes | None
    _predecessors: tuple[tuple[str, str | None], ...]

    @property
    def action(self):
        return None if self._action_bytes is None else json.loads(self._action_bytes)

    @property
    def predecessors(self):
        return [{"execution_id": execution, "observation_id": observation}
                for execution, observation in self._predecessors]

    def to_dict(self):
        """Bounded decision metadata, excluding response bodies and rationale."""
        return {"schema_version": "1", "workflow_id": WORKFLOW_ID,
                "workflow_version": WORKFLOW_VERSION, "workflow_digest": self.workflow_digest,
                "decision_kind": self.decision_kind, "step": self.step,
                "reason": self.reason, "action_digest": self.action_digest,
                "predecessors": self.predecessors}


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _references(records):
    if type(records) not in (list, tuple) or len(records) > 3:
        return ()
    return tuple((row["execution_id"], row.get("observation_id")) for row in records
                 if type(row) is dict and _uuid(row.get("execution_id"))
                 and (row.get("observation_id") is None or _uuid(row["observation_id"])))


def _stop(step, reason, records):
    return WorkflowDecision(step, "stop", reason, True, None, card_digest(), None, _references(records))


def _record_matches(case, step, record):
    if (type(record) is not dict or type(record.get("session_step")) is not int
            or record["session_step"] != step or not _uuid(record.get("execution_id"))
            or not _uuid(record.get("observation_id"))):
        return False
    action = discovery_action(case, step)
    safe = {key: value for key, value in action.items() if key != "rationale"}
    try:
        return (record.get("action_digest") == parse_action(action).digest
                and _encode(record.get("action")) == _encode(safe))
    except (ValueError, TypeError, RecursionError):
        return False


def _gate_matches(case, gate, observation, definition=None):
    definition = card() if definition is None else definition
    if gate not in definition["gates"]:
        raise ValueError("invalid_builtin_workflow_gate")
    expected = dict(definition["gates"][gate])
    if expected["followup_path"] == "{fixture_diagnostics_path}":
        expected["followup_path"] = diagnostics_path(case)
    return type(observation) is dict and observation == expected


def _case(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_assessment_case")


def decide(case, step, records, observation):
    """Propose the next exact action or stop, using only host-owned evidence.

    The provider validates sequencing and the authority frame before calling.
    Missing execution evidence stops even when no reconstructable frame exists
    (dry runs and crash inspection); it can never enable a candidate exchange.
    """
    _case(case)
    if type(step) is not int or step not in (1, 2, 3):
        raise ValueError("invalid_workflow_step")
    definition = card()
    node = definition["steps"][step - 1]
    required = node["requires"]
    if type(records) not in (list, tuple) or len(records) < len(required):
        return _stop(step, "predecessor_evidence_missing", records)
    if len(records) != len(required):
        return _stop(step, "unexpected_predecessor_evidence", records)
    executions, observations = set(), set()
    for index, (record, gate) in enumerate(zip(records, required), start=1):
        if not _record_matches(case, index, record):
            return _stop(step, "predecessor_evidence_invalid", records)
        if record["execution_id"] in executions or record["observation_id"] in observations:
            return _stop(step, "predecessor_evidence_invalid", records)
        executions.add(record["execution_id"])
        observations.add(record["observation_id"])
        if record.get("execution_status") != "succeeded":
            return _stop(step, "predecessor_execution_not_succeeded", records)
        if not _gate_matches(case, gate, record.get("observation"), definition):
            return _stop(step, "tcp_reachability_not_established" if gate == "tcp_reachable"
                         else "fixture_index_not_established", records)
    if records and (type(observation) is not bytes or len(observation) > 8192
                    or records[-1].get("authority_observation_sha256") != hashlib.sha256(observation).hexdigest()):
        return _stop(step, "authority_observation_mismatch", records)
    action = discovery_action(case, step)
    return WorkflowDecision(step, "propose", node["reason"], node["done"],
                            definition["action_digests"][case][step - 1],
                            hashlib.sha256(_encode(definition)).hexdigest(), _encode(action), _references(records))


def terminal_decision(case, records, summary):
    """Explain final authority closure; never propose or restore execution.

    Summary fields are validated again by evidence persistence. Fixed allowlists
    prevent arbitrary component error text appearing in decision explanations.
    """
    _case(case)
    if (type(summary) is not dict or type(summary.get("steps_attempted")) is not int
            or not 0 <= summary["steps_attempted"] <= 3):
        raise ValueError("invalid_workflow_summary")
    step = summary["steps_attempted"] + 1
    if summary.get("mode") == "dry_run":
        return _stop(step, "dry_run_has_no_execution_evidence", records)
    if summary.get("mode") != "execute":
        raise ValueError("invalid_workflow_summary")
    if summary.get("session_status") != "completed":
        reason = summary.get("stop_reason")
        blocked = summary.get("blocked_reason")
        if reason == "action_blocked" and type(blocked) is str and blocked in BLOCKED_REASONS:
            return _stop(step, blocked, records)
        return _stop(step, reason if type(reason) is str and reason in _STOPS else "session_stopped", records)
    if type(records) not in (list, tuple) or len(records) != 3:
        return _stop(step, "discovery_or_execution_evidence_missing", records)
    if (any(not _record_matches(case, index, row) or row.get("execution_status") != "succeeded"
            for index, row in enumerate(records, start=1))
            or len({row["execution_id"] for row in records}) != 3
            or len({row["observation_id"] for row in records}) != 3
            or not _gate_matches(case, "tcp_reachable", records[0].get("observation"))
            or not _gate_matches(case, "index_discovered", records[1].get("observation"))):
        return _stop(step, "discovery_or_execution_evidence_missing", records)
    last = records[-1].get("observation")
    expected = {"parser_version": HTTP_PARSER, "kind": "diagnostics", "followup_path": None}
    if last == {**expected, "classification": "exposed", "reason": "seeded_diagnostics_exposed"}:
        reason = "seeded_diagnostic_metadata_exposed"
    elif last == {**expected, "classification": "absent", "reason": "endpoint_not_found"}:
        reason = "diagnostic_endpoint_not_found"
    else:
        reason = "diagnostic_evidence_invalid"
    return _stop(step, reason, records)
