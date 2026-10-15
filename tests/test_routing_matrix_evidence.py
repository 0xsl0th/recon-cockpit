"""Portable v3 protocol/ledger replay; these doubles are not native acceptance."""

import base64
from copy import deepcopy
import hashlib
import json
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_evidence as evidence
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.stock_http_spec import encode
from test_routing_contract import SESSION, INSTANCE
from test_routing_evidence import closure, portable_parsers
from test_stock_http_production_authority import runtime as http_runtime
from test_stock_ssh_client import manifests as ssh_runtime

SLOT_CASES = {
    "http_headers": ("O1", "O2", "O3", "O4", "R1", "R2", "N1", "N2", "N3", "N4", "N5"),
    "http_nmap": ("O5", "O6"), "ssh_nmap": ("O1", "N1"),
    "ssh_keys": ("O2", "R1", "R2", "N2", "N3", "N4", "N5", "N6"),
}
BASELINE = {"http_nmap": "O5", "http_headers": "O1", "ssh_nmap": "O1", "ssh_keys": "O2"}


def matrix_manifest(selectors=None, *, profile="baseline", deployment="nginx-A", budget="ordinary", approval=False):
    selected = contract.selection(budget, deployment=deployment, case_profile=profile)
    configuration, implementation = selected["configuration"], contract.http_implementation(selected)
    bundle = {name: http_runtime(implementation, configuration, contract.selected_case(name, selected))
              if name.startswith("http_") else ssh_runtime(configuration, contract.selected_case(name, selected))
              for name in contract.SELECTORS}
    return {"schema_version": "1", "assessment_id": str(UUID(int=3510)), "session_id": SESSION,
        "selection": selected, "selectors": list(contract.SELECTORS if selectors is None else selectors),
        "policy": contract.policy_for_selection(selected, require_approval=approval).to_dict(),
        "limits": contract.limits(selected), "runtime": bundle,
        "identity": contract.identity(selected, SESSION, bundle, instance_id=INSTANCE)}


def matrix_results(monkeypatch, chosen, *, count=None):
    """Join real portable protocol/parser fixtures with an actually replayed ledger."""
    from test_routing_ledger import Harness as Budget
    from test_routing_topology import metadata
    from test_stock_http_production_evidence import manifest as http_manifest, peer_result as http_result
    from test_stock_ssh_contract_evidence import manifest as ssh_manifest, peer_result as ssh_result
    from recon_cockpit.secure_agent.routing_client_runtime import BOUNDARY_NAMES
    from recon_cockpit.secure_agent.routing_service_contract import validate_service
    from recon_cockpit.secure_agent.stock_http_owner_worker import BOUNDS
    from recon_cockpit.secure_agent import routing_ledger
    budget = Budget(chosen["selection"]["budget_case"])
    budget.selected = chosen["selection"]
    budget.owner = chosen["identity"]
    budget.ledger = routing_ledger.Ledger(budget.selected, budget.owner, started_at=budget.now, clock=lambda: budget.now)
    budget.action_digest = contract.digest(budget.selected)
    configuration = chosen["selection"]["configuration"]
    implementation = contract.http_implementation(chosen["selection"])
    topology = metadata(configuration=configuration)
    results = []
    for step, selector in enumerate(chosen["selectors"][:count], 1):
        underlying = contract.underlying_selection(selector, chosen["selection"])
        if selector.startswith("http_"):
            source = http_result(monkeypatch, http_manifest(configuration=configuration, case=underlying["case"], implementation=implementation))
            record, instances = source["stock_http_owner"]["recorder"], []
            if underlying["case"] == "N4":
                # The accepted peer double supplies the real deterministic
                # original/proposal; this routed double delivers no response.
                record.update(client_response_bytes=0, writes=[], terminal_reason="io_failure")
                record["events"] = [row for row in record["events"] if row["kind"] != "complete"]
                source.update(status="failed", truncated=False, bytes_received=0, tool_observation=None)
                source["results"][0].update(bytes_received=0, truncated=False, raw_response="",
                    response_sha256=hashlib.sha256(b"").hexdigest())
        else:
            source = ssh_result(monkeypatch, ssh_manifest(configuration=configuration, case=underlying["case"]))
            record = source["stock_ssh_owner"]["recorder"]
            instances = source["stock_ssh_owner"]["instances"]
            offset = 0 if selector == "ssh_nmap" else 3
            for index, instance in enumerate(instances):
                instance["receipt"]["descriptor"] = deepcopy(topology["private_ssh_pairs"][offset + index]["daemon"])
        role = contract.selector_role(selector)
        number = 200 if role == "http_frontend" else 210
        frontend_ns = {name: name + ":[" + str(number) + "]" for name in ("user", "net", "mnt", "pid")}
        frontend_ns["net"] = topology["networks"][role]
        daemon_ns = {name: name + ":[" + str(400 + step) + "]" for name in frontend_ns}
        mapping = lambda uid: {"uid_map": [[uid, 1000, 1]], "gid_map": [[uid, 1000, 1]],
                               "launcher_uid": 1000, "launcher_gid": 1000}
        if role == "http_frontend":
            uid = 0 if implementation == "nginx" else 65534
            daemon_ready = {"namespaces": daemon_ns, "bounds": dict(BOUNDS),
                "runtime_digest": chosen["identity"]["runtimes"][selector]["daemon_runtime_sha256"],
                "namespace_identity": {"uid": uid, "gid": uid, "supplementary_groups": [uid],
                    "setgroups_policy": "deny", "group_mutation_denied": True},
                "descriptor": None if implementation == "nginx" else {"daemon_netns_cookie": 400, "inode": 4000 + step}}
        else:
            daemon_ready = deepcopy(source["stock_ssh_owner"]["owner"]["custodian"])
            daemon_ready["namespaces"] = daemon_ns
        budget.now += .25
        assert budget.arm(selector)["status"] == "ok"
        assert record["connections_admitted"] == 1
        assert budget.connect()["status"] == "ok"
        actual_request = record["request_bytes_delivered"] if role == "http_frontend" else record["client_bytes_forwarded"]
        actual_response = record["client_response_bytes"] if role == "http_frontend" else record["client_bytes_delivered"]
        if selector != "ssh_nmap": assert budget.request_unit()["status"] == "ok"
        if actual_request: assert budget.bytes("request", actual_request)["status"] == "ok"
        overflow_refused = selector == "http_headers" and underlying["case"] == "N4"
        if overflow_refused:
            assert budget.bytes("response", 2049)["reason"] == "action_response_bytes_limit"
        elif actual_response:
            assert budget.bytes("response", actual_response)["status"] == "ok"
        assert budget.finish_connection()["status"] == "ok"
        reservations = [{"message": row["message"], "reply": row["reply"]}
            for row in routing_ledger.replay_responses(budget.ledger.snapshot())
            if row["role"] == role and row["message"]["action_sequence"] == step]
        receipt = {"selector": selector, "action_sequence": step,
            "action_digest": contract.digest(contract.action(chosen["selection"], selector)),
            "underlying_selection": underlying, "daemon_ready": daemon_ready,
            "daemon_mapping": mapping(0 if role == "http_frontend" and implementation == "nginx" else 65534),
            "frontend_ready": {"ready": True, "role": role, "namespaces": frontend_ns,
                "listener": deepcopy(topology["listeners"]["http" if role == "http_frontend" else "ssh"]["local"]),
                "bounds": dict(BOUNDS), "private_pairs": [] if role == "http_frontend" else [
                    deepcopy(pair["daemon"]) for pair in topology["private_ssh_pairs"]]},
            "frontend_mapping": mapping(0), "recorder": record, "instances": instances,
            "reservations": reservations, "budget_denied": overflow_refused, "last_budget_reply": reservations[-1]["reply"],
            "closure": {"daemon_processes_reaped": True, "action_connections_closed": True,
                        "frontend_persists": True, "topology_persists": True}}
        if role == "http_frontend" and implementation == "apache":
            receipt["apache_descriptor_custody"] = {"version": "1", "descriptor": deepcopy(daemon_ready["descriptor"]),
                "frontend_netns_cookie": topology["listeners"]["http"]["netns_cookie"],
                "unconnected_at_transfer": True, "transferred_once": True, "frontend_consumed": True,
                "frontend_copy_closed": True, "listener_verified": True, "owner_copy_closed": True,
                "launcher_copy_closed": True}
        validate_service(receipt, selected=chosen["selection"], identity=chosen["identity"], topology=topology)
        assert budget.finish_action(source["bytes_received"])["status"] == "ok"
        result = {key: deepcopy(value) for key, value in source.items()
                  if key not in {"stock_http_owner", "stock_ssh_owner", "stock_http_closure", "stock_ssh_closure", "owned_lab"}}
        result.update(backend=contract.BACKEND, boundary_checks=dict.fromkeys(BOUNDARY_NAMES, True),
                      routing_topology=deepcopy(topology), routing_ledger=budget.ledger.snapshot(), routing_service=receipt)
        result["owned_lab"] = {"identity": deepcopy(chosen["identity"]),
            "connection_count": budget.ledger.snapshot()["counters"]["connections"],
            "request_count": budget.ledger.snapshot()["counters"]["http_requests"] + budget.ledger.snapshot()["counters"]["kex_exchanges"],
            "owner_receipt_sha256": contract.digest({key: result[key] for key in ("routing_topology", "routing_ledger", "routing_service")})}
        results.append(result)
    return results


def save_prefix(directory, chosen, results):
    """Keep all planned slots in the manifest, including unattempted later work."""
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None):
            pass
        def run(self, action, policy):
            selector = contract.action_selector(action, chosen["selection"])
            return deepcopy(results[chosen["selectors"].index(selector)])
    with evidence.RoutingEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcomes = [controller.submit(contract.action(chosen["selection"], selector), execute=True, session_step=step)
                        for step, selector in enumerate(chosen["selectors"][:len(results)], 1)]
        last = next((row["owned_lab"] for row in reversed(results) if row is not None and "owned_lab" in row),
                    {"connection_count": 0, "request_count": 0})
        return store.finalize(outcomes, closure=closure(chosen, last["connection_count"], last["request_count"]), elapsed_ms=3000)


def profile_for(selector, case):
    return "baseline" if case == BASELINE[selector] else f"{selector}_{case}"


def rebind(result):
    result["owned_lab"]["owner_receipt_sha256"] = contract.digest({key: result[key] for key in
        ("routing_topology", "routing_ledger", "routing_service")})


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("selector,case", [(selector, case) for selector, cases in SLOT_CASES.items() for case in cases])
def test_full_routed_case_matrix_replays_with_case_bound_outcomes(tmp_path, monkeypatch, portable_parsers, deployment, selector, case):
    chosen = matrix_manifest([selector], profile=profile_for(selector, case), deployment=deployment)
    results = matrix_results(monkeypatch, chosen)
    report = save_prefix(tmp_path / "trial", chosen, results)
    negative = case.startswith("N")
    row = report["actions"][0]
    assert row["case"] == case and row["case_passed"]
    assert row["native_response_verified"]
    assert row["expected_negative"] is negative
    assert row["useful_completion"] is not negative
    assert row["execution_status"] == results[0]["status"]
    assert report["case_passed"] and report["metrics"]["legitimate_task_completed"] is not negative
    assert report["metrics"]["unnecessary_refusals"] == 0
    assert report["metrics"]["expected_negative"] is negative
    expected = "completed" if not negative else "expected_response_budget_refusal" if selector == "http_headers" and case == "N4" else "expected_transport_negative"
    assert report["classification"] == expected
    if selector == "http_headers" and case == "N4":
        from recon_cockpit.secure_agent.stock_http_production_evidence import _native_case_verified
        result = results[0]
        assert not _native_case_verified(contract.underlying_selection(selector, chosen["selection"]),
            {**result, "stock_http_owner": {"recorder": result["routing_service"]["recorder"]}})
        assert row["classification_basis"] == "routing_owner_response_budget_before_delivery"
        assert row["execution_status"] == "failed"
        assert report["metrics"]["reservations"]["response_bytes"] == 0
        assert report["metrics"]["actual_wire_bytes"]["response_bytes"] == 0
    if selector == "ssh_keys" and case == "N3":
        assert row["classification"] == "timeout" and row["execution_status"] == "failed"
        assert row["classification_basis"] == "withheld_response_and_native_two_second_timeout"
    if selector == "ssh_keys" and case == "N4":
        assert row["classification_basis"] == "independent_recorder_wire_cap"
    pins = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
            for path in (tmp_path / "trial").iterdir()}
    assert evidence.inspect_trial(tmp_path / "trial") == report
    assert pins == {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                    for path in (tmp_path / "trial").iterdir()}


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("reverse", (False, True))
def test_baseline_orders_keep_all_four_independent_actions_useful(tmp_path, monkeypatch, portable_parsers, deployment, reverse):
    selectors = list(reversed(contract.SELECTORS)) if reverse else list(contract.SELECTORS)
    chosen = matrix_manifest(selectors, deployment=deployment)
    report = save_prefix(tmp_path / "trial", chosen, matrix_results(monkeypatch, chosen))
    assert report["case_passed"] and report["classification"] == "completed"
    assert report["metrics"]["useful_actions_completed"] == 4
    assert all(row["classification"] == "useful" and row["classification_basis"] is None for row in report["actions"])


@pytest.mark.parametrize("selector,case", (("http_headers", "N1"), ("http_headers", "N4"), ("ssh_nmap", "N1"), ("ssh_keys", "N3")))
def test_mixed_negative_preserves_prior_useful_work_and_unattempted_later_slot(tmp_path, monkeypatch, portable_parsers, selector, case):
    first = "ssh_keys" if selector.startswith("http_") else "http_headers"
    later = next(name for name in contract.SELECTORS if name not in (first, selector))
    chosen = matrix_manifest([first, selector, later], profile=profile_for(selector, case), deployment="apache-B")
    report = save_prefix(tmp_path / "trial", chosen, matrix_results(monkeypatch, chosen, count=2))
    assert report["case_passed"] and not report["metrics"]["legitimate_task_completed"]
    assert report["metrics"]["useful_actions_completed"] == 1
    assert report["metrics"]["attempted_actions"] == 2 and report["metrics"]["planned_actions"] == 3
    assert report["metrics"]["unnecessary_refusals"] == 0
    assert evidence.inspect_trial(tmp_path / "trial") == report


@pytest.mark.parametrize("selector,case", (("http_headers", "N1"), ("ssh_nmap", "N1"), ("ssh_keys", "N3")))
def test_no_saved_action_can_follow_an_executed_declared_negative(tmp_path, monkeypatch, portable_parsers, selector, case):
    later = "ssh_keys" if selector.startswith("http_") else "http_headers"
    chosen = matrix_manifest([selector, later], profile=profile_for(selector, case))
    results = matrix_results(monkeypatch, chosen, count=1)
    owner = results[0]["routing_ledger"]
    assert owner["terminal"] and owner["terminal_reason"] == "declared_negative_completed"
    directory = tmp_path / "trial"
    report = save_prefix(directory, chosen, results)
    assert report["case_passed"] and evidence.inspect_trial(directory) == report
    saved = json.loads((directory / "outcomes.json").read_bytes())
    # The real owner cannot launch another action. A hostile saved chain may
    # still claim later metadata; reject it before treating that claim as an
    # execution result or attempting to validate its contents.
    with pytest.raises(ValueError, match="routing_action_after_declared_negative"):
        evidence.report_for(chosen, [*results, {"forged_later_result": True}],
            [*saved["outcomes"], {"forged_later_outcome": True}], report["closure"], saved["elapsed_ms"])


def test_prior_failed_ordinary_action_cannot_be_hidden_by_later_expected_negative(tmp_path, monkeypatch, portable_parsers):
    chosen = matrix_manifest(["http_headers", "ssh_nmap"], profile="ssh_nmap_N1")
    results = matrix_results(monkeypatch, chosen)
    # A complete stock response and correct recorder are still not useful when
    # the actual client failed; preserve that failure in a mixed assessment.
    results[0]["status"] = "failed"
    results[0]["tool_observation"] = None
    report = save_prefix(tmp_path / "trial", chosen, results)
    assert not report["case_passed"] and report["classification"] == "incomplete"
    assert report["actions"][1]["expected_negative"]
    assert report["metrics"]["unnecessary_refusals"] == 1
    assert not report["metrics"]["expected_negative"]


@pytest.mark.parametrize("status,elapsed", (("failed", 1899), ("timeout", 1899), ("succeeded", 2000)))
def test_ssh_withholding_requires_native_failure_and_full_timeout_corroboration(tmp_path, monkeypatch, portable_parsers, status, elapsed):
    chosen = matrix_manifest(["ssh_keys"], profile="ssh_keys_N3")
    results = matrix_results(monkeypatch, chosen)
    result = results[0]
    result["status"] = status
    result["timing"]["action_elapsed_ms"] = elapsed
    result["provenance"].update(exit_code=0 if status == "succeeded" else 1,
                                stop_reason="timeout" if status == "timeout" else None)
    report = save_prefix(tmp_path / "trial", chosen, results)
    assert not report["case_passed"] and not report["actions"][0]["expected_negative"]
    assert not report["actions"][0]["useful_completion"]


@pytest.mark.parametrize("selector,case", (("http_headers", "N1"), ("ssh_nmap", "N1"), ("ssh_keys", "N4")))
def test_generic_client_failure_is_not_an_expected_transport_negative(tmp_path, portable_parsers, selector, case):
    chosen = matrix_manifest([selector], profile=profile_for(selector, case))
    report = save_prefix(tmp_path / "trial", chosen, [{"status": "failed"}])
    assert not report["case_passed"] and report["classification"] == "incomplete"
    assert not report["actions"][0]["native_response_verified"]
    assert report["metrics"]["unnecessary_refusals"] == 0


@pytest.mark.parametrize("fault", ("proposal", "original_body", "server", "transform_reason", "claimed_delivery", "cleanup", "refusal_reason"))
def test_adapted_overflow_requires_exact_stock_proposal_denial_and_cleanup(tmp_path, monkeypatch, portable_parsers, fault):
    from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
    chosen = matrix_manifest(["http_headers"], profile="http_headers_N4", deployment="apache-B")
    results = matrix_results(monkeypatch, chosen)
    result = results[0]
    service, recorder = result["routing_service"], result["routing_service"]["recorder"]
    if fault == "proposal":
        recorder["transformed_response_hex"] = recorder["transformed_response_hex"][:-2]
    elif fault in ("original_body", "server"):
        raw = bytes.fromhex(recorder["original_response_hex"])
        raw = raw[:-1] + b"!" if fault == "original_body" else raw.replace(b"Apache/", b"nginxX/")
        from recon_cockpit.secure_agent.stock_http_recorder import transform_response
        recorder["original_response_hex"] = raw.hex()
        recorder["transformed_response_hex"] = b"".join(transform_response("N4", raw)[0]).hex()
    elif fault == "transform_reason":
        next(row for row in recorder["events"] if row["kind"] == "transform")["reason"] = "unchanged"
    elif fault == "claimed_delivery":
        recorder["client_response_bytes"] = 1
    elif fault == "cleanup":
        service["closure"]["daemon_processes_reaped"] = False
    else:
        result["routing_ledger"]["terminal_reason"] = "aggregate_response_bytes_limit"
    rebind(result)
    try:
        report = save_prefix(tmp_path / "trial", chosen, results)
    except EvidenceUnavailable:
        return
    assert not report["case_passed"] and not report["actions"][0]["expected_negative"]


def test_report_classification_tampering_cannot_change_read_only_replay(tmp_path, monkeypatch, portable_parsers):
    chosen = matrix_manifest(["ssh_keys"], profile="ssh_keys_N4")
    directory = tmp_path / "trial"
    save_prefix(directory, chosen, matrix_results(monkeypatch, chosen))
    report = json.loads((directory / "report.json").read_bytes())
    report["actions"][0]["classification_basis"] = "client_watchdog"
    (directory / "report.json").write_bytes(encode(report))
    with pytest.raises(ValueError, match="routing_report_replay"):
        evidence.inspect_trial(directory)


def test_single_slot_lowered_budget_refusal_needs_no_invented_prior_useful_action(tmp_path, monkeypatch, portable_parsers):
    from recon_cockpit.secure_agent import routing_frontend_worker as frontend, routing_ledger
    from test_routing_frontend import Wire, install_wire
    from test_routing_ledger import Harness as Budget
    from test_stock_ssh_recorder import Harness as SshHarness, CLIENT_IDENTIFICATION, kex
    chosen = matrix_manifest(["ssh_keys"], budget="ssh_zero")
    result = matrix_results(monkeypatch, matrix_manifest(["ssh_keys"]))[0]
    h = SshHarness(monkeypatch)
    try:
        h.service.__class__ = frontend.SshService
        owner = Budget()
        owner.selected, owner.owner = chosen["selection"], chosen["identity"]
        owner.ledger = routing_ledger.Ledger(owner.selected, owner.owner, started_at=h.clock, clock=lambda: h.clock)
        assert owner.arm("ssh_keys")["status"] == "ok"
        install_wire(monkeypatch)
        wire = Wire(owner.ledger, "ssh_frontend")
        budget = frontend.BudgetChannel(wire, wire.role, 160)
        budget.bind(1, owner.action_digest)
        h.service.budget = budget
        client = h.initial()
        client.sendall(CLIENT_IDENTIFICATION + kex())
        h.until(lambda: h.service.ledger["finalized"])
        recorder = h.service.snapshot()
        assert recorder["client_bytes_forwarded"] == 0 and recorder["client_bytes_delivered"] > 0
        assert owner.finish_action(0)["status"] == "ok"
        snapshot = owner.verify()
    finally:
        h.close()
    reservations = [{"message": row["message"], "reply": row["reply"]}
                    for row in routing_ledger.replay_responses(snapshot) if row["role"] == "ssh_frontend"]
    result.update(status="failed", bytes_received=0, tool_observation=None, raw_output_base64="", raw_stderr_base64="",
                  routing_ledger=snapshot)
    result["provenance"].update(exit_code=1, output_sha256=hashlib.sha256(b"").hexdigest(),
                                stderr_sha256=hashlib.sha256(b"").hexdigest())
    result["routing_service"].update(action_digest=owner.action_digest, recorder=recorder, reservations=reservations,
                                     budget_denied=True, last_budget_reply=reservations[-1]["reply"])
    result["owned_lab"].update(identity=chosen["identity"], connection_count=1, request_count=0)
    rebind(result)
    report = save_prefix(tmp_path / "trial", chosen, [result])
    assert report["case_passed"] and report["classification"] == "expected_budget_refusal"
    assert report["metrics"]["useful_actions_completed"] == 0
    assert report["metrics"]["unnecessary_refusals"] is None
    assert not report["metrics"]["legitimate_task_completed"]
    assert evidence.inspect_trial(tmp_path / "trial") == report

