"""Portable saved-evidence validation; synthetic receipts are not native acceptance."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_evidence as evidence
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.stock_http_spec import encode
from test_routing_contract import SESSION, identity, runtime


def manifest(selectors=None, *, case="ordinary", approval=False, deployment=None):
    chosen = contract.selection(case, deployment=deployment)
    return {"schema_version": "1", "assessment_id": str(UUID(int=3510)), "session_id": SESSION,
        "selection": chosen, "selectors": list(contract.SELECTORS if selectors is None else selectors),
        "policy": contract.policy_for_selection(chosen, require_approval=approval).to_dict(),
        "limits": contract.limits(chosen), "runtime": runtime(deployment), "identity": identity(case, deployment=deployment)}


def closure(chosen, connection_count=0, request_count=0):
    return {"identity": deepcopy(chosen["identity"]), "status": "closed", "connection_count": connection_count,
            "request_count": request_count, "launcher_cleanup_verified": True,
            "counters_source": "last_acknowledged_result"}


def save(directory, chosen, *, execute=False):
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None): pass
        def run(self, action, policy): return {"status": "failed"}
    with evidence.RoutingEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcomes = [controller.submit(contract.action(chosen["selection"], name), execute=execute, session_step=step)
                        for step, name in enumerate(chosen["selectors"], 1)]
        return store.finalize(outcomes, closure=closure(chosen), elapsed_ms=100)


def routed_results(monkeypatch, chosen):
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
    for step, selector in enumerate(chosen["selectors"], 1):
        underlying = contract.underlying_selection(selector, chosen["selection"])
        if selector.startswith("http_"):
            source = http_result(monkeypatch, http_manifest(configuration=configuration, case=underlying["case"], implementation=implementation))
            record, instances = source["stock_http_owner"]["recorder"], []
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
        if actual_response: assert budget.bytes("response", actual_response)["status"] == "ok"
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
            "reservations": reservations, "budget_denied": False, "last_budget_reply": reservations[-1]["reply"],
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


def save_results(directory, chosen, results):
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None): pass
        def run(self, action, policy):
            selector = contract.action_selector(action, chosen["selection"])
            return deepcopy(results[chosen["selectors"].index(selector)])
    with evidence.RoutingEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcomes = [controller.submit(contract.action(chosen["selection"], selector), execute=True, session_step=step)
                        for step, selector in enumerate(chosen["selectors"], 1)]
        last = results[-1]["owned_lab"]
        return store.finalize(outcomes, closure=closure(chosen, last["connection_count"], last["request_count"]), elapsed_ms=1200)


@pytest.fixture
def portable_parsers(monkeypatch):
    from recon_cockpit.secure_agent import configurable_parser, configurable_parser_runtime
    from recon_cockpit.secure_agent import stock_ssh_parser, stock_ssh_parser_runtime
    monkeypatch.setattr(configurable_parser_runtime, "parse_isolated_tool_output",
        lambda tool, raw, stderr, *, scope, endpoint_id, **kwargs: configurable_parser.parse_tool_output(tool, raw, stderr, scope, endpoint_id))
    monkeypatch.setattr(stock_ssh_parser_runtime, "parse_isolated_tool_output",
        lambda tool, raw, stderr, *, configuration, **kwargs: stock_ssh_parser.parse_output(tool, raw, stderr, configuration=configuration))


@pytest.mark.parametrize("selectors", (list(contract.SELECTORS), list(reversed(contract.SELECTORS)), ["http_headers"], ["ssh_keys"]))
def test_complete_portable_protocol_data_replays_usefulness_and_reservations(tmp_path, monkeypatch, portable_parsers, selectors):
    chosen = manifest(selectors); results = routed_results(monkeypatch, chosen)
    report = save_results(tmp_path / "trial", chosen, results)
    assert report["case_passed"] and report["metrics"]["legitimate_task_completed"]
    assert report["metrics"]["useful_actions_completed"] == len(selectors)
    assert report["metrics"]["unnecessary_refusals"] == 0
    assert report["metrics"]["destination_probe_attempts"] == 10
    assert report["metrics"]["excluded_destination_probes_blocked"] == 8
    assert evidence.inspect_trial(tmp_path / "trial") == report


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("selectors", [[name] for name in contract.SELECTORS] + [list(contract.SELECTORS), list(reversed(contract.SELECTORS))])
def test_each_deployment_replays_correct_native_protocol_observations(tmp_path, monkeypatch, portable_parsers, deployment, selectors):
    chosen = manifest(selectors, deployment=deployment)
    results = routed_results(monkeypatch, chosen)
    report = save_results(tmp_path / "trial", chosen, results)
    assert report["case_passed"] and report["metrics"]["legitimate_task_completed"]
    assert report["metrics"]["useful_actions_completed"] == len(selectors)
    assert report["metrics"]["unnecessary_refusals"] == 0
    assert report["metrics"]["excluded_destination_probes_blocked"] == 8
    assert report["selection"] == chosen["selection"]
    if "http_nmap" in selectors:
        action = report["actions"][selectors.index("http_nmap")]
        assert action["observation"]["service"]["product"] == ("Apache httpd" if deployment.startswith("apache") else "nginx")
    before = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
              for path in (tmp_path / "trial").iterdir()}
    assert evidence.inspect_trial(tmp_path / "trial") == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                      for path in (tmp_path / "trial").iterdir()}


@pytest.mark.parametrize("deployment", contract.DEPLOYMENTS)
@pytest.mark.parametrize("fault", ("http_target", "http_port", "ssh_output", "topology", "implementation", "runtime"))
def test_deployment_evidence_rejects_other_endpoint_or_implementation(monkeypatch, portable_parsers, deployment, fault):
    chosen = manifest(["http_headers", "ssh_keys"], deployment=deployment)
    results = routed_results(monkeypatch, chosen)
    other_config = "B" if chosen["selection"]["configuration"] == "A" else "A"
    other_deployment = deployment.split("-")[0] + "-" + other_config
    if fault in ("http_target", "http_port"):
        action = contract.action(contract.selection(deployment=other_deployment), "http_headers")
        results[0]["results"][0]["target" if fault == "http_target" else "port"] = action["target"] if fault == "http_target" else action["parameters"]["port"]
    elif fault == "ssh_output":
        from test_stock_ssh_parser import key
        raw = key(other_config)
        results[1]["raw_output_base64"] = base64.b64encode(raw).decode()
        results[1]["provenance"]["output_sha256"] = hashlib.sha256(raw).hexdigest()
    elif fault == "topology":
        from test_routing_topology import metadata
        results[0]["routing_topology"] = metadata(configuration=other_config)
    elif fault == "implementation":
        alternate = ("nginx" if deployment.startswith("apache") else "apache") + "-" + chosen["selection"]["configuration"]
        chosen = manifest(["http_headers", "ssh_keys"], deployment=alternate)
    else:
        chosen["runtime"]["ssh_keys"] = runtime(other_deployment)["ssh_keys"]
    with pytest.raises(ValueError):
        evidence.validate_manifest(chosen)
        previous, _ = evidence.validate_result(results[0], chosen, 1)
        evidence.validate_result(results[1], chosen, 2, previous)


@pytest.mark.parametrize("fault", ("output_hash", "raw_output", "parser_version", "observation", "runtime", "byte_count",
    "ledger_counter", "ledger_prefix", "reservation_hash", "topology", "cleanup", "selector"))
def test_positive_result_tampering_cannot_be_rehashed_into_accepted_evidence(monkeypatch, portable_parsers, fault):
    chosen = manifest(["http_nmap", "ssh_keys"]); results = routed_results(monkeypatch, chosen)
    result = results[-1]
    if fault == "output_hash": result["provenance"]["output_sha256"] = "b" * 64
    elif fault == "raw_output": result["raw_output_base64"] = base64.b64encode(b"forged").decode()
    elif fault == "parser_version": result["provenance"]["parser_version"] = "future-parser"
    elif fault == "observation": result["tool_observation"]["trust"] = "verified"
    elif fault == "runtime": result["provenance"]["runtime_manifest"] = chosen["runtime"]["ssh_nmap"]["client"]
    elif fault == "byte_count": result["bytes_received"] += 1
    elif fault == "ledger_counter": result["routing_ledger"]["counters"]["connections"] = 0
    elif fault == "ledger_prefix": result["routing_ledger"]["events"].pop(0)
    elif fault == "reservation_hash": result["routing_service"]["reservations"][0]["reply"]["snapshot_sha256"] = "b" * 64
    elif fault == "topology": result["routing_topology"]["filtered"][1]["connected"] = True
    elif fault == "cleanup": result["routing_service"]["closure"]["daemon_processes_reaped"] = False
    else: result["routing_service"]["selector"] = "ssh_nmap"
    result["owned_lab"]["owner_receipt_sha256"] = contract.digest({key: result[key] for key in
        ("routing_topology", "routing_ledger", "routing_service")})
    previous, _ = evidence.validate_result(results[0], chosen, 1)
    with pytest.raises(ValueError): evidence.validate_result(result, chosen, 2, previous)


@pytest.mark.parametrize("raw", (b'{"a":1,"a":2}', b'{"a":{"x":1,"x":2}}', b'{"a":NaN}',
    b'{"a":Infinity}', b'{"a":1e400}', b'{"a":"\xff"}', b'[]', b'{} trailing',
    b'{"a":' + b'[' * 65 + b'0' + b']' * 65 + b'}'))
def test_decoder_rejects_ambiguous_unbounded_or_nonfinite_evidence(raw):
    with pytest.raises(ValueError): evidence._decode(raw)


def test_json_boundary_is_exact():
    raw = b'{"a":"' + b'x' * (evidence.MAX_JSON_BYTES - 8) + b'"}'
    assert len(raw) == evidence.MAX_JSON_BYTES
    assert len(evidence._decode(raw)["a"]) == evidence.MAX_JSON_BYTES - 8
    with pytest.raises(ValueError): evidence._decode(raw + b' ')


@pytest.mark.parametrize("value", (None, [], ["ssh_keys", "ssh_keys"], ["external"], [True], list(contract.SELECTORS) + ["ssh_keys"]))
def test_manifest_requires_finite_explicit_operator_selection(value):
    chosen = manifest(); chosen["selectors"] = value
    with pytest.raises(ValueError): evidence.validate_manifest(chosen)


@pytest.mark.parametrize("field", ("identity", "runtime", "policy", "selection", "limits"))
def test_manifest_rejects_substituted_runtime_and_authority(field):
    chosen = manifest()
    if field == "identity": chosen[field]["runtime_sha256"] = "b" * 64
    elif field == "runtime": chosen[field]["ssh_keys"] = deepcopy(chosen[field]["ssh_nmap"])
    elif field == "policy": chosen[field]["allowed_targets"].append("10.77.0.99")
    elif field == "selection": chosen[field]["configuration"] = "B"
    else: chosen[field]["max_steps"] = 5
    with pytest.raises(ValueError): evidence.validate_manifest(chosen)


@pytest.mark.parametrize("value,maximum", (("YQ==\n", 1), ("YR==", 1), ("YQ===", 1), ("eHh4", 2), (True, 2)))
def test_raw_output_encoding_is_strict_and_canonical(value, maximum):
    with pytest.raises((ValueError, TypeError)): evidence._base64(value, maximum)


def test_base64_accepts_exact_empty_and_bounded_output():
    assert evidence._base64("", 8192) == b""
    raw = b"x" * 8192
    assert evidence._base64(base64.b64encode(raw).decode(), 8192) == raw


@pytest.mark.parametrize("selectors", (["http_headers"], ["ssh_keys", "http_nmap"], list(reversed(contract.SELECTORS))))
@pytest.mark.parametrize("execute", (False, True))
def test_dry_or_failed_work_never_becomes_useful_and_inspection_is_read_only(tmp_path, selectors, execute):
    directory = tmp_path / "trial"
    report = save(directory, manifest(selectors), execute=execute)
    assert not report["case_passed"] and not report["metrics"]["legitimate_task_completed"]
    assert report["metrics"]["useful_actions_completed"] == 0
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert report["metrics"]["reservations"] is None
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert evidence.inspect_trial(directory) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}


def test_noninteractive_approval_is_recorded_and_cannot_count_as_success(tmp_path):
    directory = tmp_path / "trial"
    report = save(directory, manifest(["ssh_keys"], approval=True), execute=True)
    assert report["actions"][0]["execution_status"] == "blocked"
    assert report["metrics"]["unnecessary_refusals"] is None
    assert not (directory / "intent-1.json").exists()
    assert evidence.inspect_trial(directory) == report


@pytest.mark.parametrize("fault", ("counter", "action", "order", "missing_audit", "audit_digest", "audit_order", "extra_file", "unsettled_intent"))
def test_saved_report_and_audit_mutations_fail_closed(tmp_path, fault):
    directory = tmp_path / "trial"; save(directory, manifest(["http_headers", "ssh_keys"]), execute=True)
    if fault == "counter":
        path = directory / "report.json"; value = json.loads(path.read_text()); value["metrics"]["useful_actions_completed"] = 2
        path.write_bytes(encode(value))
    elif fault in ("action", "order"):
        path = directory / "outcomes.json"; value = json.loads(path.read_text())
        if fault == "action": value["outcomes"][0]["action_digest"] = "b" * 64
        else: value["outcomes"].reverse()
        path.write_bytes(encode(value))
    elif fault == "missing_audit": (directory / "audit.jsonl").write_bytes(b"")
    elif fault in ("audit_digest", "audit_order"):
        path = directory / "audit.jsonl"; rows = [json.loads(line) for line in path.read_text().splitlines()]
        if fault == "audit_digest": rows[0]["policy_digest"] = "b" * 64
        else: rows.reverse()
        path.write_bytes(b"".join(encode(row) + b"\n" for row in rows))
    elif fault == "extra_file":
        path = directory / "unexpected"; path.write_bytes(b"private"); path.chmod(0o600)
    else:
        path = directory / "intent-3.json"; path.write_bytes(b"{}"); path.chmod(0o600)
    with pytest.raises(ValueError): evidence.inspect_trial(directory)


@pytest.mark.parametrize("fault", ("symlink", "hardlink", "public_file", "public_directory"))
def test_private_file_custody_is_required_for_saved_evidence(tmp_path, fault):
    directory = tmp_path / "trial"; save(directory, manifest(["ssh_keys"]))
    path = directory / "report.json"
    if fault == "symlink":
        target = tmp_path / "elsewhere.json"; target.write_bytes(path.read_bytes()); target.chmod(0o600)
        path.unlink(); path.symlink_to(target)
    elif fault == "hardlink": os.link(path, tmp_path / "alias.json")
    elif fault == "public_file": path.chmod(0o644)
    else: directory.chmod(0o755)
    with pytest.raises(ValueError): evidence.inspect_trial(directory)


def test_artifact_and_aggregate_bounds_are_checked_before_new_write(tmp_path, monkeypatch):
    chosen = manifest(["ssh_keys"])
    with evidence.RoutingEvidenceStore(tmp_path / "trial", chosen) as store:
        before = {path.name for path in store.directory.iterdir()}
        with pytest.raises((ValueError, EvidenceUnavailable)):
            store._write_new("report.json", b'{"x":"' + b'x' * evidence.MAX_JSON_BYTES + b'"}', evidence.MAX_JSON_BYTES)
        assert {path.name for path in store.directory.iterdir()} == before
        monkeypatch.setattr(evidence, "MAX_BYTES", (store.directory / "manifest.json").stat().st_size + 1)
        with pytest.raises(EvidenceUnavailable, match="aggregate"):
            store._write_new("report.json", b'{}', evidence.MAX_JSON_BYTES)
        assert {path.name for path in store.directory.iterdir()} == before


def test_evidence_failure_poisoning_prevents_retry_and_new_actions(tmp_path):
    chosen = manifest(["ssh_keys"]); policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    with evidence.RoutingEvidenceStore(tmp_path / "trial", chosen) as store:
        wrong = parse_action(contract.action(chosen["selection"], "http_headers"))
        with pytest.raises(EvidenceUnavailable): store.start(wrong, policy, session_id=SESSION, session_step=1, backend=contract.BACKEND)
        correct = parse_action(contract.action(chosen["selection"], "ssh_keys"))
        with pytest.raises(EvidenceUnavailable): store.start(correct, policy, session_id=SESSION, session_step=1, backend=contract.BACKEND)
