"""Replay and acceptance criteria using explicit portable peer doubles only."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import stock_http_production_evidence as evidence, stock_http_production_contract as contract, stock_http_spec as spec
from recon_cockpit.secure_agent import configurable_parser as parser, configurable_parser_runtime as isolated
from recon_cockpit.secure_agent import stock_http_recorder as recorder
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller, result_metadata
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.stock_http_owner_worker import BOUNDS
from recon_cockpit.secure_agent.stock_http_client_runtime import boundary_names
from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
from test_stock_http_production_authority import runtime, identity, SESSION
from test_secure_network_tools_b7_parser import service_xml
from test_stock_http_recorder import Harness


def manifest(configuration="A", case="O1", *, implementation="apache", approval=False):
    selected = contract.selection(implementation, configuration, case)
    return {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": SESSION,
        "selection": selected, "policy": contract.policy_for_selection(selected, require_approval=approval).to_dict(),
        "limits": contract.limits(selected), "runtime": runtime(implementation, configuration, case), "identity": identity(implementation, configuration, case)}


def daemon_response(configuration, case, implementation="apache"):
    status = 404 if case == "O3" else 302 if case == "O4" else 200
    body = spec.response_body(case) or b"<html>Actual stock server redirect response</html>"
    extra = b""
    if case in ("O1", "R2", *spec.NEGATIVE_CASES):
        extra += b"Content-Security-Policy: default-src 'none'\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n"
    if case == "O4":
        other = spec.action("B" if configuration == "A" else "A", "O1")
        extra += f'Location: http://{other["target"]}:{other["parameters"]["port"]}/\r\n'.encode()
    server = ("nginx" if case == "O6" else "nginx/1.28.0") if implementation == "nginx" else ("Apache" if case == "O6" else "Apache/2.4.65 (Debian)")
    return (f"HTTP/1.1 {status} Test\r\nServer: {server}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n".encode()
            + extra + b"\r\n" + body)


def rebind(result):
    owner = result["stock_http_owner"]
    result["owned_lab"]["owner_receipt_sha256"] = hashlib.sha256(spec.encode(owner)).hexdigest()
    result["stock_http_closure"]["recorder"] = deepcopy(owner["recorder"])


def peer_result(monkeypatch, selected_manifest, *, original=None):
    selected = selected_manifest["selection"]
    configuration, case = selected["configuration"], selected["case"]
    h = Harness(monkeypatch, configuration, case)
    try:
        h.arm()
        h.client(spec.request_bytes(configuration, case))
        h.reply(original or daemon_response(configuration, case, selected["implementation"]))
        if case == "N3":
            h.until(lambda: h.service.active is not None and h.service.active["stage"] == "withhold")
            h.clock = h.service.action_deadline
            h.step()
        else:
            h.until(lambda: h.service.active is None)
        h.service.close()
        ledger = h.service.snapshot()
    finally:
        h.close()
    action = contract.action(selected)
    status = {"N2": "failed", "N3": "timeout", "N4": "output_limit"}.get(case, "succeeded")
    result = {"status": status, "results": [], "truncated": status == "output_limit",
        "boundary_checks": dict.fromkeys(boundary_names(selected), True), "timing": {
            "owner_startup_ms": 10, "client_startup_ms": 20, "action_elapsed_ms": 50, "owner_teardown_ms": 5},
        "tool_observation": None, "backend": contract.BACKEND}
    owner = {"connection_count": ledger["connections_admitted"], "request_count": ledger["requests_delivered"], "recorder": ledger,
        "owner": {"recorder_namespaces": {name: name + ":[200]" for name in ("user", "net", "mnt", "pid")},
            "daemon_namespaces": {name: name + ":[300]" for name in ("user", "net", "mnt", "pid")},
            "witness_baselines": True, "recorder_bounds": dict(BOUNDS), "daemon_bounds": dict(BOUNDS),
            "private_socket_unmounted_from_client": True, "daemon_ready": True}}
    implementation = selected["implementation"]
    owner["owner"].update(implementation=implementation,
        daemon_namespace_identity={"uid": 0 if implementation == "nginx" else 65534,
                                   "gid": 0 if implementation == "nginx" else 65534, "supplementary_groups": []},
        private_transport=({"kind": "unix_socket", "listener_verified": True, "descriptor": None}
            if implementation == "nginx" else {"kind": "namespace_tcp_descriptor", "listener_verified": True,
            "descriptor": {"daemon_netns_cookie": 100, "recorder_netns_cookie": 200, "inode": 300,
                           "unconnected_at_transfer": True, "transferred_once": True,
                           "daemon_duplicate_closed": True, "connect_denied_in_daemon": True}}))
    result["stock_http_owner"] = owner
    result["owned_lab"] = {"identity": selected_manifest["identity"], "connection_count": owner["connection_count"],
        "request_count": owner["request_count"], "owner_receipt_sha256": hashlib.sha256(spec.encode(owner)).hexdigest()}
    result["stock_http_closure"] = {"identity": selected_manifest["identity"], "status": "closed", "started": True,
        "connection_count": owner["connection_count"], "request_count": owner["request_count"], "recorder": deepcopy(ledger),
        "processes_reaped": True, "namespace_descriptors_closed": True}
    if case in ("O5", "O6"):
        service = {"name": "http", "method": "probed", "conf": "10"}
        if case == "O5":
            service.update(product="nginx" if implementation == "nginx" else "Apache httpd",
                           version="1.28.0" if implementation == "nginx" else "2.4.65")
        raw = service_xml(service).replace(b"127.0.0.1", action["target"].encode()).replace(b"8080", str(action["parameters"]["port"]).encode())
        result.update(raw_output_base64=base64.b64encode(raw).decode(), raw_stderr_base64="",
            provenance={"runtime_sha256": manifest_digest(selected_manifest["runtime"]["client"]),
                "runtime_manifest": selected_manifest["runtime"]["client"], "output_sha256": hashlib.sha256(raw).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "parser_version": parser.parser_version(action["tool_id"]),
                "exit_code": 0, "stop_reason": None})
    else:
        raw = bytes.fromhex(ledger["transformed_response_hex"])[:2048]
        result["results"] = [{"target": action["target"], "port": action["parameters"]["port"], "bytes_received": len(raw),
            "truncated": result["truncated"], "raw_response": base64.b64encode(raw).decode(), "response_sha256": hashlib.sha256(raw).hexdigest()}]
    result["bytes_received"] = len(raw)
    if status == "succeeded":
        try:
            result["tool_observation"] = parser.parse_tool_output(action["tool_id"], raw, b"", contract.scope(selected), "http")
        except ValueError:
            pass
    return result


@pytest.fixture(autouse=True)
def portable_parser(monkeypatch):
    # Exercise the real pure parser here; isolated parser/native Linux proof is
    # separate. Never label these peer doubles as the accepted native corpus.
    monkeypatch.setattr(isolated, "parse_isolated_tool_output", lambda tool, raw, stderr, *, scope, endpoint_id, **kwargs:
                        parser.parse_tool_output(tool, raw, stderr, scope, endpoint_id))


def save(directory, selected_manifest, result, *, execute=True):
    policy = contract.validate_policy(selected_manifest["policy"], selected_manifest["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None):
            pass
        def run(self, action, policy):
            return deepcopy(result)
    with evidence.StockHttpProductionEvidenceStore(directory, selected_manifest) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcome = controller.submit(contract.action(selected_manifest["selection"]), execute=execute, session_step=1)
        report = store.finalize(outcome, elapsed_ms=100)
    return report


def load(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.write_bytes(spec.encode(value))


@pytest.mark.parametrize("implementation", ("nginx", "apache"))
@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_each_declared_case_replays_with_exact_useful_or_fault_result(tmp_path, monkeypatch, implementation, configuration, case):
    chosen = manifest(configuration, case, implementation=implementation)
    result = peer_result(monkeypatch, chosen)
    directory = tmp_path / "trial"
    report = save(directory, chosen, result)
    assert report["case_passed"] is True and report["native_response_verified"] is True
    assert report["metrics"]["expected_negative"] == (case in spec.NEGATIVE_CASES)
    assert report["metrics"]["useful_completion"] == (case not in spec.NEGATIVE_CASES)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert evidence.inspect_trial(directory) == report
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert before == after
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())


@pytest.mark.parametrize("field", ["owner_startup_ms", "client_startup_ms", "action_elapsed_ms", "owner_teardown_ms"])
@pytest.mark.parametrize("invalid", [None, True, -1, 60001])
def test_all_phase_timings_are_required_bounded_milliseconds(monkeypatch, field, invalid):
    chosen = manifest()
    result = peer_result(monkeypatch, chosen)
    if invalid is None:
        del result["timing"][field]
    else:
        result["timing"][field] = invalid
    with pytest.raises(ValueError, match="invalid_stock_timing"):
        evidence.validate_result(result, chosen)


@pytest.mark.parametrize("approval,execute,status", [(False, False, "dry_run"), (True, False, "dry_run"), (True, True, "blocked")])
def test_metadata_and_required_approval_refusal_are_never_native_success(tmp_path, approval, execute, status):
    chosen = manifest(approval=approval)
    report = save(tmp_path / "trial", chosen, None, execute=execute)
    assert report["execution_status"] == status and not report["case_passed"]
    assert not report["native_response_verified"]
    assert evidence.inspect_trial(tmp_path / "trial") == report


@pytest.mark.parametrize("status", ["failed", "blocked", "cancelled", "timeout"])
def test_failed_execution_with_no_owner_response_is_retained_and_inconclusive(tmp_path, status):
    chosen = manifest()
    report = save(tmp_path / "trial", chosen, {"status": status})
    assert not report["case_passed"] and not report["native_response_verified"]
    assert evidence.inspect_trial(tmp_path / "trial") == report


@pytest.mark.parametrize("mutation", ["missing_transform", "missing_daemon_response", "fatal_reason", "short_client", "extra_denial"])
def test_negative_case_requires_actual_selected_fault_and_complete_accounting(tmp_path, monkeypatch, mutation):
    chosen = manifest(case="N1")
    result = peer_result(monkeypatch, chosen)
    ledger = result["stock_http_owner"]["recorder"]
    if mutation in ("missing_transform", "missing_daemon_response"):
        kind = "transform" if mutation == "missing_transform" else "daemon_response"
        ledger["events"] = [row for row in ledger["events"] if row["kind"] != kind]
    elif mutation == "fatal_reason":
        ledger["terminal_reason"] = "io_failure"
    elif mutation == "short_client":
        result.update(status="failed", bytes_received=0, tool_observation=None)
        result["results"][0].update(bytes_received=0, raw_response="", response_sha256=hashlib.sha256(b"").hexdigest())
    else:
        ledger["connections_attempted"] += 1
        ledger["connections_denied"] += 1
        ledger["events"].extend([{ "kind": kind, "elapsed_ms": 60, "connection": 2, "bytes": 0, "reason": reason}
            for kind, reason in (("attempt", ""), ("deny", "request_limit"))])
    rebind(result)
    report = save(tmp_path / "trial", chosen, result)
    assert report["case_passed"] is False


@pytest.mark.parametrize("change", ["split", "delay"])
def test_fragmentation_requires_exact_split_boundaries_and_spacing(tmp_path, monkeypatch, change):
    chosen = manifest(case="R2")
    result = peer_result(monkeypatch, chosen)
    writes = result["stock_http_owner"]["recorder"]["writes"]
    if change == "delay":
        writes[1]["elapsed_ms"] = writes[0]["elapsed_ms"]
    else:
        writes[0]["bytes"] += 1
        writes[1]["offset"] += 1
        writes[1]["bytes"] -= 1
    rebind(result)
    assert save(tmp_path / "trial", chosen, result)["case_passed"] is False


def test_redirect_requires_exact_other_configuration_location(tmp_path, monkeypatch):
    chosen = manifest(case="O4")
    raw = daemon_response("A", "O4").replace(b"http://172.23.0.10:18080/", b"http://10.77.0.99:8080/")
    result = peer_result(monkeypatch, chosen, original=raw)
    assert save(tmp_path / "trial", chosen, result)["case_passed"] is False


@pytest.mark.parametrize("change", [lambda r: r.update(extra=True), lambda r: r.update(session_step=True),
    lambda r: r.update(tool_id="curl"), lambda r: r.update(target="10.77.0.99"),
    lambda r: r.update(reasons=["fabricated"]), lambda r: r.update(result_metadata={}),
    lambda r: r.update(approval_reference="a" * 48)])
def test_outcome_changes_are_rejected_even_with_saved_report_unchanged(tmp_path, monkeypatch, change):
    chosen = manifest()
    save(tmp_path / "trial", chosen, peer_result(monkeypatch, chosen))
    path = tmp_path / "trial" / "outcome.json"
    value = load(path)
    change(value["outcome"])
    write(path, value)
    with pytest.raises(ValueError):
        evidence.inspect_trial(path.parent)


@pytest.mark.parametrize("change", [lambda events: events.pop(), lambda events: events.reverse(),
    lambda events: events[1].update(event_id=events[0]["event_id"]),
    lambda events: events[0].update(extra=True), lambda events: events[0].update(timestamp="yesterday"),
    lambda events: events[0].update(source="other"), lambda events: events[-1].update(result_metadata={}),
    lambda events: events[0].update(reasons=["fake"]), lambda events: events[0].update(decision="deny")])
def test_audit_shape_identity_payload_and_order_are_replayed_strictly(tmp_path, monkeypatch, change):
    chosen = manifest()
    save(tmp_path / "trial", chosen, peer_result(monkeypatch, chosen))
    path = tmp_path / "trial" / "audit.jsonl"
    events = [json.loads(line) for line in path.read_bytes().splitlines()]
    change(events)
    path.write_bytes(b"".join(spec.encode(event) + b"\n" for event in events))
    with pytest.raises(ValueError):
        evidence.inspect_trial(path.parent)


@pytest.mark.parametrize("name", ["report.json", "outcome.json", "result.json", "intent.json", "manifest.json", "audit.jsonl"])
def test_symlinked_private_artifacts_refused(tmp_path, monkeypatch, name):
    chosen = manifest()
    directory = tmp_path / "trial"
    save(directory, chosen, peer_result(monkeypatch, chosen))
    path = directory / name
    outside = tmp_path / name
    path.rename(outside)
    path.symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        evidence.inspect_trial(directory)


@pytest.mark.parametrize("case", ["O5", "O6"])
def test_native_identification_cannot_invent_a_version_or_product_absent_from_response(tmp_path, monkeypatch, case):
    chosen = manifest(case=case)
    result = peer_result(monkeypatch, chosen)
    raw = base64.b64decode(result["raw_output_base64"])
    if case == "O5":
        raw = raw.replace(b'version="2.4.65"', b'version="9.99.0"')
    else:
        raw = raw.replace(b'<service name="http"', b'<service product="Apache httpd" version="2.4.0" name="http"')
    result["raw_output_base64"] = base64.b64encode(raw).decode()
    result["bytes_received"] = len(raw)
    result["provenance"]["output_sha256"] = hashlib.sha256(raw).hexdigest()
    result["tool_observation"] = parser.parse_output(parser.NMAP, raw, scope=contract.scope(chosen["selection"]), endpoint_id="http")
    assert save(tmp_path / "trial", chosen, result)["case_passed"] is False


def test_aggregate_evidence_cap_is_checked_before_json_or_audit_parsing(tmp_path, monkeypatch):
    chosen = manifest()
    directory = tmp_path / "trial"
    save(directory, chosen, peer_result(monkeypatch, chosen))
    (directory / "audit.jsonl").write_bytes(b"x" * evidence.MAX_BYTES)
    with pytest.raises(ValueError, match="aggregate_limit"):
        evidence.inspect_trial(directory)


def test_json_artifact_write_cannot_exceed_replay_parser_limit(tmp_path):
    chosen = manifest()
    with evidence.StockHttpProductionEvidenceStore(tmp_path / "trial", chosen) as store:
        with pytest.raises(evidence.EvidenceUnavailable, match="evidence_limit"):
            store._write_new("intent.json", b"x" * (evidence.MAX_JSON_BYTES + 1), evidence.MAX_BYTES)
    assert not (tmp_path / "trial" / "intent.json").exists()


@pytest.mark.parametrize("implementation", ("nginx", "apache"))
@pytest.mark.parametrize("case", ("O1", "O3", "O4", "O5", "O6", "N1"))
def test_actual_response_must_bind_selected_server_even_for_negative_cases(tmp_path, monkeypatch, implementation, case):
    chosen = manifest(case=case, implementation=implementation)
    other = "apache" if implementation == "nginx" else "nginx"
    result = peer_result(monkeypatch, chosen, original=daemon_response("A", case, other))
    report = save(tmp_path / "trial", chosen, result)
    assert report["case_passed"] is False and report["native_response_verified"] is False


@pytest.mark.parametrize("case", ("O1", "O3", "O4", "N1", "N3", "N4", "N5"))
def test_wrong_original_status_never_passes_even_when_fault_matches(tmp_path, monkeypatch, case):
    chosen = manifest(case=case)
    raw = daemon_response("A", case)
    _, rest = raw.split(b"\r\n", 1)
    # Use another otherwise supported status so the recorder still completes
    # the selected fault; case-specific grading must detect the mismatch.
    status = b"302" if case == "O3" else b"404"
    result = peer_result(monkeypatch, chosen, original=b"HTTP/1.1 " + status + b" Test\r\n" + rest)
    report = save(tmp_path / "trial", chosen, result)
    assert report["case_passed"] is False and report["native_response_verified"] is False


@pytest.mark.parametrize("change", [
    lambda owner: owner.update(implementation="nginx"),
    lambda owner: owner["daemon_namespace_identity"].update(uid=0),
    lambda owner: owner["daemon_namespace_identity"].update(supplementary_groups=[0]),
    lambda owner: owner["private_transport"].update(listener_verified=False),
    lambda owner: owner["private_transport"]["descriptor"].update(daemon_netns_cookie=200),
    lambda owner: owner["private_transport"]["descriptor"].update(unconnected_at_transfer=False),
    lambda owner: owner["private_transport"]["descriptor"].update(daemon_duplicate_closed=False),
    lambda owner: owner["private_transport"]["descriptor"].update(connect_denied_in_daemon=False),
])
def test_apache_private_transport_proof_is_required_even_after_rehash(monkeypatch, change):
    chosen = manifest()
    result = peer_result(monkeypatch, chosen)
    change(result["stock_http_owner"]["owner"])
    rebind(result)
    with pytest.raises(ValueError):
        evidence.validate_result(result, chosen)


@pytest.mark.parametrize("change", [
    lambda receipt: receipt.update(namespace_descriptors_closed=False),
    lambda receipt: receipt.update(processes_reaped=False),
    lambda receipt: receipt["identity"].update(implementation="nginx"),
])
def test_production_result_requires_closed_bound_owner(monkeypatch, change):
    chosen = manifest()
    result = peer_result(monkeypatch, chosen)
    change(result["stock_http_closure"])
    with pytest.raises(ValueError):
        evidence.validate_result(result, chosen)


def test_accepted_diagnostic_bundle_cannot_be_relabelled_as_production(monkeypatch):
    from test_stock_http_evidence import manifest as diagnostic_manifest
    from recon_cockpit.secure_agent import stock_http_evidence as diagnostic_evidence
    with pytest.raises(ValueError):
        evidence.validate_manifest(diagnostic_manifest())
    with pytest.raises(ValueError):
        diagnostic_evidence.validate_manifest(manifest(implementation="nginx"))


def test_hostile_body_stays_retained_data_without_additional_request(tmp_path, monkeypatch):
    chosen = manifest(case="R1")
    result = peer_result(monkeypatch, chosen)
    report = save(tmp_path / "trial", chosen, result)
    assert spec.HOSTILE_BODY in bytes.fromhex(result["stock_http_owner"]["recorder"]["original_response_hex"])
    assert report["case_passed"] and report["metrics"]["requests_delivered"] == 1
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert evidence.inspect_trial(tmp_path / "trial") == report
