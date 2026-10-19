"""Fifty-six architecture assertions over actual sealed O4 worker witnesses.

Each configuration executes a complete production O4 trial once. Gates refer to
distinct kernel witnesses in that retained physical run; they never substitute
portable policy assertions for a successful native execution.
"""

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent import name_tls as diagnostic
from recon_cockpit.secure_agent import name_tls_daemon as daemon
from recon_cockpit.secure_agent import name_tls_topology_spec as topology
from recon_cockpit.secure_agent.name_tls_evidence import inspect_trial

pytestmark = pytest.mark.integration
GATES = json.loads((Path(__file__).parents[1] / "docs/stage3-name-tls-native-gates.json").read_text())["architecture"]
RUNTIME = {"dnsmasq_single_process_pre_dropped_uid_no_tcp_fork",
    "dnsmasq_unused_udp_listener_cannot_receive_client_traffic", "nginx_single_process_exact_two_listeners",
    "dig_threads_bounded_to_16_and_process_fork_denied", "openssl_one_thread_and_no_process_fork",
    "dns_client/server_key_and_daemon_runtime_absent", "http_client/server_key_and_daemon_runtime_absent",
    "tls_client/server_key_and_daemon_runtime_absent", "frontend_new_socket_exec_and_process_creation_denied",
    "daemon_sealed_runtime_and_observed_readiness_images_match_partition"}
CASES = [row for row in GATES if
    row["group"] == "transport_denial" and not row["case"].endswith("second_connection")
    or row["group"] == "native_process_runtime_and_mount" and row["case"] in RUNTIME
    or row["case"] == "exact_six_networks_routes_firewalls_and_live_denied_listeners"]
assert len(CASES) == 56 and len({row["id"] for row in CASES}) == 56


@pytest.fixture(scope="module")
def witnessed_trials(tmp_path_factory):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Name/TLS architecture witnesses")
    assert sys.platform == "linux" and os.geteuid() != 0
    cached = {}
    def get(configuration):
        if configuration not in cached:
            directory = tmp_path_factory.mktemp("name-tls-boundaries-" + configuration) / "trial"
            report = diagnostic.run_trial(directory, configuration=configuration, case="O4",
                execute=True, unattended_owned_lab_test=True)
            assert report["case_passed"] is True, report
            before = {path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                      for path in directory.iterdir()}
            assert inspect_trial(directory) == report
            assert before == {path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                              for path in directory.iterdir()}
            manifest = json.loads((directory / "manifest.json").read_text())
            rows = [json.loads((directory / f"result-{step}.json").read_text()) for step in range(1, 4)]
            by_operation = {row["name_tls_service"]["recorder"]["operation"]: row for row in rows}
            assert set(by_operation) == {"dns", "http", "tls"}
            assert all(row["status"] == "succeeded" for row in rows)
            cached[configuration] = directory, manifest, by_operation, report, before
        return cached[configuration]
    return get


def _native_checks(result, manifest, operation):
    service = result["name_tls_service"]
    native = service["native_ready"]
    daemon.validate_daemon_ready(native, manifest["runtime"]["roles"][daemon.selected_role(operation)],
        service["daemon_ready"]["namespaces"], service["daemon_mapping"], operation)
    assert service["daemon_ready"]["namespace_identity"]["uid"] == 65534
    assert service["daemon_ready"]["namespace_identity"]["gid"] == 65534
    assert service["closure"]["daemon_processes_reaped"] is True
    assert service["closure"]["action_connections_closed"] is True
    if operation in ("dns", "tls"):
        observed = result["client_observation"]
        daemon.validate_client_ready(observed["native_ready"], manifest["runtime"]["roles"][operation + "_client"],
            observed["namespaces"], observed["mapping"])
    return native


def _other_operation_witness(result, operation, configuration):
    """Select the distinct observed HTTP-to-TLS or TLS-to-HTTP denial."""
    endpoint = {"http": "tls", "tls": "http"}[operation]
    value = topology.validate_metadata(result["name_tls_topology"], configuration=configuration)
    baseline, filtered = (next(row for row in value[phase]
        if row["client"] == operation and row["endpoint"] == endpoint)
        for phase in ("baselines", "filtered"))
    assert baseline["connected"] is True and filtered["connected"] is False
    return {"operation": operation, "endpoint": endpoint, "source": "topology_connection_witness",
        "topology_sha256": value["topology_sha256"], "user_namespace": value["user"],
        "client_namespace": value["networks"][operation + "_client"],
        "listener_namespace": value["networks"][topology.frontend_role(endpoint)],
        "listener": value["listeners"][endpoint], "baseline": baseline, "filtered": filtered}


@pytest.mark.parametrize("gate", CASES, ids=[row["id"] for row in CASES])
def test_actual_name_tls_boundary_witness(gate, witnessed_trials, tmp_path, record_property):
    directory, manifest, results, report, commitments = witnessed_trials(gate["configuration"])
    case = gate["case"]
    if gate["group"] == "transport_denial":
        operation, denial = case.split("/")
        assert results[operation]["name_tls_service"]["recorder"]["admitted_connections"] == 1
        if denial == "other_operation_endpoint" and operation in ("http", "tls"):
            witness = _other_operation_witness(results[operation], operation, gate["configuration"])
        else:
            field = {"wrong_port": "wrong_port_blocked", "other_operation_endpoint": "other_service_blocked",
                     "resolver_as_service": "other_service_blocked", "excluded_endpoint": "excluded_blocked",
                     "udp": "udp_blocked", "ipv6": "ipv6_blocked"}[denial]
            assert results[operation]["boundary_checks"][field] is True
            witness = {"operation": operation, "boundary": field}
    elif case == "exact_six_networks_routes_firewalls_and_live_denied_listeners":
        value = results["dns"]["name_tls_topology"]
        topology.validate_metadata(value, configuration=gate["configuration"])
        assert len(set(value["networks"].values())) == 6 and len(value["listeners"]) == 9
        assert sum(not row["connected"] for row in value["filtered"]) == 24
        assert all(row["connected"] for row in value["baselines"])
        assert value["descriptor_custody"] == {"before_export": 25, "steady": 19}
        witness = {"topology_sha256": value["topology_sha256"], "denied_connections": 24,
                   "descriptor_custody": value["descriptor_custody"]}
    elif case.endswith("server_key_and_daemon_runtime_absent"):
        operation = case.split("_", 1)[0]
        assert results[operation]["boundary_checks"]["owner_material_absent"] is True
        witness = {"operation": operation, "boundary": "owner_material_absent"}
    elif case == "frontend_new_socket_exec_and_process_creation_denied":
        for operation, result in results.items():
            ready = result["name_tls_service"]["frontend_ready"]
            assert all(ready["checks"][key] is True for key in (
                "socket_creation_blocked", "process_creation_blocked", "exec_blocked", "namespace_creation_blocked"))
            assert ready["payload_identity"]["uid"] == ready["payload_identity"]["gid"] == 65534
        witness = {"roles": sorted(results), "boundaries": ["socket", "process", "exec", "namespace"]}
    elif case == "dig_threads_bounded_to_16_and_process_fork_denied" or case == "openssl_one_thread_and_no_process_fork":
        operation = "dns" if case.startswith("dig_") else "tls"
        _native_checks(results[operation], manifest, operation)
        witness = results[operation]["client_observation"]["native_ready"]
        assert results[operation]["boundary_checks"]["fork_blocked"] is True
        assert 1 <= witness["observed_tasks"] <= (16 if operation == "dns" else 1)
    elif case == "daemon_sealed_runtime_and_observed_readiness_images_match_partition":
        witness = {operation: _native_checks(result, manifest, operation) for operation, result in results.items()}
        source = next(row for row in manifest["runtime"]["python_sources"]["files"]
                      if row["destination"].endswith("/name_tls_daemon_worker.py"))
        # Ready is emitted only after these actual EPERM probes have completed
        # on the handed socket under the filter inherited by the native image.
        # This identifies pre-exec wrapper checks, not native syscall tracing.
        witness["mandatory_pre_exec_connection_denials"] = {
            "checks": ["connect", "sendto_MSG_FASTOPEN", "sendmsg_MSG_FASTOPEN", "sendmmsg_MSG_FASTOPEN"],
            "expected_errno": "EPERM", "socket_still_unconnected": True,
            "source_sha256": source["sha256"], "observation_scope": "sealed_pre_exec_wrapper"}
    else:
        operation = "http" if case.startswith("nginx_") else "dns"
        witness = _native_checks(results[operation], manifest, operation)
        assert witness["threads"] == witness["observed_tasks"] == 1
        if case.startswith("nginx_"):
            assert len(witness["tcp_listeners"]) == 2 and not witness["udp_listeners"]
        else:
            assert len(witness["tcp_listeners"]) == len(witness["udp_listeners"]) == 1
            assert results["dns"]["boundary_checks"]["udp_blocked"] is True
            assert results["dns"]["name_tls_service"]["recorder"]["daemon_connects"] == 1
    receipt = {"gate_id": gate["id"], "case_passed": True, "physical_trial": str(directory),
               "trial_commitments": commitments, "witness": witness,
               "launcher_cleanup_verified": report["closure"]["launcher_cleanup_verified"],
               "actual_provider_calls": 0, "actual_cost_microusd": 0}
    path = tmp_path / "gate-receipt.json"
    path.write_text(json.dumps(receipt, sort_keys=True))
    path.chmod(0o600)
    assert receipt["launcher_cleanup_verified"] is True
    record_property("gate_id", gate["id"])
    record_property("case_passed", True)
    record_property("physical_trial", str(directory))
    record_property("actual_provider_calls", 0)
