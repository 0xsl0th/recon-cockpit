"""Portable receipt mapping regressions; fixtures do not claim native execution."""

from copy import deepcopy
import json

import pytest

import test_name_tls_boundaries_linux as gates
from test_name_tls_topology import metadata


def run_gate(tmp_path, operation, configuration, *, denial="other_operation_endpoint", value=None, flag=False):
    gate = next(row for row in gates.CASES if row["configuration"] == configuration
                and row["case"] == operation + "/" + denial)
    result = {"name_tls_topology": metadata(configuration) if value is None else value,
              "boundary_checks": {"other_service_blocked": flag},
              "name_tls_service": {"recorder": {"admitted_connections": 1}}}
    report = {"closure": {"launcher_cleanup_verified": True}}
    fixture = lambda _: (tmp_path / "synthetic-trial", {}, {operation: result}, report, {})
    gates.test_actual_name_tls_boundary_witness(gate, fixture, tmp_path, lambda *_: None)
    receipt = json.loads((tmp_path / "gate-receipt.json").read_text())
    assert receipt["gate_id"] == gate["id"]
    return receipt["witness"]


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("operation,endpoint", (("http", "tls"), ("tls", "http")))
def test_other_operation_receipt_selects_distinct_denial_and_reachable_baseline(tmp_path, configuration, operation, endpoint):
    value = metadata(configuration)
    witness = run_gate(tmp_path, operation, configuration, value=value)
    assert witness["operation"] == operation and witness["endpoint"] == endpoint
    assert witness["baseline"] == {"client": operation, "endpoint": endpoint, "connected": True}
    assert witness["filtered"] == {"client": operation, "endpoint": endpoint, "connected": False}
    assert witness["listener"] == value["listeners"][endpoint]
    assert witness["client_namespace"] == value["networks"][operation + "_client"]
    assert witness["listener_namespace"] == value["networks"]["web_frontend"]
    assert witness["user_namespace"] == value["user"]
    assert witness["topology_sha256"] == value["topology_sha256"]
    detached = deepcopy(witness)
    value["listeners"][endpoint]["inode"] += 100
    assert witness == detached


@pytest.mark.parametrize("operation", ("http", "tls"))
@pytest.mark.parametrize("mutation", ("baseline_unreachable", "filter_connected", "resolver_substituted",
    "listener_endpoint", "listener_namespace", "client_namespace", "listener_inode"))
def test_other_operation_mapping_rejects_tampered_physical_witness(tmp_path, operation, mutation):
    value = metadata()
    endpoint = {"http": "tls", "tls": "http"}[operation]
    baseline = next(row for row in value["baselines"] if row["client"] == operation and row["endpoint"] == endpoint)
    filtered = next(row for row in value["filtered"] if row["client"] == operation and row["endpoint"] == endpoint)
    if mutation == "baseline_unreachable": baseline["connected"] = False
    elif mutation == "filter_connected": filtered["connected"] = True
    elif mutation == "resolver_substituted": filtered["endpoint"] = "dns"
    elif mutation == "listener_endpoint": value["listeners"][endpoint]["local"] = value["listeners"]["dns"]["local"]
    elif mutation == "listener_namespace": value["listeners"][endpoint]["netns_cookie"] = value["listeners"]["dns"]["netns_cookie"]
    elif mutation == "client_namespace": value["networks"][operation + "_client"] = value["networks"]["dns_client"]
    elif mutation == "listener_inode": value["listeners"][endpoint]["inode"] = value["listeners"]["dns"]["inode"]
    with pytest.raises(ValueError, match="name_tls_topology"):
        run_gate(tmp_path, operation, "A", value=value, flag=True)
    assert not (tmp_path / "gate-receipt.json").exists()


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("operation", ("http", "tls"))
def test_resolver_as_service_still_requires_actual_client_flag(tmp_path, configuration, operation):
    with pytest.raises(AssertionError):
        run_gate(tmp_path, operation, configuration, denial="resolver_as_service", flag=False)
    witness = run_gate(tmp_path, operation, configuration, denial="resolver_as_service", flag=True)
    assert witness == {"operation": operation, "boundary": "other_service_blocked"}
