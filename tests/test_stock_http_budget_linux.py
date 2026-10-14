"""Privately instrumented clients test fixed stock-owner admission budgets.

These are adversarial boundary probes, not ordinary compatibility evidence.
They preserve READY/GO, confinement, audit and admission, and target only the
single selected owned endpoint. The unmodified 26-case corpus stays separate.
"""

import json
import os
import sys

import pytest

from recon_cockpit.secure_agent import stock_http_diagnostic as diagnostic
from recon_cockpit.secure_agent import stock_http_spec as spec
from recon_cockpit.secure_agent.stock_http_backend import AuthorizedStockHttpBackend
from recon_cockpit.secure_agent.stock_http_evidence import inspect_trial
from recon_cockpit.secure_agent.stock_http_lab import StockHttpLab
from test_secure_fixture_launcher_linux import instrument


def _probe_source(source, case):
    if case == "O1":
        anchor = '            result = probe_headers_at_deadline(request, deadline)'
        replacement = anchor + '''
            # The first real exchange remains intact; try the same exact GET
            # again through the selected TCP endpoint, never the daemon socket.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as extra:
                extra.settimeout(worker._remaining(deadline, 0.2))
                extra.connect((request["target"], request["parameters"]["port"]))
                try:
                    extra.sendall(spec.request_bytes(selected["configuration"], selected["case"]))
                    if extra.recv(1):
                        raise RuntimeError("stock_extra_request_produced_response")
                except (BrokenPipeError, ConnectionResetError):
                    pass
'''
    elif case == "O5":
        anchor = '        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))'
        replacement = '''        # Three empty exchanges consume the closed Nmap-profile connection
        # budget. A fourth connection must be rejected before any daemon GET.
        # No native Nmap completion is claimed by this instrumented probe.
        for index in range(4):
            if index:
                time.sleep(min(0.27, worker._remaining(deadline, 0.27)))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as extra:
                extra.settimeout(worker._remaining(deadline, 0.2))
                extra.connect((request["target"], request["parameters"]["port"]))
                if index == 3:
                    try:
                        if extra.recv(1):
                            raise RuntimeError("stock_fourth_connection_produced_response")
                    except ConnectionResetError:
                        pass
        return 0'''
    else:
        raise ValueError("unknown_stock_budget_probe")
    assert source.count(anchor) == 1
    candidate = source.replace(anchor, replacement)
    compile(candidate, "instrumented-stock-budget-client.py", "exec")
    return candidate


@pytest.mark.integration
@pytest.mark.parametrize("case", ("O1", "O5"))
def test_confined_stock_owner_refuses_extra_request_or_fourth_connection(tmp_path, monkeypatch, record_property, case):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for disconnected stock-owner budget probes")
    assert sys.platform == "linux" and os.geteuid() != 0
    instrument(tmp_path, monkeypatch, lambda source: _probe_source(source, case), "stock_http_client_worker")
    monkeypatch.setattr(StockHttpLab, "start", lambda *args: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedStockHttpBackend, "run", lambda *args, **kwargs: pytest.fail("host tool fallback"))
    directory = tmp_path / "evidence"
    report = diagnostic.run_trial(directory, configuration="A", case=case,
                                  execute=True, unattended_owned_lab_test=True)
    assert report["case_passed"] is False, report
    assert report["native_response_verified"] is False
    assert report["metrics"]["useful_completion"] is False
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    result = json.loads((directory / "result.json").read_bytes())
    assert result["boundary_checks"] and all(result["boundary_checks"].values())
    ledger = result["stock_http_owner"]["recorder"]
    admitted, delivered, attempted = (1, 1, 2) if case == "O1" else (3, 0, 4)
    assert ledger["connections_attempted"] == attempted
    assert ledger["connections_admitted"] == admitted
    assert ledger["connections_denied"] == 1
    assert ledger["requests_delivered"] == ledger["requests_validated"] == delivered
    assert ledger["request_bytes_delivered"] == delivered * len(spec.request_bytes("A", case))
    assert ledger["daemon_connections"] == delivered
    assert ledger["finalized"] and ledger["terminal_reason"] == "closed"
    assert ledger["pending_connections"] == ledger["active_connections"] == 0
    denied = [row for row in ledger["events"] if row["kind"] == "deny"]
    assert len(denied) == 1 and denied[0]["connection"] == attempted
    assert denied[0]["reason"] == ("request_limit" if case == "O1" else "connection_limit")
    assert len([row for row in ledger["events"] if row["kind"] == "delivered"]) == delivered
    assert all(right - left >= 249 for left, right in zip(
        ledger["admissions_elapsed_ms"], ledger["admissions_elapsed_ms"][1:]))
    assert result["stock_http_closure"]["processes_reaped"] is True
    assert result["stock_http_closure"]["namespace_descriptors_closed"] is True
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert inspect_trial(directory) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    record_property("instrumented_boundary_probe", "second_exact_get" if case == "O1" else "fourth_nmap_profile_connection")
    record_property("connections_attempted", attempted)
    record_property("connections_admitted", admitted)
    record_property("connections_denied", 1)
    record_property("requests_delivered", delivered)
    record_property("case_passed", False)
