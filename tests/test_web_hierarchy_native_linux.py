"""Actual ffuf and independent owned-server evidence; not product acceptance."""

import json
import os
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import web_hierarchy_diagnostic as diagnostic
from recon_cockpit.secure_agent import web_hierarchy_diagnostic_runtime as runtime
from recon_cockpit.secure_agent import web_hierarchy_spec as spec
from recon_cockpit.secure_agent.execution import ExecutionControl

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned T04 native trials")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.mark.parametrize("case,useful", [(case, case in ("nested", "empty", "hostile"))
                                         for case in spec.CASES])
def test_native_fixed_corpus_and_honest_ambiguity(tmp_path, record_property, case, useful):
    result = diagnostic.run_trial(case)
    # Persist even a failed assertion's observations for later diagnosis.
    path = tmp_path / (case + ".json")
    path.write_text(json.dumps(result, indent=2, sort_keys=True))
    path.chmod(0o600)
    assert result["cleanup"]["closed"] is True, result
    assert result["confinement"]["worker_ready"] is True, result
    assert all(result["confinement"].values()), result
    assert result["observation"]["useful_completion"] is useful, result
    assert result["diagnostic_only"] and not result["production_authority_validated"]
    assert result["actual_provider_calls"] == result["actual_cost_microusd"] == 0
    assert result["elapsed_ms"] < spec.SESSION_SECONDS * 1000
    owner = result["owner"]
    assert owner["diagnostic"]["max_active_requests"] <= 1, result
    if case != "stalled":
        assert owner["request_count"] == owner["connection_count"] == len(spec.PATHS), result
        assert result["execution"]["exit_code"] == 0, result
        assert result["execution"]["stop_reason"] is None, result
    else:
        assert not result["observation"]["useful_completion"]
        assert 0 < owner["request_count"] <= owner["connection_count"] <= len(spec.PATHS), result
        assert any(row["method"] == "GET" and row["path"] in spec.PATHS
                   and row["completed"] is False and row["raw_request_base64"]
                   for row in owner["diagnostic"]["ledger"]), result
    record_property("case", case)
    record_property("useful_completion", useful)
    record_property("elapsed_ms", result["elapsed_ms"])
    record_property("client_elapsed_ms", result["execution"]["elapsed_ms"])
    record_property("request_count", owner["request_count"])
    record_property("max_active_requests", owner["diagnostic"]["max_active_requests"])
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)


def test_native_cancellation_closes_owner_without_inventing_completion(monkeypatch, tmp_path):
    cancelled = threading.Event()
    original_client = runtime.capture_client
    original_capture = runtime._capture_bounded
    observers, progress, failures = [], [], []
    selected_lab = []

    def client(lab, control):
        selected_lab.append((lab, control))
        return original_client(lab, control)

    def capture(*args, **kwargs):
        # Runtime inspection and initial lab checks have finished. The owner
        # supervisor is used only by this observer while the separate client
        # supervisor captures ffuf. Cancel after an actual incomplete GET.
        def after_request():
            try:
                lab, control = selected_lab[0]
                progress.append(lab.snapshot(control, minimum_requests=1))
            except Exception as error:
                failures.append(type(error).__name__)
            finally:
                cancelled.set()
        observer = threading.Thread(target=after_request)
        observers.append(observer)
        observer.start()
        return original_capture(*args, **kwargs)

    monkeypatch.setattr(runtime, "capture_client", client)
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    try:
        result = diagnostic.run_trial("stalled", control=ExecutionControl(
            time.monotonic() + spec.SESSION_SECONDS, cancelled))
    finally:
        cancelled.set()
        for observer in observers:
            observer.join(timeout=2)
            assert not observer.is_alive()
    path = tmp_path / "cancellation.json"
    path.write_text(json.dumps({"result": result, "observed_before_cancellation": progress},
                               indent=2, sort_keys=True))
    path.chmod(0o600)
    assert result["failure"] == "session_cancelled", result
    assert result["cleanup"]["closed"] is True
    assert result["observation"]["useful_completion"] is False
    assert result["owner"] is None
    assert not failures and len(progress) == 1, failures
    assert progress[0]["request_count"] >= 1
    assert any(row["method"] == "GET" and row["completed"] is False
               for row in progress[0]["diagnostic"]["ledger"])
    assert result["cleanup"]["last_acknowledged_counts"]["request_count"] >= 1
