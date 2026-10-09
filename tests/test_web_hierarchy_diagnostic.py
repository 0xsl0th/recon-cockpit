"""Lifecycle and non-registration checks for the bounded T04 instrument."""

import base64
import json
import time

import pytest

from recon_cockpit.secure_agent import web_hierarchy_diagnostic as diagnostic
from recon_cockpit.secure_agent import web_hierarchy_spec as spec
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped


@pytest.mark.parametrize("case", [None, True, "127.0.0.1", "external", "nested; id", ["nested"]])
def test_invalid_selection_never_starts_an_owner(monkeypatch, case):
    monkeypatch.setattr(diagnostic, "DiagnosticLab", lambda *_: pytest.fail("owner constructed"))
    with pytest.raises(ValueError):
        diagnostic.run_trial(case)


def test_future_or_synthetic_clock_control_never_starts_an_owner(monkeypatch):
    monkeypatch.setattr(diagnostic, "DiagnosticLab", lambda *_: pytest.fail("owner constructed"))
    for control in (ExecutionControl(time.monotonic() + 61), ExecutionControl(60, clock=lambda: 0)):
        with pytest.raises(ValueError):
            diagnostic.run_trial("nested", control=control)


@pytest.mark.parametrize("failure", [RuntimeError("owner setup"), ExecutionStopped("session_cancelled")])
def test_setup_and_cancellation_always_close_the_namespace(monkeypatch, failure):
    from recon_cockpit.secure_agent import web_hierarchy_diagnostic_runtime as runtime
    closed = []

    class Lab:
        identity = {"scenario": "nested", "diagnostic_only": True}
        def __init__(self, case): pass
        def start(self, control): raise failure
        def close(self):
            closed.append(True)
            return {"status": "closed", "connection_count": 0, "request_count": 0}

    monkeypatch.setattr(diagnostic, "DiagnosticLab", Lab)
    monkeypatch.setattr(runtime, "capture_client", lambda *_: pytest.fail("client launched"))
    if isinstance(failure, ExecutionStopped):
        result = diagnostic.run_trial("nested")
        assert result["failure"] == "session_cancelled"
        assert result["owner"] is None and result["cleanup"]["closed"] is True
        assert not result["observation"]["useful_completion"]
    else:
        with pytest.raises(RuntimeError):
            diagnostic.run_trial("nested")
    assert closed == [True]


def test_missing_confinement_never_runs_the_result_evaluator(monkeypatch):
    from recon_cockpit.secure_agent import web_hierarchy_diagnostic_runtime as runtime
    from recon_cockpit.secure_agent import web_hierarchy_observation as observation

    class Lab:
        identity = {"scenario": "nested", "diagnostic_only": True}
        def __init__(self, case): pass
        def start(self, control): pass
        def snapshot(self, control): return {"connection_count": 0, "request_count": 0}
        def close(self): return {"status": "closed", "connection_count": 0, "request_count": 0}

    monkeypatch.setattr(diagnostic, "DiagnosticLab", Lab)
    monkeypatch.setattr(runtime, "capture_client", lambda *_: {
        "confinement": {"worker_ready": False},
        "execution": {"exit_code": 78, "stop_reason": None, "truncated": False,
                      "raw_stdout_base64": base64.b64encode(b"untrusted").decode()}})
    monkeypatch.setattr(observation, "assess", lambda *a, **k: pytest.fail("unconfined bytes assessed"))
    result = diagnostic.run_trial("nested")
    assert result["observation"]["reason"] == "confinement_not_verified"
    assert result["cleanup"]["closed"] and not result["production_authority_validated"]
    assert result["actual_provider_calls"] == result["actual_cost_microusd"] == 0


def test_native_instrument_is_not_a_registered_product_tool():
    from recon_cockpit.secure_agent.tool_catalog import list_tools
    inventory = list_tools()
    assert inventory["accepted_capability_count"] == 48
    assert inventory["candidate_capability_count"] == 0
    assert all("hierarchy" not in row["tool_id"] for row in inventory["tools"])


def test_corpus_has_exactly_one_declared_directory_level_and_twelve_paths():
    assert len(spec.PATHS) == len(set(spec.PATHS)) == 12
    assert all(path.startswith(spec.BASE) and ".." not in path for path in spec.PATHS)
    assert max(word.count("/") for word in spec.WORDS) == 1
    assert spec.WORDLIST == ("\n".join(spec.WORDS) + "\n").encode()
    assert spec.MAX_OUTPUT_BYTES == 8192 and spec.SESSION_SECONDS == 60
