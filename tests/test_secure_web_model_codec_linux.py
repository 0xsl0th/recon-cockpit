"""Actual no-network codec; provider replies are explicit synthetic bytes."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_isolation import LinuxOpenAIPlanner
from recon_cockpit.secure_agent import web_model_contract as contract
from test_secure_web_model_contract import response


pytestmark = pytest.mark.integration


@pytest.mark.parametrize("malformed", [False, True])
def test_actual_web_model_parser_is_profile_bound_and_reaps_before_release(monkeypatch, malformed):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual model codec isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    planner = LinuxOpenAIPlanner(profile=contract.WEB_MODEL_PROFILE)
    observation = contract.encode({"step": 1, "untrusted_observation": None})
    processes, requests = [], []
    original = subprocess.Popen
    def launch(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            processes.append(process)
        return process
    monkeypatch.setattr(subprocess, "Popen", launch)
    def exchange(request, **_):
        requests.append(request)
        assert request == contract.build_request(observation)
        assert contract.validate_request(request) == request
        value = response()
        if malformed:
            value["output"][0]["content"][0]["text"] = "not a proposal"
        return contract.encode(value)
    control = ExecutionControl(time.monotonic() + 20)
    if malformed:
        with pytest.raises(IsolationUnavailable):
            planner.plan(contract.CONFIG, observation, exchange, control=control)
        assert planner.last_error == "output_invalid"
    else:
        proposal = json.loads(planner.plan(contract.CONFIG, observation, exchange, control=control))
        assert proposal["action"]["tool_id"] == "nmap_tcp_connect_v1"
        assert planner.last_error is None
    assert len(requests) == 1 and all(planner.boundary_checks.values())
    assert processes and all(process.poll() is not None for process in processes)
