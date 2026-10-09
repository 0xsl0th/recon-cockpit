"""Synthetic policy advertisements after the unchanged C14 request and write EOF."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
    from . import network_tools_ssh_algorithms_fixture as collector
else:
    def _load(name):
        spec = importlib.util.spec_from_file_location("policy_" + name,
            Path(__file__).with_name(name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    fixture = _load("network_tools_fixture")
    collector = _load("network_tools_ssh_algorithms_fixture")


response = fixture.ssh_policy_response

def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.SSH_POLICY_CASES:
        raise ValueError("invalid_ssh_policy_fixture_case")
    # Validation must finish before a reply can provoke any client behavior.
    collector.read_request(connection, deadline)
    on_request()
    raw = response(case)
    if raw is None:
        time.sleep(collector._remaining(deadline))
        return
    width = 3 if case == "ssh-policy-fragmented" else len(raw)
    for start in range(0, len(raw), width):
        connection.settimeout(min(2, collector._remaining(deadline)))
        connection.sendall(raw[start:start + width])
        if width == 3:
            time.sleep(min(0.002, collector._remaining(deadline)))
