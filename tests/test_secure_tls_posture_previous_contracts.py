"""Freeze the accepted pre-T02 surface without regenerating historical hashes."""

import hashlib
import json

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent import network_tools_tls_posture_spec as tls


def test_all_43_accepted_adapters_316_cases_and_34_runtime_contracts_are_unchanged():
    # Captured from merged PR78 efdb133 before adding production profiles.
    value = {
        "adapters": {key: item.to_dict() for key, item in adapters.ADAPTERS.items()
                     if key not in tls.TOOL_VERSIONS and key != contract.SSH_POLICY_TOOL_ID},
        "cases": {case: {"action": contract.action(case), "card": workflow.card(case),
                          "descriptor": contract.capability_descriptor(case), "spec": lab.spec(case)}
                  for case in contract.CASES if case not in tls.CASES + contract.T03_CASES},
        "runtime": {key: [runtime.EXECUTABLES[key], runtime.FIXED_ARGV[key],
                          runtime.execution_environment(key),
                          [(source, destination, raw.hex())
                           for source, destination, raw in runtime.compiled_files(key)]]
                    for key in runtime.EXECUTABLES if key != contract.SSH_POLICY_TOOL_ID},
    }
    assert tuple(len(value[key]) for key in ("adapters", "cases", "runtime")) == (43, 316, 34)
    assert hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == (
        "5f759908a9c4e23261ef5a5bed642cc1689ace5786b07f105c131b7db8ace5b6")
