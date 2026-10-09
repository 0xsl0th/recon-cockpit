"""Freeze all pre-T03 profiles, including review-pending T02 production contracts."""

import hashlib
import json

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent import network_tools_tls_posture_runtime as tls_runtime
from recon_cockpit.secure_agent import network_tools_tls_posture_spec as tls
from recon_cockpit.secure_agent import network_tools_ssh_policy_spec as policy


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_all_47_previous_adapters_329_cases_and_34_runtime_contracts_are_unchanged():
    # Independently captured from merged PR79 main 5f4197fb6302eb386e37b0f24290a0f9a90c4993.
    # This preserves T02 candidates; it does not claim their acceptance.
    value = {
        "adapters": {key: item.to_dict() for key, item in adapters.ADAPTERS.items()
                     if key != policy.TOOL_ID},
        "cases": {case: {"action": contract.action(case), "card": workflow.card(case),
                          "descriptor": contract.capability_descriptor(case), "spec": lab.spec(case)}
                  for case in contract.CASES if case not in policy.CASES},
        "runtime": {key: [runtime.EXECUTABLES[key], runtime.FIXED_ARGV[key],
                          runtime.execution_environment(key),
                          [(source, destination, raw.hex())
                           for source, destination, raw in runtime.compiled_files(key)]]
                    for key in runtime.EXECUTABLES if key != policy.TOOL_ID},
    }
    assert tuple(len(value[key]) for key in ("adapters", "cases", "runtime")) == (47, 329, 34)
    assert digest(value) == "efc4e218ef361bea7b307f98623af96753d6c60868a17a26c9fc7c83cfb5779e"


def test_four_dedicated_tls_runtime_arguments_and_limits_are_unchanged():
    # T02 has a dedicated runtime outside the shared EXECUTABLES dictionary.
    # Pin it separately so the 34-row shared-runtime baseline cannot omit it.
    value = {"profile": tls_runtime.PROFILE, "ready_prefix": tls_runtime.READY_PREFIX.hex(),
        "argv": dict(tls_runtime.FIXED_ARGV), "environment": dict(tls_runtime.ENVIRONMENT),
        "parameters": dict(tls.PARAMETERS), "limits": dict(tls.LIMITS),
        "boundary_fields": sorted(tls.BOUNDARY_FIELDS),
        "compiled": {key: [(source, destination, raw.hex())
                            for source, destination, raw in runtime.compiled_files(key)]
                     for key in tls.TOOL_VERSIONS}}
    assert len(value["argv"]) == len(value["compiled"]) == 4
    assert digest(value) == "dbfabcff8de11195169de99cebfa1d2e04b076ed0177fd7fd54a96be5ff32f33"
