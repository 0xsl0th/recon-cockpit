"""Read-only injected claims checked against live Name/TLS processes and FDs."""

from copy import deepcopy
import json
import os
import sys
import time

sys.path.insert(0, "/app")

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_daemon as daemon
from recon_cockpit.secure_agent import name_tls_topology as topology
from recon_cockpit.secure_agent.name_tls_backend import ConfinedNameTLSBackend
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.isolation import _namespaces


def refusal(function):
    try:
        function()
    except (ValueError, OSError) as error:
        return {"exception": type(error).__name__, "reason": str(error)[:256]}
    raise AssertionError("injected inconsistent observation was accepted")


def main():
    value = json.loads(sys.stdin.buffer.read(262145))
    assert set(value) == {"config", "closure", "gate"}
    config, closure, gate = value["config"], value["closure"], value["gate"]
    assert config["case"] == contract.selection(gate["configuration"], "O4")
    case = gate["case"]
    refusals, observations = [], []
    if gate["group"] == "topology_and_descriptor_custody":
        original = topology.Topology.start
        def start(owner):
            result = original(owner)
            descriptors = tuple(owner._descriptors[name] for name in topology.EXPORTS)
            parent = _namespaces()
            validate = lambda row, fds: topology.validate_exports(row, fds, parent_namespaces=parent,
                                                                 configuration=gate["configuration"])
            assert validate(result, descriptors) == result
            altered = deepcopy(result)
            if case == "host_or_other_owner_namespace_rejected":
                descriptor = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                try:
                    swapped = (*descriptors[:1], descriptor, *descriptors[2:])
                    refusals.append(refusal(lambda: validate(altered, swapped)))
                finally:
                    os.close(descriptor)
            elif case == "changed_namespace_uid_mapping_rejected":
                altered["namespace_identity"]["uid_map"][0][0] = 0
                refusals.append(refusal(lambda: validate(altered, descriptors)))
            elif case == "listener_endpoint_or_cookie_change_rejected":
                altered["listeners"]["dns"]["local"][1] += 1
                refusals.append(refusal(lambda: validate(altered, descriptors)))
                altered = deepcopy(result)
                altered["listeners"]["dns"]["netns_cookie"] += 1
                refusals.append(refusal(lambda: validate(altered, descriptors)))
            else:
                raise AssertionError("unknown topology mutation")
            observations.append({"topology_sha256": result["topology_sha256"],
                                 "actual_descriptor_inodes": [os.fstat(fd).st_ino for fd in descriptors]})
            return result
        topology.Topology.start = start
    else:
        executable = case.split("/", 1)[0]
        assert executable in ("dnsmasq", "nginx", "dig", "openssl")
        client = executable in ("dig", "openssl")
        name = "client_ready" if client else "listener_ready"
        original = getattr(daemon, name)
        def observe(directory, namespaces, pins, manifest, operation, **kwargs):
            ready = original(directory, namespaces, pins, manifest, operation, **kwargs)
            if ready and not refusals and manifest["executable"] == "/tool/" + executable:
                altered = deepcopy(manifest)
                image = next(row for row in altered["files"] if row["destination"] == altered["executable"])
                image["sha256"] = "0" * 64 if image["sha256"] != "0" * 64 else "1" * 64
                refusals.append(refusal(lambda: original(directory, namespaces, pins, altered, operation, **kwargs)))
                observations.append({"actual_readiness": ready, "actual_process_directory_inode": os.fstat(directory).st_ino,
                                     "injected_image_sha256": image["sha256"]})
            return ready
        setattr(daemon, name, observe)
    backend = ConfinedNameTLSBackend(config, closure)
    policy = parse_policy(config["policy"])
    control = ExecutionControl(time.monotonic() + 60)
    binding, results = None, []
    try:
        for slot in contract.operation_plan(config["case"]):
            raw = (contract.dns_action(config["case"], config["owned_lab"], slot) if slot.startswith("dns_")
                   else contract.service_action(config["case"], config["owned_lab"], slot, binding))
            result = backend.run(parse_action(raw), policy, control=control)
            assert result["status"] == "succeeded", result
            binding = result["name_tls_ledger"]["binding"]
            results.append({"slot": slot, "status": result["status"],
                            "client_observation": result["client_observation"],
                            "daemon_native_ready": result["name_tls_service"]["native_ready"]})
        assert refusals and observations
    finally:
        closed = backend.close()
    assert closed["services"]["all_processes_reaped"] is True
    assert closed["topology"]["owner_exited"] is closed["topology"]["descriptors_closed"] is True
    print(json.dumps({"gate_id": gate["id"], "case_passed": True, "probe_kind": "injected_read_only_claim",
        "production_native_operations": results, "refusals": refusals, "observations": observations,
        "closure": closed, "actual_provider_calls": 0, "actual_cost_microusd": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
