"""Adversarial client envelopes without creating a namespace or native process."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_public as public
from recon_cockpit.secure_agent import name_tls_execution as execution, name_tls_client as client
from recon_cockpit.secure_agent import name_tls_client_worker as worker
from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_authority import Harness
from test_name_tls_native_runtime import prepared

NONCE = "a" * 64
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


def envelope(slot="dns_1", configuration="A"):
    h = Harness(configuration=configuration)
    binding = None
    if slot != "dns_1":
        h.dns()
        binding = h.ledger.snapshot()["binding"]
    selected, owner = h.selected, h.identity
    action = parse_action(contract.dns_action(selected, owner) if binding is None else
                         contract.service_action(selected, owner, slot, binding))
    op = contract.operation(slot)
    manifest = None if op == "http" else native.partition(prepared(configuration, "O4"), op + "_client")
    policy = contract.policy_for_selection(selected)
    limits = contract.limits(selected)
    return {"mode": contract.PROFILE, "selection": selected, "identity": owner, "binding": binding,
        "runtime": manifest, "namespaces": {name: name + ":[200]" for name in HOST},
        "launch": {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
            "session_id": owner["session_id"], "nonce": NONCE, "sequence": 1 if binding is None else 2,
            "action": action.to_dict(), "action_digest": action.digest, "policy": policy.to_dict(),
            "policy_digest": policy.digest, "limits": limits, "limits_digest": contract.digest(limits),
            "deadline": 150, "output_reserved_before": 0,
            "output_reserved_after": action.parameters.max_output_bytes, "host_namespaces": HOST}}


def consume(value, monkeypatch):
    monkeypatch.setattr(execution.time, "monotonic", lambda: 100)
    raw = public.encode(value)
    return execution.consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("slot", ("dns_1", "http", "tls"))
@pytest.mark.parametrize("configuration", ("A", "B"))
def test_exact_client_envelope_matches_fixed_native_partition(slot, configuration, monkeypatch):
    value = envelope(slot, configuration)
    checked, action = consume(value, monkeypatch)
    assert checked == value
    assert action.to_dict() == value["launch"]["action"]
    assert len(public.encode(value)) <= 32768


@pytest.mark.parametrize("field,bad", (("nonce", "b" * 64), ("sequence", True), ("sequence", 4),
    ("mode", "disconnected_routing_v1"), ("execute", False), ("deadline", 100), ("deadline", 161),
    ("output_reserved_after", 8191), ("output_reserved_before", True), ("action_digest", "b" * 64),
    ("policy_digest", "b" * 64), ("limits_digest", "b" * 64), ("session_id", "invalid")))
def test_recommitted_launch_mutations_still_fail_closed(field, bad, monkeypatch):
    value = envelope()
    value["launch"][field] = bad
    with pytest.raises(ValueError):
        consume(value, monkeypatch)


@pytest.mark.parametrize("slot", ("http", "tls"))
@pytest.mark.parametrize("field", ("binding", "runtime", "namespaces", "identity", "selection"))
def test_foreign_binding_or_runtime_cannot_authorize_service(slot, field, monkeypatch):
    value = envelope(slot)
    other = envelope(slot, "B")
    if field == "namespaces":
        value[field] = HOST
    elif field == "runtime" and slot == "http":
        value[field] = envelope("tls")["runtime"]
    else:
        value[field] = other[field]
    with pytest.raises(ValueError):
        consume(value, monkeypatch)


@pytest.mark.parametrize("slot", ("dns_1", "http", "tls"))
def test_release_requires_exact_nonce_and_short_native_deadline(slot, monkeypatch):
    monkeypatch.setattr(worker.time, "monotonic", lambda: 100)
    cap = contract.action_bounds(slot)["timeout_seconds"]
    assert worker.validate_go(public.encode({"nonce": NONCE, "deadline": 100 + cap}), NONCE, 160, cap) == 100 + cap
    for change in ({"nonce": "b" * 64}, {"deadline": 100}, {"deadline": 100 + cap + .001}, {"extra": True}):
        with pytest.raises(ValueError):
            worker.validate_go(public.encode({"nonce": NONCE, "deadline": 100 + cap, **change}), NONCE, 160, cap)


def test_key_bearing_owner_modules_are_absent_from_client_closure():
    forbidden = {"name_tls_spec", "name_tls_runtime", "name_tls_native_runtime", "name_tls_daemon_worker",
                 "network_tools_fixture", "network_tools_tls_certificate_material"}
    assert not forbidden.intersection(client.MODULES)
    assert "name_tls_worker_common" in client.MODULES
    assert "name_tls_execution" in client.MODULES


def test_read_only_command_requires_sealed_exact_source_inventory(monkeypatch):
    from recon_cockpit.secure_agent import name_tls_python_runtime as sources
    value = envelope("http")
    service = SimpleNamespace(slot="http", selection=value["selection"], namespace_fds=(3, 4))
    monkeypatch.setattr(client, "_trusted_program", lambda name: "/usr/bin/" + name)
    with pytest.raises(ValueError, match="snapshot_inventory"):
        client.command(service, ("/usr/lib/python3.13", []), None, [], NONCE, "b" * 64,
                       source_descriptors={}, info_fd=5)
    assert set(sources.PACKAGE_FILES) <= set(client.MODULES)


def test_nested_admission_mounts_typed_name_contract_without_owner_material(monkeypatch):
    from recon_cockpit.secure_agent import admission_isolation
    from recon_cockpit.secure_agent.session_limits import SessionLimits
    selected = contract.selection("A", "O1")
    gate = admission_isolation.LinuxLaunchAdmission(contract.policy_for_selection(selected),
        "00000000-0000-0000-0000-000000000001", SessionLimits(**contract.limits(selected)),
        execute=True, profile=contract.PROFILE, case=selected)
    monkeypatch.setattr(admission_isolation, "_namespaces", lambda: HOST)
    monkeypatch.setattr(admission_isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    import os
    import time
    from recon_cockpit.secure_agent.execution import ExecutionControl
    descriptors = admission_isolation._name_tls_source_copies(ExecutionControl(time.monotonic() + 5))
    try:
        argv = gate._command("/usr/lib/python3.13", [], "a" * 64, descriptors)
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
    destinations = {argv[index + 2] for index, value in enumerate(argv) if value == "--ro-bind-data"}
    assert {"/app/admission_runtime/" + name + ".py" for name in
            ("name_tls_contract", "name_tls_public", "session_limits")} <= destinations
    assert not any("name_tls_spec" in path or "server.key" in path for path in destinations)


class StartupClock:
    def __init__(self):
        self.value = 100.5
    def __call__(self):
        return self.value


def startup_run(monkeypatch, *, stall=None, slot='dns_1', owner_deadline=160,
                action_deadline=110, startup_deadline=102):
    """Drive trusted orchestration with simulated subprocesses and a fixed clock."""
    from recon_cockpit.secure_agent import routed, routing_services, name_tls_daemon, stock_ssh_client_runtime
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from test_name_tls_native_runtime import bundle
    value = envelope(slot)
    clock = StartupClock()
    monkeypatch.setattr(client.time, 'monotonic', clock)
    control = ExecutionControl(owner_deadline, clock=clock)
    runtime = bundle(prepared('A', 'O4'))
    value['runtime'] = None if slot == 'http' else runtime['roles'][contract.operation(slot) + '_client']
    records = {'staging_controls': [], 'launches': [], 'writes': [], 'releases': [], 'supervisors': []}
    prefix = worker.READY_PREFIX + hashlib.sha256(public.encode(value)).hexdigest().encode('ascii') + b'\n'
    process = SimpleNamespace(stdin=SimpleNamespace(close=lambda: None), returncode=0, poll=lambda: 0)

    class Supervisor(routed._Supervisor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            records['supervisors'].append(self)
            self.waits = 0
            self.closed = False
        def pipe(self):
            return 70, 71
        def watch(self, descriptor, name):
            self.buffers[name] = bytearray()
        def close_fd(self, descriptor):
            pass
        def launch(self, name, argv, **kwargs):
            self.check()
            records['launches'].append((self.control, self.deadline))
            self.buffers.update(worker_out=bytearray(), worker_err=bytearray())
            return process
        def wait_for(self, predicate, **kwargs):
            self.waits += 1
            if self.waits == 1:
                clock.value = 102 if stall == 'readiness' else 101
                self.buffers['worker_err'].extend(prefix)
            elif self.waits == 2 and slot != 'http':
                clock.value = 102 if stall == 'native_image' else 101.1
            self.check()
            assert predicate()
            self.check()
        def close(self):
            self.closed = True
            self.selector.close()

    def staging(kind, supplied):
        records['staging_controls'].append(supplied)
        if stall == kind:
            clock.value = 102
        supplied.check()
    def native_stage(manifest, unused1, unused2, supplied, **kwargs):
        staging('native_staging', supplied)
        return []
    def source_stage(runtime, modules, supplied):
        staging('source_staging', supplied)
        return {}
    def write_control(proc, raw, supervisor, **kwargs):
        supervisor.check()
        records['writes'].append((raw, supervisor.deadline, supervisor.control))
    def release(supplied, native_deadline):
        assert supplied is control
        records['releases'].append((supplied, native_deadline))
        if stall == 'release':
            clock.value = 102
        else:
            records['supervisors'][0].eof.update(('worker_out', 'worker_err'))
    service = SimpleNamespace(slot=slot, selection=value['selection'], identity=value['identity'], runtime=runtime,
        namespaces=value['namespaces'], namespace_fds=(13, 14), deadline=action_deadline,
        startup_deadline=startup_deadline, check=lambda supplied: supplied.check(), release=release)
    monkeypatch.setattr(routed, '_Supervisor', Supervisor)
    monkeypatch.setattr(client, 'sealed_snapshots', native_stage)
    monkeypatch.setattr(client.sources, 'snapshot_sources', source_stage)
    monkeypatch.setattr(client, 'command', lambda *args, **kwargs: ['simulated-client'])
    monkeypatch.setattr(stock_ssh_client_runtime, '_write_control', write_control)
    monkeypatch.setattr(routing_services, '_owner_info', lambda *args: ((13, 14), 15, value['namespaces']))
    monkeypatch.setattr(name_tls_daemon, 'launcher_mapping', lambda *args: {})
    monkeypatch.setattr(name_tls_daemon, 'client_ready', lambda *args, **kwargs: {'ready': True})
    original_stat = client.os.stat
    def stat(path, *args, **kwargs):
        if path == 'exe' and kwargs.get('dir_fd') == 15:
            return SimpleNamespace(st_dev=1, st_ino=2)
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(client.os, 'stat', stat)
    return lambda: client.run(service=service, launch=value, control=control,
        closure={'name_tls_runtime': runtime, 'stdlib': '/simulated-stdlib', 'files': []}, manifest=value['runtime']), records, control


@pytest.mark.parametrize('stall', ('native_staging', 'source_staging', 'readiness', 'native_image', 'release'))
def test_shared_startup_expiry_reaps_client_before_any_success(monkeypatch, stall):
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    run, records, control = startup_run(monkeypatch, stall=stall)
    with pytest.raises(IsolationUnavailable, match='startup exceeded action bound'):
        run()
    assert control.remaining() > 0
    assert records['supervisors'][0].closed
    assert all(item.deadline == 102 and item is not control and item.clock is control.clock
               for item in records['staging_controls'])
    if stall.endswith('staging'):
        assert records['launches'] == records['writes'] == records['releases'] == []
    elif stall in ('readiness', 'native_image'):
        assert records['releases'] == []


@pytest.mark.parametrize('slot', ('dns_1', 'http', 'tls'))
def test_client_consumes_remaining_shared_startup_and_preserves_owner_control(monkeypatch, slot):
    run, records, control = startup_run(monkeypatch, slot=slot)
    result = run()
    assert result['status'] == 'succeeded'
    assert records['launches'] == [(control, 102)]
    assert all(deadline == 102 and supplied is control for _, deadline, supplied in records['writes'])
    assert records['releases'] == [(control, 101 + contract.action_bounds(slot)['timeout_seconds'])]
    assert records['supervisors'][0].deadline == records['releases'][0][1]
    assert records['supervisors'][0].control is control and control.deadline == 160
    assert records['supervisors'][0].closed


@pytest.mark.parametrize('owner_deadline,action_deadline,expected', ((101.5, 110, 101.5), (160, 101.5, 101.5)))
def test_startup_never_outlives_owner_or_whole_action(monkeypatch, owner_deadline, action_deadline, expected):
    run, records, control = startup_run(monkeypatch, owner_deadline=owner_deadline, action_deadline=action_deadline)
    result = run()
    assert result['status'] == 'succeeded'
    assert all(item.deadline == expected for item in records['staging_controls'])
    assert records['launches'] == [(control, expected)]
    assert records['releases'] == [(control, expected)]
