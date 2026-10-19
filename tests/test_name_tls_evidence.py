"""Saved authority/audit consistency; synthetic receipts are not native proof."""

from copy import deepcopy
import json
import os
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_evidence as evidence
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.name_tls_probes import run_probe_cases
from test_name_tls_native_runtime import prepared, bundle

SESSION = str(UUID(int=11001))


def manifest(configuration="A", case="O1", *, execute=False, approval=False):
    selected = contract.selection(configuration, case)
    runtime = bundle(prepared(configuration, case))
    return {"schema_version": "1", "assessment_id": str(UUID(int=11002)), "session_id": SESSION,
            "selection": selected, "slots": list(contract.operation_plan(selected) + contract.attempt_slots(selected)),
            "policy": contract.policy_for_selection(selected, require_approval=approval).to_dict(),
            "limits": contract.limits(selected), "runtime": runtime,
            "identity": contract.identity(selected, SESSION, runtime, owner_id=str(UUID(int=11003))),
            "execute": execute, "unattended_owned_lab_test": not approval}


def closure(chosen):
    return {"identity": chosen["identity"], "status": "closed", "launcher_cleanup_verified": True,
            "counters_source": "last_acknowledged_result", "last_result": None}


def save(directory, chosen):
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None):
            pass
        def run(self, action, policy):
            return {"status": "failed"}
    with evidence.NameTLSEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcomes = []
            if chosen["slots"]:
                action = contract.dns_action(chosen["selection"], chosen["identity"])
                outcomes.append(controller.submit(action, execute=chosen["execute"], session_step=1))
        return store.finalize(outcomes, closure=closure(chosen), elapsed_ms=10)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("execute,approval", ((False, False), (True, False), (True, True)))
def test_private_saved_report_replay_is_immutable_and_never_turns_failure_into_useful(tmp_path, configuration, execute, approval):
    directory = tmp_path / "evidence"
    report = save(directory, manifest(configuration, execute=execute, approval=approval))
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert evidence.inspect_trial(directory) == report
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert report["useful_task_completed"] is False
    assert report["case_passed"] is bool(execute and approval)
    assert stat_mode(directory) == 0o700
    assert all(stat_mode(path) == 0o600 for path in directory.iterdir())


def stat_mode(path):
    return path.stat().st_mode & 0o777


def test_n4_empty_actions_cannot_claim_probe_success(tmp_path):
    directory = tmp_path / "empty"
    report = save(directory, manifest(case="N4"))
    assert not report["case_passed"] and report["actions"] == []
    assert evidence.inspect_trial(directory) == report


@pytest.mark.parametrize("change", ("extra", "symlink", "hardlink", "public_file", "public_directory", "report", "outcome", "audit", "identity"))
def test_replay_rejects_changed_custody_or_corroboration(tmp_path, change):
    directory = tmp_path / "saved"
    save(directory, manifest(execute=True))
    if change == "extra":
        (directory / "extra.json").write_text("{}")
    elif change in ("symlink", "hardlink"):
        path = directory / "report.json"
        target = tmp_path / "external.json"
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        if change == "symlink":
            path.symlink_to(target)
        else:
            os.link(target, path)
    elif change == "public_file":
        (directory / "report.json").chmod(0o644)
    elif change == "public_directory":
        directory.chmod(0o755)
    else:
        filename = {"report": "report.json", "outcome": "outcomes.json", "audit": "audit.jsonl", "identity": "manifest.json"}[change]
        path = directory / filename
        if change == "audit":
            lines = path.read_text().splitlines()
            path.write_text("\n".join(lines[:-1]) + "\n")
        else:
            value = json.loads(path.read_text())
            if change == "report":
                value["case_passed"] = True
            elif change == "outcome":
                value["outcomes"][0]["execution_id"] = str(UUID(int=999))
            else:
                value["identity"]["owner_id"] = str(UUID(int=999))
            path.write_text(json.dumps(value))
    with pytest.raises((ValueError, OSError)):
        evidence.inspect_trial(directory)


@pytest.mark.parametrize("raw", (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'[]', b'{"a":' + b'[' * 65 + b'0' + b']' * 65 + b'}'))
def test_json_limits_reject_ambiguous_or_nonfinite_data(raw):
    with pytest.raises(ValueError):
        evidence._decode(raw)


def test_n14_manifest_keeps_ordinary_owner_plan_and_two_expiry_attempts():
    chosen = manifest(case="N14")
    assert chosen["slots"] == ["dns_1", "http", "tls"]
    assert contract.operation_plan(chosen["selection"]) == ("dns_1",)
    assert evidence.validate_manifest(chosen) == chosen


@pytest.mark.parametrize("change", ("slots", "execute", "approval", "runtime", "identity"))
def test_manifest_cannot_widen_mode_plan_or_runtime(change):
    chosen = manifest()
    if change == "slots":
        chosen["slots"].append("tls")
    elif change == "execute":
        chosen["execute"] = 1
    elif change == "approval":
        chosen["unattended_owned_lab_test"] = False
    elif change == "runtime":
        chosen["runtime"] = bundle(prepared("B"))
    else:
        chosen["identity"]["owner_identity_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        evidence.validate_manifest(chosen)


def probe_bundle(directory, *, execute=True):
    chosen = manifest(case="N4", execute=execute)
    class Backend:
        name = contract.BACKEND
        def check_available(self, action):
            pytest.fail("typed refusal must precede backend access")
    backend = Backend()
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    with evidence.NameTLSEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, backend, session_id=SESSION, evidence=store)
            probes = run_probe_cases(controller, backend, selected=chosen["selection"], identity=chosen["identity"],
                control=ExecutionControl(time.monotonic() + 5), outcomes=[], execute=execute)
        report = store.finalize([], closure=closure(chosen), elapsed_ms=10, probes=probes)
    return chosen, probes, report


@pytest.mark.parametrize("execute", (True, False))
def test_n4_records_exact_three_typed_refusals_and_replays_all_audit_events(tmp_path, execute):
    directory = tmp_path / "probes"
    chosen, probes, report = probe_bundle(directory, execute=execute)
    assert len(probes["attempts"]) == 3
    assert report["case_passed"] is execute
    assert report["useful_task_completed"] is False
    assert evidence.inspect_trial(directory) == report
    events = (directory / "audit.jsonl").read_text().splitlines()
    assert len(events) == 3
    assert all(json.loads(line)["event_type"] == "validation_rejected" for line in events)


@pytest.mark.parametrize("field", ("proposal", "proposal_sha256", "expected_guard", "outcome", "status", "waited_us", "attempts"))
def test_probe_labels_cannot_replace_actual_guard_evidence(tmp_path, field):
    chosen, probes, _ = probe_bundle(tmp_path / "probes")
    if field == "proposal":
        probes["attempts"][0][field]["parameters"]["question_name"] = "harbordesk.test."
    elif field == "proposal_sha256":
        probes["attempts"][0][field] = "f" * 64
    elif field == "expected_guard":
        probes["attempts"][0][field] = "static_profile"
    elif field == "outcome":
        probes["attempts"][0][field]["reasons"] = ["approval_missing"]
    elif field == "status":
        probes[field] = "passed"
    elif field == "waited_us":
        probes[field] = True
    else:
        probes[field].pop()
    with pytest.raises(ValueError):
        evidence.validate_probe_evidence(probes, manifest=chosen, results=[], outcomes=[])


def test_probe_audit_cannot_be_omitted_from_saved_evidence(tmp_path):
    directory = tmp_path / "probes"
    probe_bundle(directory)
    (directory / "audit.jsonl").write_bytes(b"")
    with pytest.raises(ValueError, match="audit_count"):
        evidence.inspect_trial(directory)


@pytest.mark.parametrize("field", ("user", "net", "mnt", "pid"))
@pytest.mark.parametrize("invalid", (None, True, "other:[123]", "net:[0]", "net:[01]", "net:[123]\n", "net:[" + "1" * 21 + "]"))
def test_retained_namespace_identifiers_reject_malformed_data(field, invalid):
    from recon_cockpit.secure_agent import name_tls_context as context, name_tls_parser_runtime as runtime
    values = {name: name + ":[123]" for name in ("user", "net", "mnt", "pid")}
    context._namespace_vector(values)
    ready = {"parser_version": runtime.parser.PARSER_VERSION, "boundary_checks": dict.fromkeys(runtime.BOUNDARY_NAMES, True),
             "namespaces": values, "runtime_absence_verified": True,
             "identity": {"uid": 65534, "gid": 65534, "groups": [65534] * 17,
                          "uid_map": [[65534, 0, 1]], "gid_map": [[65534, 0, 1]]}}
    assert runtime._readiness(evidence._encode(ready)) == ready
    values[field] = invalid
    with pytest.raises(ValueError):
        context._namespace_vector(values)
    with pytest.raises(ValueError):
        runtime._readiness(evidence._encode(ready))


@pytest.mark.parametrize("kind", ("uid", "gid"))
@pytest.mark.parametrize("changed", ([], [[65534, 1000, True]], [[65534, True, 1]], [[False, 1000, 1]],
    [(65534, 1000, 1)], ((65534, 1000, 1),), [[65534, 1000]], [[65534, 1000, 1, 2]],
    [[65534, 1001, 1]], [[65534, 0, 1]], [[65534, 1000, 1], [1, 1, 1]]))
def test_parent_maps_require_exact_integer_rows(kind, changed):
    from recon_cockpit.secure_agent import name_tls_context as context
    value = {"launcher_uid": 1000, "launcher_gid": 1000, "uid_map": [[65534, 1000, 1]], "gid_map": [[65534, 1000, 1]]}
    context._mapping(value)
    value[kind + "_map"] = changed
    with pytest.raises(ValueError):
        context._mapping(value)


@pytest.mark.parametrize("change", ("namespaces", "malformed", "pid_bool", "pid_root", "root_parent", "map_bool", "map_target"))
def test_topology_parent_observation_cannot_change_identity_or_mapping(change):
    from recon_cockpit.secure_agent import name_tls_context as context
    topology = {"owner_namespaces": {name: name + ":[123]" for name in ("user", "net", "mnt", "pid")}}
    value = {"namespaces": deepcopy(topology["owner_namespaces"]), "payload_pid": 1234,
        "mapping": {"launcher_uid": 1000, "launcher_gid": 1000, "uid_map": [[65534, 1000, 1]], "gid_map": [[65534, 1000, 1]]}}
    assert context._topology_parent(value, topology) == contract.public.digest(value)
    if change == "namespaces":
        value["namespaces"]["user"] = "user:[456]"
    elif change == "malformed":
        value["namespaces"]["pid"] = topology["owner_namespaces"]["pid"] = "invalid"
    elif change == "pid_bool":
        value["payload_pid"] = True
    elif change == "pid_root":
        value["payload_pid"] = 0
    elif change == "root_parent":
        value["mapping"]["launcher_uid"] = 0
        value["mapping"]["uid_map"] = [[65534, 0, 1]]
    elif change == "map_bool":
        value["mapping"]["uid_map"][0][2] = True
    else:
        value["mapping"]["gid_map"][0][1] = 1001
    with pytest.raises(ValueError):
        context._topology_parent(value, topology)


def n15_process(index=0, *, alive=True):
    return {"pid": 1200 + index, "start_time_ticks": 10000 + index,
        "namespaces": {name: name + ":[" + str(300 + index) + "]" for name in ("user", "net", "mnt", "pid")},
        "pidfd_readable": not alive, "proc_absent": not alive,
        "identity_source": "current_proc" if alive else "retained_pin"}


@pytest.mark.parametrize("alive", (True, False))
def test_n15_process_receipt_distinguishes_live_readback_from_retained_reaped_identity(alive):
    value = n15_process(alive=alive)
    evidence._validate_n15_owner_process(value, value["namespaces"], alive=alive)


@pytest.mark.parametrize("alive", (True, False))
@pytest.mark.parametrize("field,changed", (("pid", True), ("pid", 0), ("pid", 2**31),
    ("start_time_ticks", True), ("start_time_ticks", 0), ("start_time_ticks", 2**63),
    ("pidfd_readable", 1), ("proc_absent", 0), ("identity_source", None)))
def test_n15_process_receipt_rejects_type_confusion_and_unbounded_identity(alive, field, changed):
    value = n15_process(alive=alive)
    namespaces = deepcopy(value["namespaces"])
    value[field] = changed
    with pytest.raises(ValueError, match="name_tls_n15_owner_process"):
        evidence._validate_n15_owner_process(value, namespaces, alive=alive)


@pytest.mark.parametrize("change", ("exited", "proc_missing", "cached", "namespace", "malformed", "extra", "missing"))
def test_n15_live_owner_cannot_be_replaced_by_launcher_or_cached_state(change):
    value = n15_process()
    namespaces = deepcopy(value["namespaces"])
    if change == "exited":
        value["pidfd_readable"] = True
    elif change == "proc_missing":
        value["proc_absent"] = True
    elif change == "cached":
        value["identity_source"] = "retained_pin"
    elif change == "namespace":
        value["namespaces"]["pid"] = "pid:[999]"
    elif change == "malformed":
        value["namespaces"]["user"] = "user:[0]"
    elif change == "extra":
        value["launcher_alive"] = True
    else:
        value.pop("pidfd_readable")
    with pytest.raises(ValueError):
        evidence._validate_n15_owner_process(value, namespaces, alive=True)


@pytest.mark.parametrize("closed", (True, False))
@pytest.mark.parametrize("change", (None, "pid", "start_time_ticks", "namespaces", "launcher_alive", "cached_alive", "ledger"))
def test_n15_transition_preserves_pinned_identity_and_acknowledged_state(closed, change):
    before = {"launcher_alive": True, "topology_owner": n15_process(), "ledger": {"actions": 1}}
    after = deepcopy(before)
    if closed:
        after["launcher_alive"] = False
        after["topology_owner"].update(pidfd_readable=True, proc_absent=True, identity_source="retained_pin")
    if change is None:
        evidence._validate_n15_owner_transition(before, after, closed=closed)
        return
    if change in ("pid", "start_time_ticks"):
        after["topology_owner"][change] += 1
    elif change == "namespaces":
        after["topology_owner"]["namespaces"]["pid"] = "pid:[999]"
    elif change == "launcher_alive":
        after["launcher_alive"] = not after["launcher_alive"]
    elif change == "cached_alive":
        after["topology_owner"]["identity_source"] = "current_proc" if closed else "retained_pin"
    else:
        after["ledger"]["actions"] = True
    with pytest.raises(ValueError, match="name_tls_n15_owner_transition"):
        evidence._validate_n15_owner_transition(before, after, closed=closed)


def test_n15_closed_owner_pid_reuse_is_distinguished_by_start_ticks_and_namespaces():
    closed, donor, recipient = (n15_process(index) for index in range(3))
    donor["pid"] = closed["pid"]
    evidence._validate_n15_owner_independence(closed, donor, recipient)


@pytest.mark.parametrize("change", ("same_identity", "same_live_pid", "user", "net", "mnt", "pid"))
def test_n15_three_owners_require_distinct_processes_and_live_namespace_identities(change):
    closed, donor, recipient = (n15_process(index) for index in range(3))
    if change == "same_identity":
        donor = deepcopy(closed)
    elif change == "same_live_pid":
        recipient["pid"] = donor["pid"]
    else:
        recipient["namespaces"][change] = donor["namespaces"][change]
    with pytest.raises(ValueError, match="name_tls_n15_owner_process_independence"):
        evidence._validate_n15_owner_independence(closed, donor, recipient)
