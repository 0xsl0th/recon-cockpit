"""Private instrumented owner driver; no daemon or client output is claimed."""

import errno
import json
import os
import resource
import select
import socket
import stat
import subprocess
import sys
import time
from copy import deepcopy


def imports():
    sys.path.insert(0, "/app")
    global contract, ledger, topology, ExecutionControl
    from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_ledger as ledger
    from recon_cockpit.secure_agent import name_tls_topology as topology
    from recon_cockpit.secure_agent.execution import ExecutionControl


def entry(allowed=()):
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor <= 2 or descriptor in allowed:
            continue
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
            continue
        raise AssertionError("unrelated inherited descriptor")
    assert all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1, 2))


def semantic(configuration="A", *, excluded=False, ttl=60):
    endpoint = contract.public.endpoints(configuration)
    return {"schema_version": "1", "question": {"name": "harbordesk.test.", "class": 1, "type": 1},
        "transaction_id": 1234, "flags": 0x8400, "records": [{"section": "answer", "name": "harbordesk.test.",
        "type": 1, "class": 1, "ttl": ttl, "data": endpoint["excluded_address"] if excluded else endpoint["http"]["target"]}]}


class Probe:
    def __init__(self, value):
        self.selected = contract.validate_selection(value["selection"])
        self.identity = contract.validate_identity(value["identity"], selection=self.selected, runtime=value["runtime"]["name_tls_runtime"])
        self.control = ExecutionControl(time.monotonic() + 60)
        self.topology = topology.Topology((value["runtime"]["stdlib"], [(path, path) for path in value["runtime"]["files"]]), self.control,
            selection=self.selected, identity=self.identity, runtime=value["runtime"]["name_tls_runtime"])
        self.channels, self.snapshots, self.observations, self.workers = {}, [], {}, []
        self.sequence = dict.fromkeys(ledger.ROLES, 0)
        self.action_sequence, self.action, self.slot, self.lease = 0, None, None, None
        self.answer, self.binding = None, None
        self.delivered = {"request": 0, "response": 0}

    def start(self):
        self.topology.start()
        self.owner_pid = self.topology._process.pid
        self.owner_pidfd = os.pidfd_open(self.owner_pid)
        self.channels["launcher"] = self.topology._channel
        for role in ledger.ROLES[1:]:
            descriptor = self.topology._descriptors.pop(role.removesuffix("_frontend") + "_ledger_channel")
            self.channels[role] = socket.socket(fileno=descriptor)
        self.snapshot()

    def snapshot(self):
        evidence = self.topology.ledger_evidence()
        ledger.validate_snapshot(evidence["ledger"], selected=self.selected, identity=self.identity, messages=evidence["messages"])
        self.snapshots.append(evidence)
        assert len(self.snapshots) <= 40
        self.binding = evidence["ledger"]["binding"]
        return evidence["ledger"]

    @property
    def role(self):
        return contract.selector_role(self.slot)

    def message(self, operation, role="launcher", **fields):
        self.sequence[role] += 1
        return {"operation": operation, "sequence": self.sequence[role], "action_sequence": self.action_sequence,
            "action_digest": contract.digest(self.action or self.selected),
            "owner_identity_sha256": self.identity["owner_identity_sha256"], **fields}

    def exchange(self, message, role="launcher"):
        topology.send_packet(self.channels[role], message)
        reply, _ = topology.receive_packet(self.channels[role])
        ledger.validate_reply(reply, message, role=role)
        self.observations["last_exchange"] = {"role": role, "message": message, "reply": reply}
        return reply

    def send(self, operation, role="launcher", **fields):
        return self.exchange(self.message(operation, role, **fields), role)

    def action_for(self, slot, binding=None):
        return (contract.dns_action(self.selected, self.identity, slot) if slot.startswith("dns_") else
                contract.service_action(self.selected, self.identity, slot, binding or self.binding))

    def arm(self, slot):
        self.action_sequence += 1
        self.slot, self.action = slot, self.action_for(slot)
        self.answer, self.delivered = None, {"request": 0, "response": 0}
        reply = self.send("ARM", slot=slot, action=self.action)
        assert reply["status"] == "ok", reply
        return reply

    def connect(self):
        reply = self.send("RESERVE_CONNECTION", self.role, local_id=1)
        if reply["status"] == "wait":
            time.sleep(reply["retry_after_ms"] / 1000 + .005)
            reply = self.send("RESERVE_CONNECTION", self.role, local_id=1)
        assert reply["status"] == "ok", reply
        self.lease = reply["lease"]

    def operation(self):
        reply = self.send("RESERVE_OPERATION", self.role, lease=self.lease, kind=contract.operation(self.slot))
        assert reply["status"] == "ok", reply

    def reserve(self, direction, count):
        return self.send("RESERVE_BYTES", self.role, lease=self.lease, direction=direction, bytes=count)

    def observe(self, *, excluded=False):
        self.answer = semantic(self.selected["configuration"], excluded=excluded)
        self.delivered = {"request": 40, "response": 80}
        reply = self.send("OBSERVE_DNS", self.role, lease=self.lease, semantic=self.answer,
            request_sha256="1" * 64, original_answer_sha256="2" * 64, delivered_answer_sha256="3" * 64, response_bytes=80)
        assert reply["status"] == "ok", reply

    def finish_connection(self):
        reply = self.send("FINISH_CONNECTION", self.role, lease=self.lease,
            delivered_request_bytes=self.delivered["request"], delivered_response_bytes=self.delivered["response"], transcript_sha256="c" * 64)
        assert reply["status"] == "ok", reply
        self.lease = None

    def finish(self, *, success=True, observation=None):
        if self.lease is not None:
            self.finish_connection()
        reply = self.send("FINISH_ACTION", output_bytes=0, native_success=success,
            observation=self.answer if observation is None else observation, parsed_result_sha256="d" * 64, native_result_sha256="e" * 64)
        assert reply["status"] == "ok", reply
        self.binding = reply["binding"] or self.binding
        return reply

    def dns(self, *, request=40, response=80, excluded=False):
        self.arm("dns_1")
        self.connect()
        self.operation()
        assert self.reserve("request", request)["status"] == "ok"
        assert self.reserve("response", response)["status"] == "ok"
        self.observe(excluded=excluded)
        self.finish()

    def begin(self, operation):
        if operation != "dns":
            self.dns()
        self.arm("dns_1" if operation == "dns" else operation)
        self.connect()
        self.operation()

    def denied(self, reply, reason, before):
        assert (reply["status"], reply["reason"]) == ("denied", reason), reply
        after = self.snapshot()
        assert after["terminal"] and after["terminal_reason"] == reason
        assert after["counters"] == before["counters"]

    def stopped(self, message, *, role="launcher"):
        before = self.snapshots[-1]["ledger"]
        assert before["terminal"]
        try:
            self.exchange(message, role)
        except (ValueError, OSError):
            pass
        else:
            raise AssertionError("terminal owner accepted later work")
        self.topology._process.wait(timeout=3)
        assert self.topology._process.returncode == 78
        self.observations["terminal_attempt"] = {"role": role, "message": message, "closed_owner_refused": True}

    def worker(self):
        channel = self.channels[self.role]
        value = {"role": self.role, "action_sequence": self.action_sequence, "action_digest": contract.digest(self.action),
                 "deadline": self.control.deadline, "owner_identity_sha256": self.identity["owner_identity_sha256"]}
        child = subprocess.Popen([sys.executable, "-I", "-S", __file__, "channel-worker", str(channel.fileno()), json.dumps(value)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(channel.fileno(),))
        self.workers.append(child)
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode == 0 and not stderr, stderr
        result = json.loads(stdout)
        assert result["pid"] == child.pid
        self.sequence[self.role] = max(self.sequence[self.role], result["sequence"])
        return result

    def close(self):
        for child in self.workers:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
        for role, channel in self.channels.items():
            if role != "launcher":
                channel.close()
        closed = self.topology.close()
        assert closed["owner_exited"] and closed["descriptors_closed"]
        assert select.select([self.owner_pidfd], [], [], 2)[0]
        os.close(self.owner_pidfd)
        return closed


def run(probe, gate):
    name, op = gate["name"], gate["operation"]
    if name in ("wrong_channel_role", "message_sequence_replay", "message_sequence_gap", "action_sequence_changed", "action_digest_changed", "owner_identity_changed"):
        probe.arm("dns_1")
        if name == "message_sequence_replay":
            probe.connect()
            message = deepcopy(probe.observations["last_exchange"]["message"])
        else:
            role = "http_frontend" if name == "wrong_channel_role" else probe.role
            message = probe.message("RESERVE_CONNECTION", role, local_id=1)
            if name == "message_sequence_gap": message["sequence"] += 1
            elif name == "action_sequence_changed": message["action_sequence"] += 1
            elif name == "action_digest_changed": message["action_digest"] = "f" * 64
            elif name == "owner_identity_changed": message["owner_identity_sha256"] = "f" * 64
        before = probe.snapshot()
        reason = {"wrong_channel_role": "action_role_changed", "message_sequence_replay": "message_sequence_changed",
            "message_sequence_gap": "message_sequence_changed", "action_sequence_changed": "action_binding_changed",
            "action_digest_changed": "action_binding_changed", "owner_identity_changed": "owner_identity_changed"}[name]
        probe.denied(probe.exchange(message, "http_frontend" if name == "wrong_channel_role" else probe.role), reason, before)
    elif name in ("selection_changed", "runtime_changed"):
        raw = probe.action_for("dns_1")
        raw["parameters"]["selection_sha256" if name == "selection_changed" else "runtime_identity_sha256"] = "f" * 64
        before = probe.snapshot()
        probe.denied(probe.send("ARM", action_sequence=1, action_digest=contract.digest(raw), slot="dns_1", action=raw), "action_commitment_changed", before)
    elif name in ("finished_lease_replay", "bytes_before_operation", "operation_replay", "overlap_concurrency"):
        probe.arm("dns_1"); probe.connect()
        if name in ("finished_lease_replay", "operation_replay"): probe.operation()
        lease = probe.lease
        if name == "finished_lease_replay": probe.finish_connection()
        before = probe.snapshot()
        if name == "overlap_concurrency":
            reply, reason = probe.send("RESERVE_CONNECTION", probe.role, local_id=2), "concurrent_connection_limit"
        elif name == "operation_replay":
            reply, reason = probe.send("RESERVE_OPERATION", probe.role, lease=lease, kind="dns"), "operation_replayed"
        else:
            reply = probe.send("RESERVE_BYTES", probe.role, lease=lease, direction="request", bytes=1)
            reason = "connection_lease_changed" if name == "finished_lease_replay" else "operation_not_reserved"
        probe.denied(reply, reason, before)
    elif name == "worker_replacement_sequence_reset":
        probe.arm("dns_1")
        first = probe.worker()
        before = probe.snapshot()
        second = probe.worker()
        assert first["pid"] != second["pid"] and first["status"] == "ok"
        assert second["status"] == "denied" and second["reason"] == "message_sequence_changed"
        after = probe.snapshot()
        assert after["terminal_reason"] == "message_sequence_changed" and after["counters"] == before["counters"]
        probe.observations["replacement_workers"] = [first, second]
    elif name == "settled_slot_replay":
        probe.dns()
        raw = probe.action_for("dns_1")
        before = probe.snapshot()
        probe.denied(probe.send("ARM", action_sequence=2, action_digest=contract.digest(raw), slot="dns_1", action=raw), "slot_replayed", before)
    elif name in ("post_terminal_arm", "post_terminal_reservation", "channel_continuity_loss", "negative_http_terminal"):
        probe.dns()
        before = probe.snapshot()
        if name == "channel_continuity_loss":
            probe.channels["http_frontend"].close()
            for _ in range(20):
                time.sleep(.01)
                after = probe.snapshot()
                if after["terminal"]: break
            assert after["terminal_reason"] == "continuity_lost" and after["counters"] == before["counters"]
        else:
            reason = "declared_probe_refused" if name == "negative_http_terminal" else "cancelled"
            if name == "negative_http_terminal":
                from recon_cockpit.secure_agent.models import parse_action, ValidationError
                attempted = probe.action_for("http")
                attempted["parameters"]["host"] = "other.harbordesk.test:8080"
                try:
                    parse_action(attempted)
                except ValidationError as error:
                    probe.observations["host_mismatch_typed_refusal"] = {"proposal": attempted, "reason": error.code}
                else:
                    raise AssertionError("changed Host accepted")
            assert probe.send("STOP", reason=reason)["status"] == "ok"
            after = probe.snapshot()
            assert after["terminal_reason"] == reason and after["counters"] == before["counters"]
        raw = probe.action_for("tls" if name == "negative_http_terminal" else "http")
        if name == "post_terminal_reservation":
            message = probe.message("RESERVE_BYTES", "http_frontend", lease="f" * 64, direction="request", bytes=1)
            probe.stopped(message, role="http_frontend")
        else:
            probe.stopped(probe.message("ARM", action_sequence=2, slot=raw["parameters"]["operation_slot"], action=raw, action_digest=contract.digest(raw)))
    elif name == "cross_role_spacing":
        probe.dns()
        before = probe.snapshot()
        probe.arm("http")
        reply = probe.send("RESERVE_CONNECTION", probe.role, local_id=1)
        assert reply["status"] == "wait" and reply["reason"] == "admission_rate", reply
        assert probe.snapshot()["counters"]["connections"] == 1
        time.sleep(reply["retry_after_ms"] / 1000 + .005)
        probe.connect()
        after = probe.snapshot()
        assert after["last_admission_us"] - before["last_admission_us"] >= 250000
    elif name.startswith("per_action_"):
        probe.begin(op)
        direction = "request" if name == "per_action_request_bytes" else "response"
        cap = contract.action_bounds(probe.slot)[direction + "_bytes"]
        assert probe.reserve(direction, cap)["status"] == "ok"
        before = probe.snapshot()
        probe.denied(probe.reserve(direction, 1), "action_" + direction + "_bytes_limit", before)
    elif name in ("aggregate_request_bytes", "aggregate_response_bytes"):
        direction = "request" if name == "aggregate_request_bytes" else "response"
        probe.dns(request=512 if direction == "request" else 40, response=4096 if direction == "response" else 80)
        probe.arm("http"); probe.connect(); probe.operation()
        assert probe.reserve(direction, contract.action_bounds("http")[direction + "_bytes"])["status"] == "ok"
        probe.finish()
        probe.arm("tls"); probe.connect(); probe.operation()
        assert probe.reserve(direction, contract.action_bounds("tls")[direction + "_bytes"])["status"] == "ok"
        before = probe.snapshot()
        assert before["counters"][direction + "_bytes"] == contract.budgets(probe.selected)[direction + "_bytes"]
        probe.denied(probe.reserve(direction, 1), "aggregate_" + direction + "_bytes_limit", before)
    elif name in ("maximum_output_and_fourth_action", "maximum_connections_and_extra_refusal"):
        probe.dns()
        for slot in ("http", "tls"):
            probe.arm(slot); probe.connect(); probe.operation(); probe.finish()
        before = probe.snapshot()
        assert before["counters"]["output_bytes"] == 18432 and before["counters"]["connections"] == 3
        assert before["counters"]["actions"] == 3 and before["terminal_reason"] == "completed"
        probe.stopped(probe.message("ARM", action_sequence=4, slot="dns_1", action=probe.action_for("dns_1")))
    elif name == "retained_output_over_reservation":
        probe.arm("dns_1")
        before = probe.snapshot()
        probe.denied(probe.send("FINISH_ACTION", output_bytes=8193, native_success=False, observation=None,
            parsed_result_sha256="d" * 64, native_result_sha256="e" * 64), "output_bytes_limit", before)
    elif name == "real_action_deadline":
        if op != "dns": probe.dns()
        probe.arm("dns_1" if op == "dns" else op)
        before = probe.snapshot()
        seconds = contract.action_bounds(probe.slot)["hard_action_seconds"]
        time.sleep(seconds + .1)
        after = probe.snapshot()
        assert after["terminal_reason"] == "action_deadline" and after["counters"] == before["counters"]
        assert after["elapsed_us"] - before["actions"][-1]["armed_us"] >= seconds * 1000000
        probe.stopped(probe.message("RESERVE_CONNECTION", probe.role, local_id=1), role=probe.role)
    elif name in ("unwritten_reservation_no_refund", "failed_write_reservation_no_refund"):
        probe.dns()
        probe.arm("http"); probe.connect(); probe.operation()
        assert probe.reserve("response", 2048)["status"] == "ok"
        before = probe.snapshot()
        if name.startswith("failed"):
            sender, receiver = socket.socketpair()
            receiver.close()
            try:
                sender.send(b"x" * 2048)
            except BrokenPipeError as error:
                assert error.errno == errno.EPIPE
                probe.observations["actual_failed_write_errno"] = error.errno
            else: raise AssertionError("closed peer accepted bytes")
            finally: sender.close()
        probe.finish()
        assert probe.snapshot()["counters"] == before["counters"]
        probe.arm("tls"); probe.connect(); probe.operation()
        assert probe.reserve("response", 1)["status"] == "ok"
        assert probe.snapshot()["counters"]["response_bytes"] == 2129
    elif name in ("negative_dns_terminal", "negative_tls_terminal", "negative_profile_dns_prerequisite_active"):
        probe.dns(excluded=name == "negative_dns_terminal")
        if name != "negative_dns_terminal":
            assert not probe.snapshot()["terminal"] and probe.binding is not None
            probe.arm("tls"); probe.connect(); probe.operation(); probe.finish(success=False)
        after = probe.snapshot()
        assert after["terminal_reason"] == "declared_negative_completed"
        probe.stopped(probe.message("ARM", action_sequence=3, slot="http", action=probe.action_for("dns_1")))
    elif name == "parser_report_only_binding":
        probe.arm("dns_1"); probe.connect(); probe.operation()
        assert probe.reserve("request", 40)["status"] == "ok" and probe.reserve("response", 80)["status"] == "ok"
        probe.finish_connection()
        before = probe.snapshot()
        probe.denied(probe.send("FINISH_ACTION", output_bytes=10, native_success=True, observation=semantic(),
            parsed_result_sha256="d" * 64, native_result_sha256="e" * 64), "dns_native_wire_disagreement", before)
        assert probe.snapshots[-1]["ledger"]["binding"] is None
    elif name == "missing_binding":
        before = probe.snapshot()
        probe.denied(probe.send("ARM", action_sequence=1, slot="http", action=probe.action_for("dns_1")), "binding_missing", before)
    else:
        changes = {"forged_binding_digest": ("binding_sha256", "f" * 64), "changed_generation": ("observation_generation", 2),
            "changed_answer_digest": ("observed_answer_sha256", "f" * 64), "changed_ttl": ("observed_ttl_seconds", 59),
            "changed_observed_time": ("observed_at_us", 1), "extended_expiry": ("expires_at_us", 60000001),
            "changed_numeric_endpoint": ("target", "10.77.0.99"), "changed_canonical_name": ("canonical_name", "other.harbordesk.test"),
            "changed_http_host": ("host", "other.harbordesk.test:8080"), "changed_tls_sni": ("sni", "other.harbordesk.test"),
            "changed_certificate_name": ("expected_certificate_name", "other.harbordesk.test"),
            "changed_ca_digest": ("public_ca_sha256", "f" * 64), "binding_runtime_changed": ("runtime_identity_sha256", "f" * 64)}
        assert name in changes, name
        probe.dns()
        slot = "tls" if name in ("changed_tls_sni", "changed_certificate_name", "changed_ca_digest") else "http"
        raw = probe.action_for(slot)
        key, changed = changes[name]
        if key == "target":
            raw[key] = changed
        else:
            assert key in raw["parameters"]
            raw["parameters"][key] = changed
        before = probe.snapshot()
        probe.denied(probe.send("ARM", action_sequence=2, slot=slot, action=raw, action_digest=contract.digest(raw)), "action_commitment_changed", before)


def channel_worker(descriptor, value):
    from recon_cockpit.secure_agent.name_tls_frontend_worker import BudgetChannel, BudgetRefused
    channel = socket.socket(fileno=descriptor)
    budget = BudgetChannel(channel, value["role"], value["deadline"], value["owner_identity_sha256"])
    budget.bind(value["action_sequence"], value["action_digest"])
    result = {"pid": os.getpid(), "role": value["role"], "instrumented_role_worker": True}
    try:
        assert budget.connection(1)
        budget.request("dns")
        budget.finish(request_bytes=0, response_bytes=0, transcript_sha256="c" * 64, reason="test_worker_finished")
        result.update(status="ok", reason=None)
    except BudgetRefused:
        result.update(status="denied", reason=budget.last_reply["reason"])
    finally:
        channel.close()
    result["sequence"] = budget.sequence
    print(json.dumps(result, sort_keys=True))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "channel-worker":
        descriptor = int(sys.argv[2]); entry((descriptor,)); imports()
        channel_worker(descriptor, json.loads(sys.argv[3])); return
    assert len(sys.argv) == 2
    entry(); imports()
    raw = sys.stdin.buffer.read(262145)
    assert len(raw) <= 262144
    value = json.loads(raw)
    assert set(value) == {"selection", "identity", "runtime", "host_namespaces", "gate"}
    assert all(os.readlink("/proc/self/ns/" + name) != identity for name, identity in value["host_namespaces"].items())
    topology.Topology._assert_launcher()
    from recon_cockpit.secure_agent import planner_worker as bootstrap
    bootstrap._zero_capabilities(); bootstrap._no_new_privileges(); bootstrap._root_read_only()
    for kind, limit in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30), (resource.RLIMIT_NOFILE, 128),
                        (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 16777216), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(kind, (limit, limit))
    probe = Probe(value)
    try:
        probe.start()
        run(probe, value["gate"])
        receipt = {"schema_version": "1", "gate_id": value["gate"]["id"], "selection": probe.selected,
            "identity": probe.identity, "topology": probe.topology.identity, "owner_pid": probe.owner_pid,
            "snapshots": probe.snapshots, "observations": probe.observations,
            "instrumented_owner_probe": True, "daemon_or_native_client_executed": False,
            "claimed_daemon_payload_bytes": 0, "actual_provider_calls": 0}
    finally:
        closure = probe.close()
    receipt.update(closure=closure, test_passed=True)
    encoded = json.dumps(receipt, sort_keys=True)
    assert len(encoded) <= 1048576
    print(encoded)


if __name__ == "__main__":
    main()
