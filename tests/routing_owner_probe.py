"""Test-only driver for the unchanged isolated routing owner and role channels.

This is an instrumented enforcement harness, never a production entry point.
It reserves capacity without executing a daemon or native client. Its outer
watchdog can outlive the real sixty-second owner solely to observe cleanup.
"""

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


def _entry_descriptors(allowed=()):
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor <= 2 or descriptor in allowed:
            continue
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        raise AssertionError("probe inherited an unrelated descriptor")
    assert all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1, 2))


def _imports():
    sys.path.insert(0, "/app")
    global contract, ledger, transport, ExecutionControl, runtime, bootstrap
    from recon_cockpit.secure_agent import routing_contract as contract
    from recon_cockpit.secure_agent import routing_ledger as ledger
    from recon_cockpit.secure_agent import routing_topology as transport
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.owned_launcher_runtime import runtime
    from recon_cockpit.secure_agent import planner_worker as bootstrap


class Probe:
    def __init__(self, value, case):
        self.selected = contract.validate_selection(value["selection"])
        profile = {"declared_http_negative_stops_owner": "http_headers_N1",
                   "declared_ssh_negative_stops_owner": "ssh_nmap_N1"}.get(case, "baseline")
        assert self.selected == contract.selection(deployment="nginx-A", case_profile=profile)
        self.identity = contract.validate_identity(value["identity"], selection=self.selected,
            runtime=value["runtime"]["routing_runtime"])
        self.started = time.monotonic()
        self.control = ExecutionControl(self.started + 60)
        self.topology = transport.Topology(runtime(value["runtime"], owner=True), self.control,
            selection=self.selected, identity=self.identity)
        self.channels = {}
        self.sequences = dict.fromkeys(ledger.ROLES, 0)
        self.action_sequence = 0
        self.action_digest = contract.digest(self.selected)
        self.selector = None
        self.lease = None
        self.messages = []
        self.snapshots = []
        self.observations = {}
        self.workers = []

    def start(self):
        self.topology.start()
        self.owner_pid = self.topology._process.pid
        self.owner_pidfd = os.pidfd_open(self.owner_pid)
        for role in ("http_frontend", "ssh_frontend"):
            service = role.split("_")[0]
            descriptor = self.topology._descriptors.pop(service + "_ledger_channel")
            self.channels[role] = socket.socket(fileno=descriptor)
        self.channels["launcher"] = self.topology._channel
        self.snapshot()

    def snapshot(self):
        # The test harness uses the real owner's read-only snapshot protocol;
        # replay checks the actual event stream rather than trusted counters.
        snapshot = self.topology.ledger_snapshot()
        ledger.validate_snapshot(snapshot, selected=self.selected, identity=self.identity)
        self.snapshots.append(snapshot)
        assert len(self.snapshots) <= 20
        return snapshot

    def message(self, operation, *, role="launcher", sequence=None, action_sequence=None,
                action_digest=None, **fields):
        if sequence is None:
            self.sequences[role] += 1
            sequence = self.sequences[role]
        return {"operation": operation, "sequence": sequence,
            "action_sequence": self.action_sequence if action_sequence is None else action_sequence,
            "action_digest": self.action_digest if action_digest is None else action_digest, **fields}

    def exchange(self, message, *, role):
        channel = self.channels[role]
        transport.send_packet(channel, message)
        reply, _ = transport.receive_packet(channel)
        ledger.validate_reply(reply, message, role=role)
        self.messages.append({"role": role, "message": deepcopy(message), "reply": reply})
        assert len(self.messages) <= 128
        return reply

    def call(self, operation, *, role="launcher", **fields):
        return self.exchange(self.message(operation, role=role, **fields), role=role)

    def arm(self, selector, **changed):
        self.selector = selector
        self.action_sequence += 1
        self.action_digest = contract.digest(contract.action(self.selected, selector))
        fields = {"selector": selector, "runtime_digests": self.identity["runtimes"][selector], **changed}
        reply = self.call("ARM", **fields)
        self.expect(reply, "ok")
        return reply

    @property
    def role(self):
        return contract.selector_role(self.selector)

    def connect(self):
        reply = self.call("RESERVE_CONNECTION", role=self.role, local_id=1)
        if reply["status"] == "wait":
            self.expect(reply, "wait", "admission_rate")
            time.sleep(reply["retry_after_ms"] / 1000 + .005)
            reply = self.call("RESERVE_CONNECTION", role=self.role, local_id=1)
        self.expect(reply, "ok")
        self.lease = reply["lease"]
        return reply

    def request(self):
        reply = self.call("RESERVE_REQUEST", role=self.role, lease=self.lease,
            kind="http" if self.role == "http_frontend" else "kex")
        self.expect(reply, "ok")

    def reserve(self, direction, count):
        return self.call("RESERVE_BYTES", role=self.role, lease=self.lease,
            direction=direction, bytes=count)

    def finish_connection(self):
        self.expect(self.call("FINISH_CONNECTION", role=self.role, lease=self.lease), "ok")
        self.lease = None

    def finish(self):
        if self.lease is not None:
            self.finish_connection()
        self.expect(self.call("FINISH_ACTION", output_bytes=0), "ok")

    @staticmethod
    def expect(reply, status, reason=None):
        assert (reply["status"], reply["reason"]) == (status, reason), reply

    def denied(self, reply, reason, *, unchanged=None):
        self.expect(reply, "denied", reason)
        snapshot = self.snapshot()
        assert snapshot["terminal"] and snapshot["terminal_reason"] == reason
        if unchanged is not None:
            assert snapshot["counters"] == unchanged["counters"]
        return snapshot

    def channel_closed(self, operation, *, role, **fields):
        message = self.message(operation, role=role, **fields)
        try:
            transport.send_packet(self.channels[role], message)
            transport.receive_packet(self.channels[role])
        except (ValueError, OSError):
            pass
        else:
            raise AssertionError("terminal owner issued another reply")
        self.topology._process.wait(timeout=3)
        assert self.topology._process.returncode == 78
        self.observations["further_work_refused_by_closed_owner"] = True
        self.observations["attempted_post_terminal_message"] = {"role": role, "message": message}

    def worker(self):
        # Each invocation is a different real process with fresh BudgetChannel
        # state. Only the already bound role socket is inherited. The parent
        # retains its copy, so this measures replacement, not channel EOF.
        channel = self.channels[self.role]
        value = {"role": self.role, "action_sequence": self.action_sequence,
            "action_digest": self.action_digest, "deadline": self.control.deadline}
        process = subprocess.Popen([sys.executable, "-I", "-S", __file__, "channel-worker",
            str(channel.fileno()), json.dumps(value)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(channel.fileno(),))
        self.workers.append(process)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr.decode("utf-8", "replace")
        assert len(stdout) < 4096 and not stderr
        result = json.loads(stdout)
        assert result["pid"] == process.pid and result["role"] == self.role
        return result

    def close(self):
        for process in self.workers:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
        for role, channel in self.channels.items():
            if role != "launcher":
                channel.close()
        receipt = self.topology.close()
        assert receipt["owner_exited"] and receipt["descriptors_closed"]
        if hasattr(self, "owner_pidfd"):
            assert select.select([self.owner_pidfd], [], [], 2)[0] == [self.owner_pidfd]
            os.close(self.owner_pidfd)
        return receipt


def _saturate(probe, direction):
    key = direction + "_bytes"
    for selector in contract.SELECTORS:
        probe.arm(selector)
        probe.connect()
        if selector != "ssh_nmap":
            probe.request()
        count = contract.action_bounds(selector)[key]
        if count:
            probe.expect(probe.reserve(direction, count), "ok")
        if selector != contract.SELECTORS[-1]:
            probe.finish()
    before = probe.snapshot()
    assert before["counters"][key] == contract.budgets(probe.selected)[key]
    probe.denied(probe.reserve(direction, 1), "aggregate_" + key + "_limit", unchanged=before)


def run_case(probe, case):
    if case == "cross_role_spacing":
        probe.arm("http_headers")
        probe.connect()
        probe.finish()
        before = probe.snapshot()
        probe.arm("ssh_nmap")
        reply = probe.call("RESERVE_CONNECTION", role=probe.role, local_id=1)
        probe.expect(reply, "wait", "admission_rate")
        waiting = probe.snapshot()
        assert waiting["counters"]["connections"] == before["counters"]["connections"] == 1
        time.sleep(reply["retry_after_ms"] / 1000 + .005)
        probe.connect()
        after = probe.snapshot()
        assert after["last_admission_us"] - before["last_admission_us"] >= 250000
        probe.finish()
    elif case == "overlap_concurrency":
        probe.arm("ssh_keys"); probe.connect()
        before = probe.snapshot()
        probe.denied(probe.call("RESERVE_CONNECTION", role=probe.role, local_id=2),
            "concurrency_limit", unchanged=before)
    elif case in ("aggregate_request_bytes", "aggregate_response_bytes"):
        _saturate(probe, "request" if case == "aggregate_request_bytes" else "response")
    elif case in ("action_request_bytes", "action_response_bytes"):
        probe.arm("http_headers"); probe.connect(); probe.request()
        direction = "request" if case == "action_request_bytes" else "response"
        before = probe.snapshot()
        probe.denied(probe.reserve(direction, contract.action_bounds(probe.selector)[direction + "_bytes"] + 1),
            "action_" + direction + "_bytes_limit", unchanged=before)
    elif case == "maximum_output_and_fifth_action":
        for selector in contract.SELECTORS:
            probe.arm(selector); probe.finish()
        before = probe.snapshot()
        assert before["counters"]["actions"] == 4
        assert before["counters"]["output_bytes"] == 26624
        reply = probe.call("ARM", action_sequence=5, selector="http_headers",
            action_digest=contract.digest(contract.action(probe.selected, "http_headers")),
            runtime_digests=probe.identity["runtimes"]["http_headers"])
        probe.denied(reply, "invalid_action_sequence", unchanged=before)
    elif case == "retained_output_excess":
        probe.arm("http_headers")
        before = probe.snapshot()
        probe.denied(probe.call("FINISH_ACTION", output_bytes=2049), "output_bytes_limit", unchanged=before)
    elif case == "action_deadline":
        probe.arm("http_headers")
        before = probe.snapshot()
        time.sleep(1.05)
        after = probe.snapshot()
        assert after["terminal"] and after["terminal_reason"] == "action_deadline"
        assert after["counters"] == before["counters"]
        assert after["elapsed_us"] - before["actions"][0]["armed_us"] >= 1000000
        probe.channel_closed("RESERVE_CONNECTION", role=probe.role, local_id=1)
    elif case == "owner_lifetime":
        before = probe.snapshot()
        assert before["counters"]["actions"] == 0 and not before["terminal"]
        # This intentionally does not use the launcher's deadline-bound waiter:
        # the independent test watchdog only observes the real owner exit.
        probe.topology._process.wait(timeout=max(.1, probe.control.deadline - time.monotonic()) + 3)
        elapsed = time.monotonic() - probe.started
        assert 60 <= elapsed < 64, elapsed
        assert probe.topology._process.returncode == 78
        probe.observations["owner_lifetime_elapsed_ms"] = round(elapsed * 1000)
        probe.channel_closed("ARM", role="launcher", action_sequence=1,
            action_digest=contract.digest(contract.action(probe.selected, "http_headers")),
            selector="http_headers", runtime_digests=probe.identity["runtimes"]["http_headers"])
    elif case == "failed_write_no_refund":
        from recon_cockpit.secure_agent.routing_frontend_worker import BudgetChannel
        probe.arm("http_headers")
        budget = BudgetChannel(probe.channels[probe.role], probe.role, probe.control.deadline)
        budget.bind(probe.action_sequence, probe.action_digest)
        assert budget.connection(1)
        budget.request("http")
        active = {}
        budget.before_write(active, "response", 2048)
        before = probe.snapshot()
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        receiver.close()
        try:
            sender.send(b"x" * 2048)
        except BrokenPipeError as error:
            assert error.errno == errno.EPIPE
            probe.observations["closed_test_socket_write_errno"] = error.errno
        else:
            raise AssertionError("closed test socket accepted a write")
        finally:
            sender.close()
        assert active["routing_credit"]["response"] == 2048
        budget.finish()
        probe.sequences[probe.role] = budget.sequence
        probe.messages.extend({"role": probe.role, **row} for row in budget.reservations)
        probe.expect(probe.call("FINISH_ACTION", output_bytes=0), "ok")
        settled = probe.snapshot()
        assert settled["counters"] == before["counters"]
        assert settled["actions"][0]["output_bytes_retained"] == 0
        probe.arm("ssh_nmap"); probe.connect()
        probe.expect(probe.reserve("response", 255), "ok")
        after = probe.snapshot()
        assert after["counters"]["response_bytes"] == 2303
        assert after["actions"][0]["counters"]["response_bytes"] == 2048
        probe.denied(probe.reserve("response", 1), "action_response_bytes_limit", unchanged=after)
    elif case == "worker_replacement_sequence":
        probe.arm("http_nmap")
        first = probe.worker()
        assert first["status"] == "ok" and first["sequence"] == 3
        before = probe.snapshot()
        second = probe.worker()
        assert first["pid"] != second["pid"]
        assert second["status"] == "denied" and second["reason"] == "message_sequence_changed"
        after = probe.snapshot()
        assert after["terminal_reason"] == "message_sequence_changed"
        assert after["identity"] == before["identity"] and after["counters"] == before["counters"]
        assert before["counters"]["connections"] == before["counters"]["http_requests"] == 1
        probe.observations["channel_workers"] = [first, second]
    elif case in ("changed_selection", "changed_runtime", "changed_action_digest"):
        selector = "http_headers"
        digest = contract.digest(contract.action(probe.selected, selector))
        runtimes = deepcopy(probe.identity["runtimes"][selector])
        if case == "changed_selection":
            other = contract.selection(deployment="nginx-A", case_profile="http_headers_N1")
            digest = contract.digest(contract.action(other, selector))
            assert digest != contract.digest(contract.action(probe.selected, selector))
        elif case == "changed_runtime":
            runtimes["daemon_runtime_sha256"] = "f" * 64
            assert runtimes != probe.identity["runtimes"][selector]
        else:
            digest = "f" * 64
        before = probe.snapshot()
        reply = probe.call("ARM", action_sequence=1, action_digest=digest,
            selector=selector, runtime_digests=runtimes)
        probe.denied(reply, "runtime_identity_changed" if case == "changed_runtime" else "action_digest_changed",
            unchanged=before)
    elif case == "wrong_channel_role":
        probe.arm("http_headers")
        before = probe.snapshot()
        probe.denied(probe.call("RESERVE_CONNECTION", role="ssh_frontend", local_id=1),
            "action_role_changed", unchanged=before)
    elif case == "message_sequence_replay":
        probe.arm("http_headers"); probe.connect()
        original = deepcopy(probe.messages[-1]["message"])
        before = probe.snapshot()
        probe.denied(probe.exchange(original, role=probe.role), "message_sequence_changed", unchanged=before)
    elif case == "changed_action_sequence":
        probe.arm("http_headers")
        before = probe.snapshot()
        probe.denied(probe.call("RESERVE_CONNECTION", role=probe.role, local_id=1, action_sequence=2),
            "action_binding_changed", unchanged=before)
    elif case == "finished_lease_replay":
        probe.arm("http_headers"); probe.connect(); probe.request()
        lease = probe.lease
        probe.finish_connection()
        before = probe.snapshot()
        probe.denied(probe.call("RESERVE_BYTES", role=probe.role, lease=lease, direction="request", bytes=1),
            "connection_lease_changed", unchanged=before)
    elif case == "channel_continuity_loss":
        probe.arm("http_headers"); probe.connect(); probe.request(); probe.finish()
        before = probe.snapshot()
        probe.channels["http_frontend"].close()
        # Wait for the actual owner's EOF event, never force its local state.
        for _ in range(10):
            time.sleep(.05)
            after = probe.snapshot()
            if after["terminal"]:
                break
        assert after["terminal"] and after["terminal_reason"] == "continuity_lost"
        assert after["counters"] == before["counters"]
        probe.channel_closed("ARM", role="launcher", action_sequence=2, selector="ssh_keys",
            action_digest=contract.digest(contract.action(probe.selected, "ssh_keys")),
            runtime_digests=probe.identity["runtimes"]["ssh_keys"])
    elif case == "post_terminal_reservation":
        probe.arm("http_headers"); probe.connect(); probe.request()
        before = probe.snapshot()
        probe.denied(probe.reserve("response", 2049), "action_response_bytes_limit", unchanged=before)
        probe.channel_closed("RESERVE_BYTES", role=probe.role, lease=probe.lease, direction="response", bytes=1)
    elif case == "bytes_before_kex":
        probe.arm("ssh_keys"); probe.connect()
        before = probe.snapshot()
        probe.denied(probe.reserve("request", 1), "request_not_reserved", unchanged=before)
    elif case == "request_replay":
        probe.arm("http_headers"); probe.connect(); probe.request()
        before = probe.snapshot()
        probe.denied(probe.call("RESERVE_REQUEST", role=probe.role, lease=probe.lease, kind="http"),
            "request_replayed", unchanged=before)
    elif case == "settled_selector_replay":
        probe.arm("http_headers"); probe.finish()
        before = probe.snapshot()
        probe.denied(probe.call("ARM", action_sequence=2, selector=probe.selector,
            runtime_digests=probe.identity["runtimes"][probe.selector]), "selector_replayed", unchanged=before)
    elif case in ("declared_http_negative_stops_owner", "declared_ssh_negative_stops_owner"):
        selector = "http_headers" if case == "declared_http_negative_stops_owner" else "ssh_nmap"
        later = "ssh_keys"
        probe.arm(selector); probe.connect()
        if selector == "http_headers":
            probe.request()
        probe.finish_connection()
        before = probe.snapshot()
        assert not before["terminal"]
        probe.finish()
        after = probe.snapshot()
        assert after["terminal"] and after["terminal_reason"] == "declared_negative_completed"
        assert after["counters"] == before["counters"]
        assert after["counters"]["actions"] == 1 and after["actions"][-1]["status"] == "finished"
        probe.channel_closed("ARM", role="launcher", action_sequence=2, selector=later,
            action_digest=contract.digest(contract.action(probe.selected, later)),
            runtime_digests=probe.identity["runtimes"][later])
    else:
        raise AssertionError("unlisted owner probe")


def channel_worker(descriptor, value):
    from recon_cockpit.secure_agent.routing_frontend_worker import BudgetChannel, BudgetRefused
    channel = socket.socket(fileno=descriptor)
    budget = BudgetChannel(channel, value["role"], value["deadline"])
    budget.bind(value["action_sequence"], value["action_digest"])
    result = {"pid": os.getpid(), "role": value["role"], "instrumented_channel_worker": True}
    try:
        assert budget.connection(1)
        budget.request("http")
        budget.finish()
        result.update(status="ok", reason=None)
    except BudgetRefused:
        assert budget.last_reply is not None and budget.last_reply["status"] == "denied"
        result.update(status="denied", reason=budget.last_reply["reason"])
    finally:
        channel.close()
    result["sequence"] = budget.sequence
    print(json.dumps(result, sort_keys=True))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "channel-worker":
        descriptor = int(sys.argv[2])
        _entry_descriptors((descriptor,))
        _imports()
        channel_worker(descriptor, json.loads(sys.argv[3]))
        return
    assert len(sys.argv) == 2
    _entry_descriptors()
    _imports()
    raw = sys.stdin.buffer.read(131073)
    assert len(raw) <= 131072
    value = json.loads(raw)
    assert set(value) == {"selection", "identity", "runtime", "host_namespaces"}
    assert all(os.readlink("/proc/self/ns/" + name) != identity
               for name, identity in value["host_namespaces"].items())
    # Match the production private launcher's custody/privilege/resource checks;
    # this test entry does not claim audit, approval or client launch authority.
    transport.Topology._assert_launcher()
    bootstrap._zero_capabilities()
    bootstrap._no_new_privileges()
    bootstrap._root_read_only()
    for kind, limit in ((resource.RLIMIT_AS, 256 * 1048576), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CORE, 0),
                        (resource.RLIMIT_FSIZE, 16 * 1048576), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(kind, (limit, limit))
    probe = Probe(value, sys.argv[1])
    try:
        probe.start()
        run_case(probe, sys.argv[1])
        receipt = {"schema_version": "1", "test_kind": "instrumented_routing_owner_channel_probe",
            "case": sys.argv[1], "selection": probe.selected, "identity": probe.identity,
            "topology": probe.topology.identity, "owner_pid": probe.owner_pid,
            "messages": probe.messages, "snapshots": probe.snapshots,
            "observations": probe.observations, "daemon_or_native_client_executed": False,
            "claimed_daemon_payload_bytes": 0, "actual_provider_calls": 0, "actual_cost_microusd": 0}
    finally:
        closure = probe.close()
    receipt.update(closure=closure, test_passed=True)
    encoded = json.dumps(receipt, sort_keys=True, allow_nan=False)
    assert len(encoded) < 524288
    print(encoded)


if __name__ == "__main__":
    main()
