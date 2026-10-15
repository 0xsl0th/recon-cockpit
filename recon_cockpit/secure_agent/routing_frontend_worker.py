"""Routed fixed-protocol frontends with live owner-budget reservations."""

import errno
import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                raise
            raise ValueError("routing_frontend_inherited_descriptor")


ENTRY_DESCRIPTORS_VERIFIED = False
if __name__ == "__main__":
    try:
        private_descriptors()
        ENTRY_DESCRIPTORS_VERIFIED = True
    except Exception:
        sys.stderr.write("routing_frontend_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

from copy import deepcopy
import math
import select
import socket
import stat
import time

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from recon_cockpit.secure_agent import stock_http_recorder as http, stock_ssh_recorder as ssh
from recon_cockpit.secure_agent import stock_http_owner_worker as existing, stock_ssh_owner_worker as ssh_owner
from recon_cockpit.secure_agent import worker, tool_worker_common as common
from recon_cockpit.secure_agent.stock_ssh_owner_worker import send_packet, receive_packet, encode, decode


class BudgetRefused(OSError):
    """Expected owner denial; no corresponding private transport may proceed."""


class BudgetChannel:
    def __init__(self, channel, role, deadline):
        if role not in ("http_frontend", "ssh_frontend"):
            raise ValueError("routing_frontend_role_changed")
        self.channel, self.role, self.deadline = channel, role, deadline
        self.sequence, self.action_sequence = 0, 0
        self.action_digest = None
        self.lease, self.failed, self.last_reply = None, False, None
        self.continuity_lost = False
        self.reservations = []
        self.retry_at = 0

    def bind(self, action_sequence, action_digest):
        if (self.failed or self.lease is not None or type(action_sequence) is not int
                or not self.action_sequence < action_sequence <= 4 or type(action_digest) is not str
                or not contract._HASH.fullmatch(action_digest)):
            raise ValueError("routing_frontend_action_binding_changed")
        self.action_sequence, self.action_digest = action_sequence, action_digest
        self.reservations, self.last_reply = [], None
        self.retry_at = 0

    def call(self, operation, **fields):
        cleanup = operation == "FINISH_CONNECTION"
        if (self.continuity_lost or self.failed and not cleanup or self.action_digest is None
                or time.monotonic() >= self.deadline and not cleanup):
            raise BudgetRefused("routing_frontend_budget_unavailable")
        self.sequence += 1
        message = {"operation": operation, "sequence": self.sequence,
            "action_sequence": self.action_sequence, "action_digest": self.action_digest, **fields}
        if len(encode(message)) > ledger.MAX_MESSAGE_BYTES:
            raise ValueError("routing_frontend_budget_message_limit")
        try:
            self.channel.settimeout(min(1, max(.001, self.deadline - time.monotonic())))
            send_packet(self.channel, message)
            reply, _ = receive_packet(self.channel, descriptor_required=False)
            reply = ledger.validate_reply(reply, message, role=self.role)
        except BaseException:
            self.failed = True
            self.continuity_lost = True
            raise
        finally:
            self.channel.setblocking(False)
        self.last_reply = reply
        if len(self.reservations) >= 128:
            self.failed = True
            raise ValueError("routing_frontend_reservation_record_limit")
        self.reservations.append({"message": message, "reply": reply})
        if reply["status"] == "denied":
            self.failed = True
            raise BudgetRefused(reply["reason"])
        return reply

    def connection(self, local_id):
        if self.lease is not None:
            raise ValueError("routing_frontend_overlapping_lease")
        if time.monotonic() < self.retry_at:
            return False
        reply = self.call("RESERVE_CONNECTION", local_id=local_id)
        if reply["status"] == "wait":
            self.retry_at = time.monotonic() + reply["retry_after_ms"] / 1000
            return False
        self.lease = reply["lease"]
        return True

    def request(self, kind):
        self.call("RESERVE_REQUEST", lease=self.lease, kind=kind)

    def before_write(self, active, direction, amount):
        if type(amount) is not int or amount <= 0:
            raise ValueError("routing_frontend_invalid_write")
        credit = active.setdefault("routing_credit", {"request": 0, "response": 0})
        extra = max(0, amount - credit[direction])
        if extra:
            self.call("RESERVE_BYTES", lease=self.lease, direction=direction, bytes=extra)
            credit[direction] += extra

    def after_write(self, active, direction, count):
        credit = active["routing_credit"]
        if type(count) is not int or not 0 <= count <= credit[direction]:
            raise ValueError("routing_frontend_write_exceeded_reservation")
        credit[direction] -= count

    def finish(self):
        if self.lease is not None:
            lease, self.lease = self.lease, None
            if not self.continuity_lost:
                self.call("FINISH_CONNECTION", lease=lease)


class HttpService(http.Service):
    def __init__(self, selector, listener, *, deadline, budget):
        if selector not in ("http_nmap", "http_headers"):
            raise ValueError("routing_frontend_http_selector_changed")
        if (listener.family != socket.AF_INET or listener.getsockname() != ("10.77.0.10", 8080)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("routing_frontend_http_listener_changed")
        self.budget, self.selector = budget, selector
        super().__init__("A", contract.underlying_selection(selector)["case"], listener, deadline=deadline)

    def _admit(self):
        now = time.monotonic()
        if (self.active is not None or not self.pending or self.ledger["requests_validated"]
                or self.last_admission is not None and now - self.last_admission < .25):
            return super()._admit()
        try:
            if self.budget.connection(self.ledger["connections_admitted"] + 1):
                super()._admit()
        except BudgetRefused:
            self.close("io_failure")

    def _connect_daemon(self):
        self.budget.request("http")
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.setblocking(False)
        try:
            result = channel.connect_ex("/peer/" + self.selector + "/nginx.sock")
            if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                raise OSError(result, "routing_private_nginx_unavailable")
            return channel
        except BaseException:
            channel.close()
            raise

    def _write_daemon(self):
        active = self.active
        self.budget.before_write(active, "request", len(self.expected) - active["request_sent"])
        before = self.ledger["request_bytes_delivered"]
        super()._write_daemon()
        self.budget.after_write(active, "request", self.ledger["request_bytes_delivered"] - before)

    def _write_client(self):
        active = self.active
        self.budget.before_write(active, "response", len(active["chunks"][active["chunk_index"]]) - active["offset"])
        before = self.ledger["client_response_bytes"]
        super()._write_client()
        self.budget.after_write(active, "response", self.ledger["client_response_bytes"] - before)

    def _finish_active(self, *, reset=False):
        active = self.active
        super()._finish_active(reset=reset)
        if active is not None:
            self.budget.finish()


class SshService(ssh.Service):
    def __init__(self, selector, listener, *, deadline, budget, connection_factory, connection_finalizer):
        if selector not in ("ssh_nmap", "ssh_keys"):
            raise ValueError("routing_frontend_ssh_selector_changed")
        self.budget = budget
        super().__init__("A", contract.underlying_selection(selector)["case"], listener, deadline=deadline,
                         connection_factory=connection_factory, connection_finalizer=connection_finalizer)

    def _admit(self):
        if (self.active is not None or not self.pending
                or self.last_admission is not None and time.monotonic() - self.last_admission < .25):
            return
        try:
            if self.budget.connection(self.ledger["connections_admitted"] + 1):
                super()._admit()
        except BudgetRefused:
            self.close("io_failure")

    def _write(self, direction):
        active = self.active
        if direction == "daemon":
            if not active.get("routing_request_reserved"):
                self.budget.request("kex")
                active["routing_request_reserved"] = True
            offered = len(active["to_daemon"])
            kind, counter = "request", "client_bytes_forwarded"
        else:
            offered = len(active["chunks"][0]) - active["chunk_offset"]
            kind, counter = "response", "client_bytes_delivered"
        self.budget.before_write(active, kind, offered)
        before = self.ledger[counter]
        super()._write(direction)
        self.budget.after_write(active, kind, self.ledger[counter] - before)

    def _finish(self, reason, *, denied=False):
        active = self.active
        super()._finish(reason, denied=denied)
        if active is not None and not active.get("cleanup_failed"):
            self.budget.finish()


def _receive_fd(channel, operation):
    message, descriptor = receive_packet(channel, descriptor_required=True)
    if message != {"operation": operation}:
        os.close(descriptor)
        raise ValueError("routing_frontend_descriptor_order_changed")
    return descriptor


def require_idle_listener(listener):
    """A persistent listener cannot carry an old client's backlog into an action."""
    if select.select([listener], [], [], 0)[0]:
        raise ValueError("routing_frontend_unbound_connection")


def main():
    # The topology passes only finite descriptors over this inherited channel;
    # no route/firewall operation or private peer discovery exists here.
    channel = listener = budget_socket = None
    service = channels = None
    pairs = []
    try:
        if not ENTRY_DESCRIPTORS_VERIFIED or len(sys.argv) != 1:
            raise ValueError("routing_frontend_invalid_bootstrap")
        channel = ssh_owner._control_channel(0)
        initial, _ = receive_packet(channel, descriptor_required=False)
        fields = {"selection", "role", "identity", "deadline", "namespaces", "host_namespaces", "private_pairs"}
        if type(initial) is not dict or set(initial) != fields:
            raise ValueError("routing_frontend_invalid_initial")
        selected = contract.validate_selection(initial["selection"])
        identity = contract.validate_identity(initial["identity"], selection=selected)
        role, deadline = initial["role"], initial["deadline"]
        if (role not in ("http_frontend", "ssh_frontend") or type(deadline) not in (float, int)
                or not math.isfinite(deadline) or not 0 < deadline - time.monotonic() <= 60):
            raise ValueError("routing_frontend_invalid_lifetime")
        from recon_cockpit.secure_agent.routing_client_worker import assert_routed_namespaces
        assert_routed_namespaces(initial["host_namespaces"], initial["namespaces"])
        listener = socket.socket(fileno=_receive_fd(channel, "listener"))
        if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or listener.getsockname() != (("10.77.0.10", 8080) if role == "http_frontend" else ("10.77.0.20", 2222))
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("routing_frontend_listener_changed")
        budget_socket = ssh_owner._control_channel(_receive_fd(channel, "ledger"))
        budget = BudgetChannel(budget_socket, role, deadline)
        identities = initial["private_pairs"]
        if type(identities) is not list or len(identities) != (4 if role == "ssh_frontend" else 0):
            raise ValueError("routing_frontend_private_pair_count")
        for index, descriptor_identity in enumerate(identities):
            client = socket.socket(fileno=_receive_fd(channel, "private_client_" + str(index)))
            server = socket.socket(fileno=_receive_fd(channel, "private_server_" + str(index)))
            actual = ssh_owner.custodian.connected_identity(server.fileno())
            peer = ssh_owner.custodian.connected_identity(client.fileno())
            if (actual != ssh_owner.validate_connected_identity(descriptor_identity)
                    or actual["local"] != peer["peer"] or actual["peer"] != peer["local"]
                    or actual["netns_cookie"] != peer["netns_cookie"]):
                client.close(); server.close()
                raise ValueError("routing_frontend_private_pair_changed")
            client.setblocking(False); server.setblocking(False)
            pairs.append((client, server, actual))
        worker._set_limits(worker._remaining(deadline, 60))
        existing.scratch_bound("/scratch")
        if role == "http_frontend":
            existing.verify_peer_read_only()
        worker.drop_privileges(); existing.limits(deadline)
        existing.socket_filter(daemon=False); existing.confinement_witnesses()
        permissions = {"/dev/null": 6, "/proc/self/status": 4, "/scratch": (1 << 15) - 2}
        if role == "http_frontend":
            permissions["/peer"] = 8
        common.apply_landlock(permissions)
        send_packet(channel, {"ready": True, "role": role, "namespaces": existing.namespaces(),
            "listener": list(listener.getsockname()), "bounds": existing.BOUNDS, "private_pairs": identities})
        command_sequence = 0
        seen = set()
        while True:
            worker._remaining(deadline, 60)
            if select.select([channel], [], [], .01)[0]:
                command, _ = receive_packet(channel, descriptor_required=False)
                if command is None:
                    return 0
                command_sequence += 1
                if (type(command.get("sequence")) is not int or command["sequence"] != command_sequence
                        or command_sequence > 16 or command.get("operation") not in ("start", "arm", "finish", "close")):
                    raise ValueError("routing_frontend_command_changed")
                operation = command["operation"]
                expected = {"sequence", "operation"} | ({"selector", "action_sequence", "action_digest"} if operation == "start" else {"deadline"} if operation == "arm" else set())
                if set(command) != expected:
                    raise ValueError("routing_frontend_command_fields")
                if operation == "start":
                    require_idle_listener(listener)
                    selector = contract.validate_selector(command["selector"])
                    if (service is not None or selector in seen or contract.selector_role(selector) != role
                            or command["action_digest"] != contract.digest(contract.action(selected, selector))):
                        raise ValueError("routing_frontend_action_changed")
                    seen.add(selector)
                    budget.bind(command["action_sequence"], command["action_digest"])
                    if role == "ssh_frontend":
                        custody = ssh_owner._control_channel(_receive_fd(channel, "custodian"))
                        indices = range(3) if selector == "ssh_nmap" else (3,)
                        chosen = [pairs[index] for index in indices]
                        if any(pair is None for pair in chosen):
                            raise ValueError("routing_private_pair_reused")
                        for index in indices:
                            pairs[index] = None
                        channels = ssh_owner.InstanceChannels(custody, chosen, deadline)
                        service = SshService(selector, listener.dup(), deadline=deadline, budget=budget,
                            connection_factory=channels.connect, connection_finalizer=channels.finalize)
                    else:
                        service = HttpService(selector, listener.dup(), deadline=deadline, budget=budget)
                elif operation == "arm":
                    if service is None:
                        raise ValueError("routing_frontend_missing_action")
                    service.arm(command["deadline"])
                elif operation in ("finish", "close"):
                    if service is not None:
                        service.close()
                    if channels is not None:
                        channels.close()
                    require_idle_listener(listener)
                snapshot = None if service is None else service.snapshot()
                send_packet(channel, {"sequence": command_sequence, "operation": operation,
                    "recorder": snapshot, "instances": [] if channels is None else deepcopy(channels.receipts),
                    "reservations": deepcopy(budget.reservations), "budget_denied": budget.failed,
                    "last_budget_reply": deepcopy(budget.last_reply)})
                if operation == "close":
                    return 0
                if operation == "finish":
                    service = None
                    if channels is not None:
                        channels.channel.close()
                        channels = None
            if service is not None:
                service.tick(.001)
            else:
                require_idle_listener(listener)
    except Exception:
        sys.stderr.write("routing_frontend_refused\n")
        return 78
    finally:
        if service is not None:
            service.close()
        if channels is not None:
            channels.close(); channels.channel.close()
        for pair in pairs:
            if pair is not None:
                client, server, _ = pair
                client.close(); server.close()
        for owned in (listener, budget_socket, channel):
            if owned is not None:
                owned.close()


if __name__ == "__main__":
    raise SystemExit(main())
