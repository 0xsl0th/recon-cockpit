"""Explicitly gated single-call broker and Linux socket-capability transport.

Imports and construction are inert. No legacy provider, retry, DNS, proxy,
credential discovery, approval restoration or host execution fallback exists.
"""

from __future__ import annotations

import array
import errno
import hashlib
import os
from pathlib import Path
import select
import socket
import stat
import tempfile
import threading
import time
from uuid import uuid4

from .cost_contract import CostError, TokenUsage
from .cost_ledger import CostLedger
from .execution import ExecutionControl, ExecutionStopped
from .isolation import LinuxFixtureBackend, _namespaces, _runtime_files, _trusted_program
from .provider_contract import WORKER_STATUSES
from .provider_lab import _command
from .provider_pilot_contract import (
    CHECKS, INPUT_LIMIT, OUTPUT_LIMIT, MAX_PACKET, PilotConfig, PilotError, encode, validate_credential,
)
from .provider_worker import _decode
from .routed import _Supervisor


def _control(control):
    if (type(control) is not ExecutionControl or control.clock is not time.monotonic
            or control.remaining() > 120):
        raise PilotError("pilot_invalid_control")


def _send_packet(channel, data, supervisor, fd=None):
    ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
    if len(data) > MAX_PACKET:
        raise PilotError("pilot_invalid_config")
    channel.setblocking(False)
    while True:
        supervisor.check()
        try:
            if channel.sendmsg([data], ancillary) != len(data):
                raise PilotError("pilot_transport_failed")
            return
        except BlockingIOError:
            supervisor.wait_for(lambda: bool(select.select([], [channel], [], 0)[1]), worker_may_exit=True)


def _connect(config, supervisor):
    # AF_INET + validated literal avoids getaddrinfo, proxy settings and DNS.
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.setblocking(False)
        result = connection.connect_ex((config.ip, config.port))
        if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
            raise PilotError("pilot_transport_failed")
        supervisor.wait_for(lambda: bool(select.select([], [connection], [], 0)[1]), worker_may_exit=True)
        if connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
            raise PilotError("pilot_transport_failed")
        return connection
    except BaseException:
        connection.close()
        raise


def _credential_file(path):
    """Only an explicit operator-owned 0600 regular file; never ambient keys."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 512):
                raise PilotError("pilot_invalid_credential")
            raw = os.read(fd, 513)
        finally:
            os.close(fd)
        return validate_credential(raw.decode("ascii").removesuffix("\n"), "live")
    except (OSError, UnicodeError, ValueError, TypeError):
        raise PilotError("pilot_invalid_credential") from None


class LinuxPilotTransport:
    """Trusted configuration only. Owned mode accepts exclusively fake keys."""

    def __init__(self, config, *, ca_pem, credential_file=None, synthetic_credential=None):
        if (type(config) is not PilotConfig or type(ca_pem) is not str
                or not 1 <= len(ca_pem) <= 524288 or not ca_pem.startswith("-----BEGIN CERTIFICATE-----\n")
                or config.mode == "live" and (credential_file is None or synthetic_credential is not None)
                or config.mode == "owned" and (credential_file is not None or synthetic_credential is None)):
            raise PilotError("pilot_invalid_config")
        try:
            ca_pem.encode("ascii")
        except UnicodeError:
            raise PilotError("pilot_invalid_config") from None
        if config.mode == "owned":
            validate_credential(synthetic_credential, "owned")
        self._config, self._ca = config, ca_pem
        self._credential_file, self._synthetic = credential_file, synthetic_credential
        self._used = False
        self._lock = threading.Lock()

    @property
    def config(self):
        return self._config

    def exchange(self, *, control, authorize):
        if not self.config.enabled:
            raise PilotError("pilot_disabled")
        _control(control)
        with self._lock:
            if self._used:
                raise PilotError("pilot_reused")
            self._used = True
        supervisor = None
        channel = child = connection = temporary = None
        try:
            LinuxFixtureBackend().check_available()
            if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
                raise PilotError("pilot_transport_failed")
            stdlib, files = _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)
            temporary = tempfile.TemporaryDirectory(prefix="recon-pilot-ca-")
            ca_path = Path(temporary.name) / "ca.pem"
            ca_path.write_text(self._ca, encoding="ascii")
            ca_path.chmod(0o600)
            launch = {"host_namespaces": _namespaces(), "deadline": control.deadline,
                      "ip": self.config.ip, "port": self.config.port, "mode": self.config.mode,
                      "ca_digest": hashlib.sha256(self._ca.encode("ascii")).hexdigest()}
            argv = _command(stdlib, files, "provider_pilot_worker.py")
            directory = Path(__file__).parent
            mounts = ["--ro-bind", str(ca_path), "/run/provider/ca.pem",
                      "--ro-bind", str(directory / "provider_worker.py"), "/app/provider_worker.py"]
            for name in ("provider_pilot_contract.py", "cost_contract.py"):
                mounts += ["--ro-bind", str(directory / name), "/app/recon_cockpit/secure_agent/" + name]
            index = argv.index("--remount-ro")
            argv[index:index] = mounts
            argv.append(hashlib.sha256(encode(launch)).hexdigest())
            supervisor = _Supervisor(control.remaining(), 16384, control=control)
            channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            process = supervisor.launch("worker", argv, stdin=child)
            child.close()
            _send_packet(channel, encode(launch), supervisor)
            supervisor.wait_for(lambda: b"\n" in supervisor.buffers["worker_out"] or
                                process.poll() is not None and "worker_out" in supervisor.eof, worker_may_exit=True)
            if b"\n" not in supervisor.buffers["worker_out"]:
                raise PilotError("pilot_transport_failed")
            ready_raw, _, _ = supervisor.buffers["worker_out"].partition(b"\n")
            ready = _decode(bytes(ready_raw))
            if (set(ready) != {"ready", "checks"} or ready["ready"] is not True
                    or type(ready["checks"]) is not dict or set(ready["checks"]) != CHECKS
                    or any(v is not True for v in ready["checks"].values())):
                raise PilotError("pilot_invalid_receipt")
            # This callback durably consumes the one-time ledger send claim.
            authorize()
            control.check()
            connection = _connect(self.config, supervisor)
            credential = (self._synthetic if self.config.mode == "owned"
                          else _credential_file(self._credential_file))
            _send_packet(channel, encode({"credential": credential}), supervisor, connection.fileno())
            connection.close()
            channel.close()
            supervisor.wait_for(lambda: process.poll() is not None and {"worker_out", "worker_err"} <= supervisor.eof,
                                worker_may_exit=True)
            if process.returncode != 0 or supervisor.buffers["worker_err"]:
                raise PilotError("pilot_transport_failed")
            lines = bytes(supervisor.buffers["worker_out"]).splitlines()
            if len(lines) != 2:
                raise PilotError("pilot_invalid_receipt")
            result = _decode(lines[1])
            control.check()
            return result
        except (PilotError, ExecutionStopped, CostError):
            raise
        except Exception:
            raise PilotError("pilot_transport_failed") from None
        finally:
            # Exceptions during cleanup must never release a successful result.
            try:
                for item in (channel, child, connection):
                    if item is not None:
                        item.close()
            finally:
                try:
                    if supervisor is not None:
                        supervisor.close()
                finally:
                    if temporary is not None:
                        temporary.cleanup()


def _summary(receipt):
    if (type(receipt) is not dict or set(receipt) != {"status", "http_status", "summary"}
            or type(receipt["status"]) is not str or receipt["status"] not in WORKER_STATUSES
            or receipt["http_status"] is not None and (type(receipt["http_status"]) is not int
                                                       or not 100 <= receipt["http_status"] <= 599)):
        raise PilotError("pilot_invalid_receipt")
    if receipt["status"] != "ok":
        if receipt["summary"] is not None:
            raise PilotError("pilot_invalid_receipt")
        return None
    value = receipt["summary"]
    if (receipt["http_status"] != 200 or type(value) is not dict
            or set(value) != {"accepted", "usage", "reference"} or type(value["accepted"]) is not bool):
        raise PilotError("pilot_invalid_receipt")
    if value["usage"] is None:
        if value["accepted"] or value["reference"] is not None:
            raise PilotError("pilot_invalid_receipt")
        return value
    import re
    if (type(value["usage"]) is not dict or set(value["usage"]) != {"input_tokens", "output_tokens", "cached_input_tokens"}
            or type(value["reference"]) is not str or re.fullmatch(r"response-[a-f0-9]{64}", value["reference"]) is None):
        raise PilotError("pilot_invalid_receipt")
    TokenUsage(**value["usage"])
    return value


class ControlledProviderCall:
    """One process-local permission, bound to one durable financial attempt."""

    def __init__(self, ledger, audit, transport):
        if type(ledger) is not CostLedger or type(transport) is not LinuxPilotTransport:
            raise PilotError("pilot_invalid_config")
        self._ledger, self._audit, self._transport = ledger, audit, transport
        self.attempt_id = "pilot-" + uuid4().hex
        self._lock, self._used = threading.Lock(), False

    def _emit(self, event, **fields):
        try:
            self._audit.emit({"event_type": event, "attempt_id": self.attempt_id,
                              "config_digest": self._transport.config.digest, **fields})
        except Exception:
            raise PilotError("pilot_audit_failed") from None

    def run(self, *, scope_id, control):
        config = self._transport.config
        if not config.enabled:
            raise PilotError("pilot_disabled")
        _control(control)
        with self._lock:
            if self._used:
                raise PilotError("pilot_reused")
            self._used = True
        if self._ledger.mode != ("provider" if config.mode == "live" else "simulation"):
            raise PilotError("pilot_mode_mismatch")
        if config.price.ceiling(INPUT_LIMIT, OUTPUT_LIMIT) > config.max_call_microusd:
            raise PilotError("pilot_call_cap")
        dispatched = settled = estimated = False
        try:
            self._ledger.estimate(self.attempt_id, scope_id=scope_id, request_digest=config.digest,
                price=config.price, usage=TokenUsage(512, 32), input_token_limit=INPUT_LIMIT,
                output_token_limit=OUTPUT_LIMIT)
            estimated = True
            self._ledger.reserve(self.attempt_id)
            self._emit("pilot_reserved", mode=config.mode)

            def authorize():
                nonlocal dispatched
                control.check()
                self._ledger.begin_dispatch(self.attempt_id, request_digest=config.digest)
                dispatched = True
                self._emit("pilot_dispatch_started")

            result = _summary(self._transport.exchange(control=control, authorize=authorize))
            if not dispatched:
                raise PilotError("pilot_invalid_receipt")
            if result is None or result["usage"] is None:
                raise PilotError("pilot_unresolved")
            usage = TokenUsage(**result["usage"])
            attempt = self._ledger.settle_usage(self.attempt_id, usage,
                receipt_reference=result["reference"], event_id=self.attempt_id + "-usage")
            settled = True
            # Record incurred overruns even when output cannot be accepted.
            accepted = result["accepted"] and usage.input_tokens <= INPUT_LIMIT and usage.output_tokens <= OUTPUT_LIMIT
            self._emit("pilot_settled", accepted=accepted, actual_microusd=attempt["actual_microusd"])
            control.check()
            if not accepted:
                raise PilotError("pilot_output_rejected")
            return {"attempt_id": self.attempt_id, "ack": True, "mode": config.mode,
                    "actual_microusd": attempt["actual_microusd"], "actual_source": "usage_derived"}
        except BaseException as exc:
            if estimated and not settled:
                if dispatched:
                    reason = ("cancelled" if isinstance(exc, ExecutionStopped) and exc.reason == "session_cancelled"
                              else "timeout" if isinstance(exc, ExecutionStopped) else "transport_error")
                    self._ledger.mark_uncertain(self.attempt_id, reason=reason)
                else:
                    self._ledger.cancel(self.attempt_id)
            raise
