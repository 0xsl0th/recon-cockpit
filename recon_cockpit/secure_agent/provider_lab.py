"""Disposable, disconnected TLS transport with synthetic pipe-only credentials.

Every exchange owns its network, certificates and processes. No public provider,
host network, ambient credential lookup or configurable destination exists here.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import secrets
import select
import stat
import subprocess
import tempfile
import threading
import time

from .execution import ExecutionControl, ExecutionStopped
from .isolation import (IsolationUnavailable, LinuxFixtureBackend, _capture_bounded,
                        _namespaces, _runtime_files, _trusted_program)
from .models import load_json
from .owned_lab import _CLOSE_NAMESPACE_FDS
from .provider_contract import (BOUNDARY_NAMES, MAX_RESPONSE_BYTES, SCENARIOS,
                                WORKER_STATUSES, ProviderError, encode, validate_request)
from .routed import _Supervisor, _pin_namespaces


def _send(supervisor, process, raw, *, close=False):
    """Bound bootstrap writes too: a wedged child must not block cancellation."""
    stream = process.stdin
    os.set_blocking(stream.fileno(), False)
    offset = 0
    while offset < len(raw):
        supervisor.check()
        try:
            offset += os.write(stream.fileno(), raw[offset:offset + 4096])
        except BlockingIOError:
            supervisor.wait_for(lambda: bool(select.select([], [stream], [], 0)[1]),
                                worker_may_exit=True)
    if close:
        stream.close()


def _message(supervisor, offset):
    supervisor.wait_for(lambda: b"\n" in supervisor.buffers["owner_out"][offset:], worker_may_exit=True)
    buffered = supervisor.buffers["owner_out"]
    end = buffered.index(b"\n", offset) + 1
    if end - offset > 4096:
        raise ProviderError("provider_receipt_invalid")
    return load_json(bytes(buffered[offset:end])), end


def _certificates(directory, scenario, control):
    """Generate ephemeral owned self-signed certificates using a fixed command."""
    openssl = _trusted_program("openssl")

    def generate(stem, hostname):
        argv = [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "1", "-subj", "/CN=" + hostname,
                "-addext", "subjectAltName=DNS:" + hostname,
                "-keyout", str(directory / (stem + ".key")), "-out", str(directory / (stem + ".crt"))]
        code, _, _, reason = _capture_bounded(argv, b"", 5, 16384, control=control)
        if code != 0 or reason is not None:
            raise ProviderError("provider_transport_failed")
        for suffix in (".key", ".crt"):
            (directory / (stem + suffix)).chmod(0o600)
        return (directory / (stem + ".crt")).read_text(encoding="ascii")

    ca = generate("server", "wrong.owned.invalid" if scenario == "wrong_hostname" else "provider.owned.invalid")
    if scenario == "untrusted_certificate":
        ca = generate("unrelated", "provider.owned.invalid")
    return ca


def _command(stdlib, files, module):
    argv = LinuxFixtureBackend()._command(stdlib, files)
    directory = Path(__file__).parent
    mounts = []
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        mounts.extend(("--ro-bind", str((directory / "__init__.py").resolve()), destination))
    for name in ("provider_contract.py", "openai_protocol.py", "models.py", "session_protocol.py"):
        mounts.extend(("--ro-bind", str((directory / name).resolve()), "/app/recon_cockpit/secure_agent/" + name))
    for name in ("planner_worker.py", module):
        mounts.extend(("--ro-bind", str((directory / name).resolve()), "/app/" + name))
    argv[argv.index("--remount-ro"):argv.index("--remount-ro")] = mounts
    argv[-1] = "/app/" + module
    return argv


class LinuxOwnedProviderTransport:
    """Fixed scenarios only; constructing a transport performs no I/O."""

    def __init__(self, scenario="success"):
        if type(scenario) is not str or scenario not in SCENARIOS:
            raise ProviderError("provider_invalid_transport")
        self._scenario = scenario
        self._last_receipt = None
        self._lock = threading.Lock()

    @property
    def scenario(self):
        return self._scenario

    @property
    def last_receipt(self):
        return copy.deepcopy(self._last_receipt)

    def exchange(self, request, *, control, context_digest):
        if not self._lock.acquire(blocking=False):
            raise ProviderError("provider_already_running")
        try:
            return self._exchange(request, control=control, context_digest=context_digest)
        finally:
            self._lock.release()

    def _exchange(self, request, *, control, context_digest):
        self._last_receipt = None
        validate_request(request)
        if (type(control) is not ExecutionControl or control.clock is not time.monotonic
                or type(context_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", context_digest) is None):
            raise ProviderError("provider_invalid_control")
        if control.remaining() > 120:
            raise ProviderError("provider_invalid_control")
        receipt = {"schema_version": "1", "context_digest": context_digest, "status": "transport_error",
                   "http_status": None, "boundary_checks": None,
                   "cleanup": {"worker_reaped": True, "owner_reaped": True},
                   "connection_count": None, "request_count": None}
        supervisor = None
        temporary = None
        body = None
        cleanup_failed = False
        try:
            LinuxFixtureBackend().check_available()
            if Path(_trusted_program("bwrap")).stat().st_mode & stat.S_ISUID:
                raise IsolationUnavailable("Provider requires non-setuid Bubblewrap")
            nsenter = _trusted_program("nsenter")
            host = _namespaces()
            stdlib, files = _runtime_files("/usr/bin/python3", _trusted_program("nft"), control=control)
            temporary = tempfile.TemporaryDirectory(prefix="recon-owned-provider-")
            directory = Path(temporary.name)
            ca = _certificates(directory, self._scenario, control)
            credential = "synthetic-" + secrets.token_hex(32)
            supervisor = _Supervisor(control.remaining(), 131072, control=control)
            info_r, info_w = supervisor.pipe()
            supervisor.watch(info_r, "info")
            argv = _command(stdlib, files, "provider_lab_worker.py")
            argv[1:1] = ["--info-fd", str(info_w)]
            index = argv.index("--remount-ro")
            argv[index:index] = ["--ro-bind", str(directory / "server.crt"), "/run/provider/server.crt",
                                 "--ro-bind", str(directory / "server.key"), "/run/provider/server.key"]
            owner = supervisor.launch("owner", argv, pass_fds=(info_w,), stdin=subprocess.PIPE)
            supervisor.close_fd(info_w)
            _send(supervisor, owner, encode({"scenario": self._scenario, "credential": credential,
                  "deadline": control.deadline, "host_namespaces": host}) + b"\n")
            ready, offset = _message(supervisor, 0)
            supervisor.wait_for(lambda: "info" in supervisor.eof)
            if (type(ready) is not dict or set(ready) != {"ready", "namespaces", "witness_baselines"}
                    or ready["ready"] is not True or ready["witness_baselines"] is not True):
                raise ProviderError("provider_isolation_failed")
            pins = _pin_namespaces(bytes(supervisor.buffers["info"]), host)
            supervisor.fds.update(pins)
            metadata = load_json(bytes(supervisor.buffers["info"]))
            lab = {name: os.readlink(f"/proc/{metadata['child-pid']}/ns/{name}") for name in host}
            if (ready["namespaces"] != lab or any(lab[name] == host[name] for name in host)
                    or any(os.readlink(f"/proc/self/fd/{fd}") != lab[name]
                           for name, fd in zip(("user", "net"), pins))):
                raise ProviderError("provider_isolation_failed")
            launch = encode({"schema_version": "1", "request": request.decode("ascii"), "credential": credential,
                             "ca_pem": ca, "deadline": control.deadline, "host_namespaces": host, "lab_namespaces": lab})
            argv = _command(stdlib, [(s, d) for s, d in files if d != "/usr/sbin/nft"], "provider_worker.py")
            argv.remove("--unshare-net")
            index = argv.index("CAP_NET_ADMIN")
            del argv[index - 1:index + 1]
            argv.append(hashlib.sha256(launch).hexdigest())
            argv = [nsenter, f"--user=/proc/self/fd/{pins[0]}", f"--net=/proc/self/fd/{pins[1]}",
                    "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_NAMESPACE_FDS, *argv]
            process = supervisor.launch("worker", argv, pass_fds=pins, stdin=subprocess.PIPE)
            _send(supervisor, process, launch, close=True)
            supervisor.wait_for(lambda: process.poll() is not None and
                                {"worker_out", "worker_err"} <= supervisor.eof, worker_may_exit=True)
            if process.returncode != 0:
                raise ProviderError("provider_transport_failed")
            result = load_json(bytes(supervisor.buffers["worker_out"]))
            if (type(result) is not dict or set(result) != {"schema_version", "status", "http_status", "response", "boundary_checks"}
                    or result["schema_version"] != "1" or type(result["status"]) is not str
                    or result["status"] not in WORKER_STATUSES
                    or (result["http_status"] is not None and
                        (type(result["http_status"]) is not int or not 100 <= result["http_status"] <= 599))):
                raise ProviderError("provider_receipt_invalid")
            checks = result["boundary_checks"]
            if type(checks) is not dict or set(checks) != BOUNDARY_NAMES or any(value is not True for value in checks.values()):
                raise ProviderError("provider_isolation_failed")
            if result["status"] == "ok":
                if type(result["response"]) is not str or len(result["response"]) > 4 * ((MAX_RESPONSE_BYTES + 2) // 3):
                    raise ProviderError("provider_receipt_invalid")
                body = base64.b64decode(result["response"], validate=True)
                if not 1 <= len(body) <= MAX_RESPONSE_BYTES or result["http_status"] != 200:
                    raise ProviderError("provider_receipt_invalid")
            elif result["response"] is not None:
                raise ProviderError("provider_receipt_invalid")
            receipt.update(http_status=result["http_status"], boundary_checks=checks)
            # Success requires the owner's independent counts. Keep a partial
            # success provisional so cancellation before SNAP completes cannot
            # produce an invalid "ok" receipt and hide the original stop.
            if result["status"] != "ok":
                receipt["status"] = result["status"]
            _send(supervisor, owner, b"SNAP\n")
            counts, _ = _message(supervisor, offset)
            if (type(counts) is not dict or set(counts) != {"connection_count", "request_count"}
                    or any(type(value) is not int or not 0 <= value <= 1 for value in counts.values())
                    or counts["request_count"] > counts["connection_count"]
                    or (result["status"] == "ok" and counts != {"connection_count": 1, "request_count": 1})):
                raise ProviderError("provider_receipt_invalid")
            receipt.update(status=result["status"], **counts)
            control.check()
        except ExecutionStopped as exc:
            if exc.reason == "session_timeout":
                receipt["status"] = "deadline_exceeded"
            raise
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("provider_transport_failed") from None
        finally:
            if supervisor is not None:
                try:
                    supervisor.close()
                except Exception:
                    cleanup_failed = True
                for name in ("owner", "worker"):
                    process = supervisor.processes.get(name)
                    receipt["cleanup"][name + "_reaped"] = process is None or process.poll() is not None
            if temporary is not None:
                try:
                    temporary.cleanup()
                except OSError:
                    cleanup_failed = True
            self._last_receipt = copy.deepcopy(receipt)
            if cleanup_failed or not all(receipt["cleanup"].values()):
                raise ProviderError("provider_cleanup_failed") from None
        control.check()
        return {"body": body, "receipt": copy.deepcopy(receipt)}
