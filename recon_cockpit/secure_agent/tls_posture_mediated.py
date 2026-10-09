"""Owned TLS transport-mediation experiment, outside the product catalog.

The client reuses the native diagnostic's fixed arguments, validation, runtime
closure and confinement limits. A new worker adds private-peer bypass witnesses,
and the owned service gains a transport mediator. Neither this harness nor its
private receipts provide product execution authority.
"""

import base64
import hashlib
import os
from pathlib import Path
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces
from .tls_posture_diagnostic import (
    CASES, DiagnosticLab, SESSION_SECONDS, client_command as original_client_command, inspect_runtime,
    validate_selection,
)
from .tool_runtime_common import sealed_snapshots
from . import tls_posture_diagnostic_worker as fixed
from . import tls_posture_mediated_worker as mediated_worker


def client_command(lab, manifest, descriptors, commitment):
    """Use the same client boundary with additional Unix-socket witnesses."""
    argv = original_client_command(lab, manifest, descriptors, commitment)
    directory = Path(__file__).parent
    name = "tls_posture_mediated_worker.py"
    destination = "/app/recon_cockpit/secure_agent/" + name
    index = argv.index("--remount-ro")
    argv[index:index] = ["--ro-bind", str(directory / name), destination]
    argv[-2] = destination
    return argv


class MediatedLab(DiagnosticLab):
    """Own the mediator and peer; expose neither to the confined client."""

    def _make_identity(self, case, instance_id):
        return {**super()._make_identity(case, instance_id), "mediated": True}

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).parent
        mounts = []
        for name in ("tls_posture_mediated_owner.py", "tls_posture_mediator.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/tls_posture_mediated_owner.py"
        return argv

    def snapshot(self, control):
        self._check(control)
        self._verify_pins()
        if self._sequence:
            raise IsolationUnavailable("TLS mediated snapshot is single-use")
        self._sequence = 1
        self._supervisor.processes["lab"].stdin.write(fixed.encode({"sequence": 1,
            "minimum_connections": 0, "minimum_requests": 0}) + b"\n")
        value = self._read_message()
        if (type(value) is not dict
                or set(value) != {"sequence", "connection_count", "request_count", "diagnostic", "mediation"}
                or type(value["sequence"]) is not int or value["sequence"] != 1
                or any(type(value[key]) is not int or not 0 <= value[key] <= 2
                       for key in ("connection_count", "request_count"))
                or type(value["diagnostic"]) is not dict
                or type(value["mediation"]) is not dict):
            raise IsolationUnavailable("TLS mediated owner receipt invalid")
        # _read_message enforces the unchanged finite owner-message bound.
        # The analyzer validates semantic ledgers, never restoring authority.
        self._counts = {key: value[key] for key in self._counts}
        return {key: item for key, item in value.items() if key != "sequence"}


def run_trial(case, version):
    """Run one fixed owned experiment and retain raw facts after cleanup."""
    validate_selection(case, version)
    control = ExecutionControl(time.monotonic() + SESSION_SECONDS)
    manifest = inspect_runtime(control)
    from .network_tools_fixture import TLS_CERTIFICATE_CA_PEM
    descriptors = sealed_snapshots(manifest, "compiled:fixture-ca", TLS_CERTIFICATE_CA_PEM, control)
    lab = MediatedLab(case, version)
    result = None
    try:
        lab.start(control)
        request = {"version": version, "deadline": min(time.monotonic() + 5, control.deadline),
            "host_namespaces": _namespaces(), "lab_namespaces": lab._lab_namespaces, "manifest": manifest}
        raw = fixed.encode(request)
        commitment = hashlib.sha256(raw).hexdigest()
        fixed.validate_request(raw, commitment)
        prefix = mediated_worker.READY_PREFIX + commitment.encode("ascii") + b"\n"
        started = time.monotonic()
        code, stdout, stderr, reason = _capture_bounded(client_command(lab, manifest, descriptors, commitment),
            raw, max(0, request["deadline"] - time.monotonic()), fixed.MAX_OUTPUT_BYTES + len(prefix),
            control=control, pass_fds=(*lab._namespace_fds, *descriptors))
        elapsed = round((time.monotonic() - started) * 1000)
        ready = stderr.startswith(prefix)
        if ready:
            stderr = stderr[len(prefix):]
        if len(stdout) + len(stderr) > fixed.MAX_OUTPUT_BYTES:
            reason = "output_limit"
            stdout = stdout[:fixed.MAX_OUTPUT_BYTES]
            stderr = stderr[:fixed.MAX_OUTPUT_BYTES - len(stdout)]
        owner = lab.snapshot(control)
        result = {"schema_version": "1", "diagnostic_only": True, "mediated": True,
            "case": case, "version": version, "argv": list(fixed.FIXED_ARGV[version]),
            "runtime_manifest": manifest,
            "runtime_sha256": hashlib.sha256(fixed.encode(manifest)).hexdigest(),
            "execution": {"exit_code": code, "stop_reason": reason, "elapsed_ms": elapsed,
                "raw_stdout_base64": base64.b64encode(stdout).decode("ascii"),
                "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
                "truncated": reason == "output_limit"},
            "owner": owner, "confinement": {"worker_ready": ready,
                "private_namespaces_and_firewall": ready, "read_only_pinned_runtime": ready,
                "landlock_and_seccomp": ready, "no_inherited_descriptors": ready,
                "unix_socket_and_socketpair_denied": ready},
            "actual_provider_calls": 0, "actual_cost_microusd": 0,
            "cleanup": {"closed": False}}
    finally:
        # The only inherited client descriptors are namespace pins and sealed
        # runtime snapshots. All peer/socketpair state belongs to the owner.
        try:
            for descriptor in descriptors:
                os.close(descriptor)
        finally:
            closure = lab.close()
            if result is not None:
                result["cleanup"] = {"closed": closure["status"] == "closed"}
    return result
