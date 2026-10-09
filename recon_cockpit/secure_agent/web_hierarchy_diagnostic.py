"""Owned T04 native feasibility only, outside the registered authority path.

No target, arbitrary command, wordlist or attachment is accepted. Every trial
owns and destroys one disconnected namespace. Diagnostic receipts cannot serve
as action grants or production assessment evidence.
"""

import base64
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

from .execution import ExecutionControl, ExecutionStopped
from .isolation import IsolationUnavailable
from .models import load_json
from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from . import web_hierarchy_spec as spec


CASES = spec.CASES


class DiagnosticLab(OwnedLab):
    """Reuse the accepted namespace lifecycle with a separate ledger protocol."""

    def __init__(self, case):
        spec.validate_case(case)
        super().__init__(case, str(uuid4()),
                         SessionLimits(1, spec.SESSION_SECONDS, spec.MAX_OUTPUT_BYTES))

    def _make_identity(self, case, instance_id):
        return {"scenario": spec.validate_case(case), "instance_id": instance_id,
                "diagnostic_only": True,
                "wordlist_sha256": hashlib.sha256(spec.WORDLIST).hexdigest()}

    def _runtime(self, control):
        self._bootstrap = super()._runtime(control)
        return self._bootstrap

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).parent
        mounts = []
        for name in ("web_hierarchy_spec.py", "web_hierarchy_fixture.py", "web_hierarchy_owner.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/web_hierarchy_owner.py"
        return argv

    def _read_message(self):
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][self._offset:])
        buffered = supervisor.buffers["lab_out"]
        end = buffered.index(b"\n", self._offset) + 1
        raw = bytes(buffered[self._offset:end])
        if len(raw) > spec.MAX_OWNER_MESSAGE:
            raise IsolationUnavailable("Web hierarchy owner receipt exceeds its bound")
        self._offset = end
        try:
            return load_json(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise IsolationUnavailable("Invalid web hierarchy owner receipt") from exc

    def snapshot(self, control, *, minimum_requests=0):
        with self._lock:
            self._check(control)
            self._verify_pins()
            if (not self._started or self._sequence or type(minimum_requests) is not int
                    or not 0 <= minimum_requests <= len(spec.PATHS)):
                raise IsolationUnavailable("Web hierarchy snapshot is single-use")
            self._sequence = 1
            command = {"sequence": 1, "minimum_connections": minimum_requests,
                       "minimum_requests": minimum_requests}
            self._supervisor.processes["lab"].stdin.write(
                json.dumps(command, separators=(",", ":")).encode("ascii") + b"\n")
            value = self._read_message()
            if (type(value) is not dict
                    or set(value) != {"sequence", "connection_count", "request_count", "diagnostic"}
                    or type(value["sequence"]) is not int or value["sequence"] != 1
                    or any(type(value[key]) is not int or not 0 <= value[key] <= spec.MAX_CONNECTIONS
                           for key in ("connection_count", "request_count"))
                    or value["request_count"] > value["connection_count"]
                    or value["request_count"] < minimum_requests
                    or type(value["diagnostic"]) is not dict
                    or value["diagnostic"].get("case") != self.identity["scenario"]):
                raise IsolationUnavailable("Web hierarchy owner acknowledgement invalid")
            self._counts = {key: value[key] for key in self._counts}
            return {key: item for key, item in value.items() if key != "sequence"}


def run_trial(case, *, control=None):
    """Capture one fixed native trial; cleanup precedes any returned result."""
    spec.validate_case(case)
    if control is None:
        control = ExecutionControl(time.monotonic() + spec.SESSION_SECONDS)
    if (type(control) is not ExecutionControl or control.clock is not time.monotonic
            or control.remaining() > spec.SESSION_SECONDS):
        raise ValueError("invalid_web_hierarchy_control")
    from .web_hierarchy_diagnostic_runtime import capture_client
    from .web_hierarchy_observation import assess

    started = time.monotonic()
    lab = DiagnosticLab(case)
    result = {"schema_version": "1", "diagnostic_only": True, "case": case,
              "lab_identity": lab.identity, "actual_provider_calls": 0,
              "actual_cost_microusd": 0, "owner": None,
              "production_authority_validated": False, "cleanup": {"closed": False}}
    try:
        lab.start(control)
        captured = capture_client(lab, control)
        result.update(captured)
        result["owner"] = lab.snapshot(control)
        execution = captured["execution"]
        if captured["confinement"].get("worker_ready") is True:
            result["observation"] = assess(
                base64.b64decode(execution["raw_stdout_base64"], validate=True), result["owner"],
                exit_code=execution["exit_code"], stop_reason=execution["stop_reason"],
                truncated=execution["truncated"])
        else:
            result["observation"] = {"useful_completion": False, "outcome": "inconclusive",
                                     "reason": "confinement_not_verified"}
    except ExecutionStopped as exc:
        result["failure"] = exc.reason
        result["observation"] = {"useful_completion": False, "outcome": "inconclusive",
                                 "reason": exc.reason}
    finally:
        closure = lab.close()
        result["cleanup"] = {"closed": closure["status"] == "closed",
                             "last_acknowledged_counts": {key: closure[key] for key in
                                                          ("connection_count", "request_count")}}
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result
