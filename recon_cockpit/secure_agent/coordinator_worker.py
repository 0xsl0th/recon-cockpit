"""Fixed persistent coordinator with no host authority or selectable code."""

import errno
import importlib.util
import json
import os
import stat
import sys
from uuid import UUID


SCENARIOS = ("three_step", "injection_target", "injection_authority", "endless",
             "replay", "wrong_session", "forge_approval", "oversized", "early_exit", "offline_provider")


def _load(name):
    spec = importlib.util.spec_from_file_location("secure_fixed_" + name, "/app/" + name + ".py")
    if spec is None or spec.loader is None:
        raise RuntimeError("missing_fixed_coordinator_module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_descriptors():
    # The launcher closes inherited descriptors and detaches the terminal.
    # Verify before loading ctypes: libffi may retain a descriptor to its own
    # explicitly mounted runtime file. No untrusted input is consumed here.
    for fd in range(3):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode) or os.isatty(fd):
            raise RuntimeError("invalid_coordinator_channel")
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd <= 2:
            continue
        try:
            os.fstat(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:  # Closed directory iterator.
                continue
            raise
        raise RuntimeError("unexpected_coordinator_descriptor")
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError as exc:
        if exc.errno not in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            raise
    else:
        os.close(fd)
        raise RuntimeError("coordinator_terminal_accessible")


def _encode(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def _init(raw, ipc, *, version="1"):
    value = ipc.object_payload(raw)
    if (set(value) != {"schema_version", "session_id"} or value["schema_version"] != version
            or type(value["session_id"]) is not str or str(UUID(value["session_id"])) != value["session_id"]):
        raise ValueError("invalid_coordinator_init")
    return value["session_id"]


def _response(raw, ipc, session_id, sequence):
    value = ipc.object_payload(raw)
    if (set(value) != {"schema_version", "session_id", "sequence", "stop", "observation"}
            or value["schema_version"] != "1" or value["session_id"] != session_id
            or type(value["sequence"]) is not int or value["sequence"] != sequence
            or type(value["stop"]) is not bool
            or value["observation"] is not None and type(value["observation"]) is not dict):
        raise ValueError("invalid_coordinator_response")
    return value


def _offline_response(raw, ipc, session_id, sequence, *, planning):
    value = ipc.object_payload(raw)
    if (set(value) != {"schema_version", "session_id", "sequence", "stop", "plan"}
            or value["schema_version"] != "2" or value["session_id"] != session_id
            or type(value["sequence"]) is not int or value["sequence"] != sequence
            or type(value["stop"]) is not bool):
        raise ValueError("invalid_coordinator_response")
    if planning and not value["stop"]:
        if type(value["plan"]) is not dict:
            raise ValueError("invalid_coordinator_response")
    elif value["plan"] is not None:
        raise ValueError("invalid_coordinator_response")
    return value


def _offline_dialogue(ipc, session_id, send):
    for sequence in range(1, ipc.MAX_OFFLINE_REQUESTS // 2 + 1):
        request = {"schema_version": "2", "session_id": session_id, "sequence": sequence}
        send(ipc.REQUEST, {**request, "operation": "plan"})
        response = _offline_response(ipc.read_frame(sys.stdin.buffer, ipc.RESPONSE), ipc,
                                     session_id, sequence, planning=True)
        if not response["stop"]:
            send(ipc.REQUEST, {**request, "operation": "propose", "plan": response["plan"]})
            response = _offline_response(ipc.read_frame(sys.stdin.buffer, ipc.RESPONSE), ipc,
                                         session_id, sequence, planning=False)
        if response["stop"]:
            if sys.stdin.buffer.read(1) != b"":
                raise ValueError("extra_coordinator_input")
            send(ipc.RESULT, {"schema_version": "2", "session_id": session_id, "status": "closed"})
            return 0
    raise ValueError("coordinator_request_limit")


def main():
    try:
        if len(sys.argv) != 6 or sys.argv[1] not in SCENARIOS:
            raise ValueError("invalid_coordinator_scenario")
        scenario = sys.argv[1]
        _private_descriptors()
        bootstrap = _load("planner_worker")
        _, host = bootstrap._arguments(["three_step", *sys.argv[2:]])
        checks = bootstrap._bootstrap(host)
        ipc = _load("coordinator_ipc")
        session_id = _init(ipc.read_frame(sys.stdin.buffer, ipc.INIT), ipc,
                           version="2" if scenario == "offline_provider" else "1")

        def send(kind, value):
            sys.stdout.buffer.write(ipc.frame(kind, _encode(value)))
            sys.stdout.buffer.flush()

        send(ipc.READY, {"schema_version": "1", "boundary_checks": checks})
        if scenario == "offline_provider":
            return _offline_dialogue(ipc, session_id, send)
        planner = _load("session_planner")
        if scenario == "early_exit":
            return 0
        previous = None
        original = None
        for sequence in range(1, ipc.MAX_REQUESTS + 1):
            plan = planner.proposal(scenario if scenario in planner.SCENARIOS else "endless",
                                    {"step": sequence, "untrusted_observation": previous})
            request = {"schema_version": "1", "session_id": session_id, "sequence": sequence, "plan": plan}
            if scenario == "wrong_session":
                request["session_id"] = str(UUID(int=UUID(session_id).int ^ 1))
            elif scenario == "forge_approval":
                request["approval_reference"] = "coordinator-forged-approval"
            elif scenario == "replay" and original is not None:
                request = original
            if original is None:
                original = request
            if scenario == "oversized":
                sys.stdout.buffer.write((ipc.MAX_REQUEST_BYTES + 2).to_bytes(4, "big") + bytes((ipc.REQUEST,)))
                sys.stdout.buffer.flush()
                raise ValueError("oversized_coordinator_fixture")
            send(ipc.REQUEST, request)
            response = _response(ipc.read_frame(sys.stdin.buffer, ipc.RESPONSE), ipc, session_id, sequence)
            if response["stop"]:
                if sys.stdin.buffer.read(1) != b"":
                    raise ValueError("extra_coordinator_input")
                send(ipc.RESULT, {"schema_version": "1", "session_id": session_id, "status": "closed"})
                return 0
            previous = response["observation"]
        raise ValueError("coordinator_request_limit")
    except Exception:
        sys.stderr.write("secure_coordinator_failed\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
