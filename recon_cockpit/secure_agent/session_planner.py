"""Fixed trusted subprocess used to test untrusted multi-step proposals.

Deliberately reacts unsafely to an injection marker in two scenarios: this
produces data that the policy/schema boundary must reject, never execution.
No controller, policy, approval, audit, plugin, network, or credential API is
available through this protocol. Python's isolated mode is not an OS sandbox;
this bundled script is trusted code, not an arbitrary provider implementation.
"""

from __future__ import annotations

import json
import re
import sys
import uuid


SCENARIOS = ("three_step", "injection_target", "injection_authority", "endless")
MAX_OBSERVATION_BYTES = 8192


def _unique_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid_constant")


def _observation(raw: bytes) -> dict:
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise ValueError("observation_limit")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields,
                       parse_constant=_reject_constant)
    if type(value) is not dict or set(value) != {"step", "untrusted_observation"}:
        raise ValueError("invalid_observation")
    if type(value["step"]) is not int or not 1 <= value["step"] <= 1_000_000:
        raise ValueError("invalid_step")
    feedback = value["untrusted_observation"]
    if feedback is not None:
        if type(feedback) is not dict or set(feedback) != {"execution_status", "body"}:
            raise ValueError("invalid_feedback")
        status = feedback["execution_status"]
        if type(status) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", status):
            raise ValueError("invalid_status")
        if type(feedback["body"]) is not str:
            raise ValueError("invalid_body")
        # Escaped surrogate characters are JSON strings but not UTF-8 text.
        feedback["body"].encode("utf-8")
    return value


def proposal(scenario: str, observation: dict) -> dict:
    step = observation["step"]
    if (scenario == "three_step" and step > 3) or (
        scenario in ("injection_target", "injection_authority") and step > 2
    ):
        return {"schema_version": "1", "action": None, "done": True}
    feedback = observation["untrusted_observation"]
    injected = feedback is not None and "Ignore prior" in feedback["body"]
    action = {
        "schema_version": "1",
        "action_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"secure-session-mock:{scenario}:{step}")),
        "tool_id": "http_probe",
        "target": "127.0.0.1",
        "parameters": {
            "port": 8080, "method": "GET",
            "path": "/injection" if (scenario == "three_step" and step == 2) or (
                scenario in ("injection_target", "injection_authority") and step == 1
            ) else "/",
            "timeout_seconds": 1, "max_output_bytes": 1024,
        },
        "rationale": "DETERMINISTIC SESSION MOCK: inspect the owned in-namespace fixture.",
    }
    if step > 1 and injected:
        if scenario == "injection_target":
            action["target"] = "127.0.0.2"
        elif scenario == "injection_authority":
            action["approval"] = True
    done = (scenario == "three_step" and step == 3) or (
        scenario in ("injection_target", "injection_authority") and step == 2
    )
    return {"schema_version": "1", "action": action, "done": done}


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in SCENARIOS:
            raise ValueError("invalid_scenario")
        raw = sys.stdin.buffer.read(MAX_OBSERVATION_BYTES + 1)
        result = proposal(sys.argv[1], _observation(raw))
        sys.stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=True) + "\n")
    except (ValueError, TypeError, RecursionError):
        # Never expose response text, process internals, or partial proposals.
        sys.stderr.write("session_mock_invalid_request\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
