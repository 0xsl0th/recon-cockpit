"""One authority-bound fixture launch in a fresh OS isolation domain.

The host authority supplies a private stdin pipe and trusted argv commitment.
This is not a bearer-token service or protection against that host authority.
No controller, approvals, audit, broker, provider or credentials are mounted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import time
from uuid import UUID

if __package__:
    from .models import load_json, parse_action, parse_policy
    from . import worker
else:
    # A fixed mount location; neither an observation nor launch field selects it.
    sys.path.insert(0, "/app")
    try:
        from recon_cockpit.secure_agent.models import load_json, parse_action, parse_policy
        import worker
    except ImportError:
        sys.stderr.write("secure_executor_launch_refused\n")
        raise SystemExit(78) from None


MAX_LAUNCH_BYTES = 32768
LAUNCH_FIELDS = frozenset({
    "schema_version", "mode", "execute", "session_id", "nonce", "sequence",
    "action", "action_digest", "policy", "policy_digest", "limits", "limits_digest",
    "deadline", "output_reserved_before", "output_reserved_after", "host_namespaces",
})


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def digest(value) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def _hex(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


class LaunchVerifier:
    """Consume exactly one request against the fresh launch's trusted context."""

    def __init__(self, nonce, context_digest, *, clock=time.monotonic):
        if not _hex(nonce) or not _hex(context_digest):
            raise ValueError("invalid_executor_context")
        self._nonce = nonce
        self._context_digest = context_digest
        self._clock = clock
        self._used = False

    def consume(self, raw: bytes) -> tuple[dict, float]:
        if self._used:
            raise ValueError("executor_launch_already_consumed")
        self._used = True  # Invalid attempts also consume this process's launch.
        if type(raw) is not bytes or len(raw) > MAX_LAUNCH_BYTES:
            raise ValueError("invalid_executor_launch")
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), self._context_digest):
            raise ValueError("executor_context_mismatch")
        envelope = load_json(raw)
        if (set(envelope) != LAUNCH_FIELDS or envelope["schema_version"] != "1"
                or envelope["mode"] != "fixture" or envelope["execute"] is not True
                or not _hex(envelope["nonce"])
                or not hmac.compare_digest(envelope["nonce"], self._nonce)):
            raise ValueError("invalid_executor_launch")
        session_id = envelope["session_id"]
        if type(session_id) is not str or str(UUID(session_id)) != session_id:
            raise ValueError("invalid_executor_session")
        limits = envelope["limits"]
        ceilings = {"max_steps": 16, "max_runtime_seconds": 600, "max_output_bytes": 16 * 65536}
        if (type(limits) is not dict or set(limits) != set(ceilings)
                or any(type(limits[name]) is not int or not 1 <= limits[name] <= maximum
                       for name, maximum in ceilings.items())
                or envelope["limits_digest"] != digest(limits)):
            raise ValueError("invalid_executor_limits")
        sequence = envelope["sequence"]
        if type(sequence) is not int or not 1 <= sequence <= limits["max_steps"]:
            raise ValueError("executor_step_limit")
        deadline = envelope["deadline"]
        now = self._clock()
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline - now <= limits["max_runtime_seconds"]):
            raise ValueError("executor_deadline_expired_or_invalid")
        action = parse_action(envelope["action"])
        policy = parse_policy(envelope["policy"])
        if (action.to_dict() != envelope["action"] or policy.to_dict() != envelope["policy"]
                or envelope["action_digest"] != action.digest or envelope["policy_digest"] != policy.digest
                or policy.evaluate(action).decision == "deny"):
            raise ValueError("executor_action_or_policy_denied")
        if action.targets != ("127.0.0.1",) or not 1024 <= action.parameters.port <= 65534:
            raise ValueError("executor_fixture_only")
        before, after = envelope["output_reserved_before"], envelope["output_reserved_after"]
        if (type(before) is not int or type(after) is not int
                or not 0 <= before < after <= limits["max_output_bytes"]
                or after - before != action.parameters.max_output_bytes
                or (sequence == 1 and before != 0) or (sequence > 1 and before < sequence - 1)):
            raise ValueError("executor_output_limit")
        host = envelope["host_namespaces"]
        if (type(host) is not dict or set(host) != {"user", "net", "mnt", "pid"}
                or any(type(value) is not str or not re.fullmatch(name + r":\[\d+\]", value)
                       for name, value in host.items())):
            raise ValueError("invalid_executor_namespaces")
        request = {"target": "127.0.0.1", "parameters": action.parameters.to_dict(),
                   "verify_boundary": True, "host_namespaces": host}
        return worker.validate_request(encode(request)), deadline


def main() -> int:
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("executor_requires_private_authority_pipe")
        verifier = LaunchVerifier(sys.argv[1], sys.argv[2])
        # read(size) waits for EOF when shorter; no trailing second request is accepted.
        raw = sys.stdin.buffer.read(MAX_LAUNCH_BYTES + 1)
        sys.stdin.close()
        request, deadline = verifier.consume(raw)
        result = worker.execute(request, deadline=deadline)
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        sys.stderr.write("secure_executor_launch_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
