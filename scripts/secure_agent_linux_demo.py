"""Run the owned Linux fixture demonstration and assert its actual outcomes.

This explicitly uses a trusted, fixture-only automatic policy for unattended
validation. It never grants human approvals or enables non-local destinations.
Run from an installed checkout: python scripts/secure_agent_linux_demo.py
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.isolation import IsolationUnavailable, LinuxFixtureBackend
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.providers import MockProvider


def _require_boundary_checks(checks: object) -> None:
    expected = {"forbidden_ip_blocked", "forbidden_port_blocked",
                "namespace_creation_blocked", "capabilities_dropped"}
    if (type(checks) is not dict or set(checks) != expected
            or any(checks[name] is not True for name in expected)):
        raise RuntimeError("kernel boundary verification failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain JSONL evidence at this operator-selected path")
    args = parser.parse_args()
    backend = LinuxFixtureBackend(verify_boundary=True)
    try:
        backend.check_available()
    except IsolationUnavailable as exc:
        print(json.dumps({"demo": "blocked", "reason": exc.code, "detail": str(exc)}))
        return 2
    demo_policy = parse_policy({
        "schema_version": "1", "policy_version": "owned-fixture-demo-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 4096, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 60,
    })
    directory = Path(tempfile.mkdtemp(prefix="recon-secure-demo-")) if args.audit is None else None
    audit_path = args.audit if args.audit else directory / "audit.jsonl"
    print(json.dumps({"provider": MockProvider.name, "policy_version": demo_policy.policy_version,
                      "note": "Explicit automatic policy for owned isolated fixtures; no model validation or human approval claim.",
                      "audit": str(audit_path)}))
    try:
        with AuditSink(audit_path) as audit:
            controller = Controller(demo_policy, audit, backend)
            original_digest = controller.policy.digest
            for path, expected in (("/", "succeeded"), ("/injection", "succeeded"), ("/redirect", "succeeded"),
                                   ("/large", "output_limit"), ("/slow", "timeout")):
                raw = json.loads(MockProvider().propose())
                raw["parameters"].update(path=path, timeout_seconds=1)
                result = controller.submit(raw, execute=True)
                if result["execution_status"] != expected:
                    raise RuntimeError(f"{path}: expected {expected}, got {result['execution_status']}")
                if controller.policy.digest != original_digest:
                    raise RuntimeError("policy changed")
                payload = result.get("untrusted_result")
                checks = payload.get("boundary_checks") if type(payload) is dict else None
                _require_boundary_checks(checks)
                print(json.dumps({"case": path, "status": result["execution_status"],
                                  "boundary_checks": checks, "metadata": result["result_metadata"]}))
            for label, change in (("out_of_scope", {"target": "127.0.0.2"}),
                                  ("forbidden_tool", {"tool_id": "shell"}),
                                  ("unknown_parameter", {"parameters": {"command": "id"}})):
                raw = json.loads(MockProvider().propose())
                raw.update(change)
                result = controller.submit(raw, execute=True)
                if result["decision"] != "deny":
                    raise RuntimeError(f"{label} was not rejected")
                print(json.dumps({"case": label, "status": result["execution_status"], "reasons": result["reasons"]}))
            approval_policy = parse_policy({**demo_policy.to_dict(), "require_approval": True})
            result = Controller(approval_policy, audit, backend).submit(MockProvider().propose(), execute=True)
            if result["reasons"] != ["noninteractive_approval_required"]:
                raise RuntimeError("noninteractive approval did not fail closed")
            print(json.dumps({"case": "noninteractive_approval", "status": result["execution_status"], "reasons": result["reasons"]}))
    except (RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"demo": "failed", "detail": str(exc)}))
        return 1
    print(json.dumps({"demo": "passed", "audit": str(audit_path),
                      "limits": "specific owned fixtures and deterministic mock; no universal prompt-injection immunity"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
