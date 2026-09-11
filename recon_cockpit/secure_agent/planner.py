"""Deterministic mock planner subprocess. This is NOT an autonomous model.

The provider protocol carries JSON data only. This fixed script has no execution,
policy, audit, or approval API. Real model integration needs a separately
sandboxed provider and credential broker; loading arbitrary Python providers in
the controller is intentionally unsupported.
"""

import json


def proposal() -> dict:
    return {
        "schema_version": "1",
        "action_id": "11111111-1111-4111-8111-111111111111",
        "tool_id": "http_probe",
        "target": "127.0.0.1",
        "parameters": {
            "port": 8080, "method": "GET", "path": "/",
            "timeout_seconds": 2, "max_output_bytes": 1024,
        },
        "rationale": "DETERMINISTIC MOCK: inspect the owned in-namespace fixture.",
    }


if __name__ == "__main__":
    print(json.dumps(proposal(), sort_keys=True))
