#!/usr/bin/env python3
"""Capture one development-only owned TLS feasibility trial as private JSON."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon_cockpit.secure_agent.tls_posture_diagnostic import CASES, run_trial, validate_selection
from recon_cockpit.secure_agent.tls_posture_diagnostic_worker import VERSIONS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=CASES)
    parser.add_argument("--version", required=True, choices=VERSIONS)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute-owned-diagnostic", required=True, action="store_true")
    args = parser.parse_args(argv)
    validate_selection(args.case, args.version)
    # Reserve a new private regular file before executing. Never overwrite an
    # earlier receipt or follow a symlink supplied as the destination.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as destination:
        try:
            result = run_trial(args.case, args.version)
        except Exception as exc:
            # A setup/capture failure is still a retained development finding.
            # Do not emit traceback, exception text or inherited configuration.
            result = {"schema_version": "1", "diagnostic_only": True,
                "case": args.case, "version": args.version,
                "failure": "diagnostic_setup_or_capture_failed", "failure_type": type(exc).__name__,
                "actual_provider_calls": 0, "actual_cost_microusd": 0}
        json.dump(result, destination, sort_keys=True, indent=2, allow_nan=False)
        destination.write("\n")
    if "failure" in result:
        print(json.dumps({"diagnostic_only": True, "output": str(args.output), "failure": result["failure"]}))
        return 2
    print(json.dumps({"diagnostic_only": True, "case": args.case, "version": args.version,
        "output": str(args.output), "execution": {key: result["execution"][key]
            for key in ("exit_code", "stop_reason", "elapsed_ms", "truncated")},
        "worker_ready": result["confinement"]["worker_ready"], "cleanup": result["cleanup"]}))
    return 0 if result["confinement"]["worker_ready"] and result["cleanup"]["closed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
