#!/usr/bin/env python3
"""Inspect fixed stock OpenSSH files and compiled owned-lab preparation.

This entry point never starts a daemon/helper, performs authentication, generates
keys or issues authority. Installed dependency metadata is not native acceptance.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent import stock_ssh_runtime as runtime
from recon_cockpit.secure_agent import stock_ssh_spec as spec


def _exclusive_output(path):
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("ssh_preflight_parent_must_be_private")
        return os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=parent)
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--configuration", required=True, choices=spec.CONFIGURATIONS)
    parser.add_argument("--case", required=True, choices=spec.CASES)
    parser.add_argument("--output", required=True, type=Path,
                        help="new receipt below an existing owner-only directory")
    args = parser.parse_args(argv)
    selection = spec.selection(args.configuration, args.case)
    try:
        descriptor = _exclusive_output(args.output)
    except (OSError, ValueError):
        print(json.dumps({"status": "output_refused", "preflight_only": True}), file=sys.stderr)
        return 2
    result = {"schema_version": "1", "preflight_only": True,
        "configuration": args.configuration, "case": args.case, "selection": selection,
        "service_execution_verified": False, "native_services_started": 0,
        "helper_executions_performed": 0, "authentication_attempts": 0,
        "keys_generated": 0, "tool_actions_executed": 0, "authority_issued": False,
        "actual_provider_calls": 0, "actual_cost_microusd": 0}
    started = time.monotonic()
    with os.fdopen(descriptor, "w", encoding="ascii") as destination:
        try:
            control = ExecutionControl(started + 15)
            manifest = runtime.inspect_runtime(args.configuration, args.case, control)
            runtime.verify_current(manifest, control)
            result.update(status="runtime_inspected", runtime_manifest=manifest,
                          runtime_sha256=runtime.manifest_digest(manifest))
        except Exception as exc:
            result.update(status="inspection_failed", failure_type=type(exc).__name__)
        result["inspection_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        json.dump(result, destination, sort_keys=True, indent=2, allow_nan=False)
        destination.write("\n")
        destination.flush()
        os.fsync(destination.fileno())
    print(json.dumps({"status": result["status"], "preflight_only": True,
                      "service_execution_verified": False}))
    return 0 if result["status"] == "runtime_inspected" else 2


if __name__ == "__main__":
    raise SystemExit(main())
