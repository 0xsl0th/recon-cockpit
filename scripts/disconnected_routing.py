#!/usr/bin/env python3
"""Run fixed, separately selected tools in the disconnected HTTP/SSH routing lab."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon_cockpit.secure_agent.routing_contract import SELECTORS, BUDGET_CASES, DEPLOYMENTS


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", allow_abbrev=False)
    run.add_argument("--action", choices=SELECTORS, action="append", dest="selectors", required=True,
                     help="Select one independent action; repeat for explicit order, each at most once.")
    run.add_argument("--budget-case", choices=BUDGET_CASES, default="ordinary")
    run.add_argument("--deployment", choices=DEPLOYMENTS,
                     help="Select one fixed owned deployment for this assessment; omitted uses the original fixed-A contract.")
    run.add_argument("--directory", type=Path, required=True)
    run.add_argument("--execute", action="store_true")
    run.add_argument("--unattended-owned-lab-test", action="store_true",
                     help="Explicit test policy only for the fixed owned disconnected lab; records no personal approval.")
    inspect = commands.add_parser("inspect", allow_abbrev=False)
    inspect.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        from recon_cockpit.secure_agent.routing_evidence import inspect_trial
        report = inspect_trial(args.directory)
    else:
        from recon_cockpit.secure_agent.routing import run_trial
        report = run_trial(args.directory, selectors=args.selectors, budget_case=args.budget_case,
            deployment=args.deployment,
            execute=args.execute, unattended_owned_lab_test=args.unattended_owned_lab_test)
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0 if report["case_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
