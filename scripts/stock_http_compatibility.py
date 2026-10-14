#!/usr/bin/env python3
"""Run or inspect one finite disconnected nginx or Apache HTTP operation."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon_cockpit.secure_agent.stock_http_spec import CONFIGURATIONS, CASES


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", allow_abbrev=False)
    run.add_argument("--implementation", choices=("nginx", "apache"), required=True)
    run.add_argument("--configuration", choices=CONFIGURATIONS, required=True)
    run.add_argument("--case", choices=CASES, required=True)
    run.add_argument("--directory", type=Path, required=True)
    run.add_argument("--execute", action="store_true")
    run.add_argument("--unattended-owned-lab-test", action="store_true",
                     help="Explicit no-personal-approval test policy for this fixed disconnected corpus only.")
    inspect = commands.add_parser("inspect", allow_abbrev=False)
    inspect.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        from recon_cockpit.secure_agent.stock_http_production_evidence import inspect_trial
        report = inspect_trial(args.directory)
    else:
        from recon_cockpit.secure_agent.stock_http_production import run_trial
        report = run_trial(args.directory, implementation=args.implementation,
            configuration=args.configuration, case=args.case,
            execute=args.execute, unattended_owned_lab_test=args.unattended_owned_lab_test)
    # Raw service bytes remain private evidence, never terminal control text.
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0 if report["case_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
