#!/usr/bin/env python3
"""Run or inspect a fixed owned DNS-to-HTTP/TLS assessment."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", allow_abbrev=False)
    run.add_argument("--configuration", choices=("A", "B"), default="A")
    run.add_argument("--case", choices=("O1", "O2", "O3", "O4", "O5", "R1", "R2", *("N" + str(n) for n in range(1, 17))), default="O4")
    run.add_argument("--order", choices=("default", "tls_first"), default="default")
    run.add_argument("--directory", type=Path, required=True)
    run.add_argument("--execute", action="store_true")
    run.add_argument("--unattended-owned-lab-test", action="store_true",
        help="Explicit test policy for this disconnected owned lab; records no personal approval.")
    inspect = commands.add_parser("inspect", allow_abbrev=False)
    inspect.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        from recon_cockpit.secure_agent.name_tls_evidence import inspect_trial
        report = inspect_trial(args.directory)
    else:
        from recon_cockpit.secure_agent.name_tls import run_trial
        report = run_trial(args.directory, configuration=args.configuration, case=args.case, order=args.order,
            execute=args.execute, unattended_owned_lab_test=args.unattended_owned_lab_test)
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if report.get("case_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
