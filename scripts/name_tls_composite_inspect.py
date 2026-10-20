#!/usr/bin/env python3
"""Inspect one saved N15 composite; never create an owner or approval grant."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("file", type=Path, help="Private saved N15 composite JSON file")
    args = parser.parse_args(argv)
    from recon_cockpit.secure_agent.name_tls_composite_evidence import inspect_composite
    report = inspect_composite(args.file)
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if report["case_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
