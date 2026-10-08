#!/usr/bin/env python3
"""Replay a private TLS development capture without executing an assessment."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.tls_posture_observation_contract import PROFILE_IDS
from recon_cockpit.secure_agent.tls_posture_observation_inspection import inspect_saved_diagnostic


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="Existing private mediated diagnostic JSON")
    parser.add_argument("--version", choices=PROFILE_IDS, required=True,
                        help="Expected fixed TLS version; independently checked against the capture")
    args = parser.parse_args(argv)
    try:
        observation = inspect_saved_diagnostic(args.capture, args.version)
    except (OSError, ValueError, IsolationUnavailable):
        print(json.dumps({"diagnostic_only": True, "execution_authority": False,
                          "status": "unavailable_or_invalid"}, sort_keys=True))
        return 2
    print(json.dumps({"diagnostic_only": True, "execution_authority": False,
                      "status": "parsed", "observation": observation}, sort_keys=True, allow_nan=False))
    # Successful inspection does not mean a useful TLS task or process exit0.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
