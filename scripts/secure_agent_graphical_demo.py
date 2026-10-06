"""Bounded owner walkthrough for four disconnected owned-fixture actions.

Default operation prints the exact plan only. Explicit execution opens the fixed
isolated graphical reviewer; the operator must personally answer each prompt.
No automatic input, provider, credentials, real target attachment or resume mode.
"""

import argparse
import json
from pathlib import Path
import signal
import stat
import os
import tempfile

from recon_cockpit.gui.controller import read_scope_file
from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentRequest, ConfigurableAssessmentService
from recon_cockpit.secure_agent.execution import ExecutionStopped


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, default=Path(__file__).resolve().parents[1] /
                        'examples/secure-agent-configurable-scope.json')
    parser.add_argument('--output-parent', type=Path, help='Existing operator-owned, non-shared-writable folder.')
    parser.add_argument('--execute-owned-fixtures', action='store_true')
    args = parser.parse_args(argv)
    if args.execute_owned_fixtures and args.output_parent is None:
        parser.error('--execute-owned-fixtures requires --output-parent')
    try:
        scope = read_scope_file(args.scope)
        if not args.execute_owned_fixtures:
            print(json.dumps({'mode': 'plan_only', 'capability': contract.capability_descriptor(scope),
                'approval_frontend': 'graphical_v1', 'personal_walkthrough_recorded': False}, sort_keys=True))
            return 0
        parent = args.output_parent.absolute()
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('invalid_graphical_demo_parent')
        directory = Path(tempfile.mkdtemp(prefix='graphical-owned-', dir=parent))
        request = ConfigurableAssessmentRequest(scope_json=contract.encode(scope),
            policy_json=contract.encode(contract.policy_for_scope(scope, require_approval=True).to_dict()),
            assessment_dir=directory / 'evidence', audit_path=directory / 'audit.jsonl',
            execute=True, approval_frontend='graphical_v1')
        service = ConfigurableAssessmentService(request)
        previous = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda *_: service.cancel())
            print(json.dumps({'mode': 'owned_graphical_review', 'session_dir': str(directory),
                              'limits': contract.LIMITS, 'live_calls_enabled': False}), flush=True)
            result = service.run()
            print(json.dumps(result, sort_keys=True))
            return 0 if result['assessment_outcome'] == 'completed' else 1
        finally:
            service.cancel()
            for number, handler in previous.items():
                signal.signal(number, handler)
    except ExecutionStopped as exc:
        print(json.dumps({'outcome': 'stopped', 'reason': exc.reason, 'live_calls_enabled': False}))
        return 1
    except (OSError, ValueError, RuntimeError):
        print(json.dumps({'outcome': 'failed', 'reason': 'graphical_owned_walkthrough_unavailable',
                          'live_calls_enabled': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
