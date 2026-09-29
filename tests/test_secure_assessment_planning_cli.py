"""Pre-I/O selection and fresh simulation storage for bounded planning."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.cost_contract import CostError
from recon_cockpit.secure_agent.cost_ledger import CostLedger


GATES = ['--isolated-audit', '--isolated-approvals', '--isolated-launch-admission',
         '--isolated-launcher', '--require-launch-audit', '--require-launch-approval']


def options(tmp_path):
    return ['--workflow-assessment', 'a', '--fixture', '--dry-run', *GATES,
            '--assessment-dir', str(tmp_path/'evidence'),
            '--assessment-planning-offline', 'success', '--planning-ledger', str(tmp_path/'money')]


@pytest.mark.parametrize('fault', ['workflow', 'approval_gate', 'ledger', 'no_profile',
    'negative_budget', 'oversized_budget', 'planning_duration', 'live', 'model', 'same_directory',
    'ledger_in_evidence', 'evidence_in_ledger'])
def test_invalid_planning_selection_refuses_before_policy_or_storage(tmp_path, monkeypatch, fault):
    args = options(tmp_path)
    if fault == 'workflow':
        args[0] = '--http-assessment'
    elif fault == 'approval_gate':
        args.remove('--require-launch-approval')
    elif fault == 'ledger':
        index = args.index('--planning-ledger')
        del args[index:index+2]
    elif fault == 'no_profile':
        index = args.index('--assessment-planning-offline')
        del args[index:index+2]
    elif fault in ('negative_budget', 'oversized_budget'):
        args += ['--planning-budget-microusd', '-1' if fault == 'negative_budget' else str(10**15+1)]
    elif fault == 'planning_duration':
        args += ['--session-max-seconds', '121']
    elif fault == 'live':
        args += ['--live']
    elif fault == 'model':
        args += ['--openai-model', 'unreviewed']
    elif fault == 'same_directory':
        args[args.index('--planning-ledger')+1] = str(tmp_path/'evidence')
    elif fault == 'ledger_in_evidence':
        args[args.index('--planning-ledger')+1] = str(tmp_path/'evidence'/'money')
    else:
        args[args.index('--assessment-dir')+1] = str(tmp_path/'money'/'evidence')
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: pytest.fail('policy read before refusal'))
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    assert not list(tmp_path.iterdir())


def test_new_planning_account_inherits_cap_and_cannot_resume(tmp_path):
    directory = tmp_path/'money'
    args = SimpleNamespace(assessment_planning_offline='success', planning_ledger=directory,
                           planning_budget_microusd=12345)
    with cli._planning_context(args, str(uuid4())) as (ledger, scope):
        report = ledger.report(scope)
        assert report['summary']['mode'] == 'simulation'
        assert report['summary']['effective_available_microusd'] == 12345
        assert [row['kind'] for row in report['budget_chain']] == [
            'account', 'engagement', 'session', 'agent', 'action']
        assert report['summary']['attempt_count'] == 0
        identity = ledger.ledger_id
    saved = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    with pytest.raises(CostError):
        with cli._planning_context(args, str(uuid4())):
            pytest.fail('existing money account replaced')
    with CostLedger(directory, read_only=True) as ledger:
        assert ledger.ledger_id == identity
        assert ledger.report()['summary']['limit_microusd'] == 12345
    assert saved == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}


def test_default_workflow_creates_no_planning_account(tmp_path, monkeypatch):
    monkeypatch.setattr(CostLedger, 'create', lambda *_args, **_kwargs: pytest.fail('ledger created'))
    with cli._planning_context(SimpleNamespace(assessment_planning_offline=None), str(uuid4())) as planning:
        assert planning is None
