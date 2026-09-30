"""Owned TLS planning through Linux boundaries; scripted PTYs prove mechanics."""

import fcntl
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli, provider_lab
from recon_cockpit.secure_agent.assessment_planning_transport import LinuxOwnedPlanningTransport
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent.cost_ledger import CostLedger
from recon_cockpit.secure_agent.evidence import inspect_assessment
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.provider_contract import BOUNDARY_NAMES as TLS_BOUNDARIES
from test_secure_approval_linux import terminal
from test_secure_launch_admission_linux import run_workflow
from test_secure_provider_linux import processes, assert_reaped, descendants, assert_no_survivors


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned TLS assessment planning')
    assert sys.platform == 'linux' and os.geteuid() != 0


def planning_options(tmp_path, scenario='success'):
    return ['--isolated-launcher', '--require-launch-audit', '--require-launch-approval',
            '--assessment-planning-owned-tls', scenario, '--planning-ledger', str(tmp_path/'cost')]


def arguments(tmp_path, scenario='success', *, execute=True):
    return ['--workflow-assessment', 'a', '--owned-lab', '--isolated-audit',
            '--isolated-approvals', '--isolated-launch-admission',
            '--policy', 'examples/secure-agent-discovery-policy.json',
            '--assessment-dir', str(tmp_path/'evidence'), '--audit', str(tmp_path/'events.jsonl'),
            '--execute' if execute else '--dry-run', *planning_options(tmp_path, scenario)]


def stored_accounting(tmp_path):
    # Read only after the session closes its writer: closing another SQLite
    # handle can release locks held by the active authority in this process.
    with CostLedger(tmp_path/'cost', read_only=True) as ledger:
        return ledger.report(), ledger.attempts(), ledger.events(limit=1000)


def forbid_launches(monkeypatch):
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: pytest.fail('launcher started'))
    monkeypatch.setattr(LinuxApprovalService, '_start', lambda *_: pytest.fail('approval started'))


def assert_tls_receipt(receipt, *, status='ok', requests=1):
    assert receipt['status'] == status
    assert receipt['boundary_checks'] == dict.fromkeys(TLS_BOUNDARIES, True)
    assert receipt['cleanup'] == {'worker_reaped': True, 'owner_reaped': True}
    assert receipt['connection_count'] == 1 and receipt['request_count'] == requests


def tls_process_count(processes, role):
    return sum('/app/assessment_planning_tls_' + role + '.py' in argv for _, argv, _ in processes)


@pytest.mark.parametrize('backend', ['--fixture', '--owned-lab'])
@pytest.mark.parametrize('case,outcome,exchanges', [
    ('a', 'validated', 3), ('b', 'not_demonstrated', 3), ('c', 'inconclusive', 3),
    ('d', 'inconclusive', 3), ('e', 'inconclusive', 3), ('f', 'inconclusive', 2),
])
def test_owned_tls_planning_all_outcomes_settle_before_both_direct_gates(
        tmp_path, monkeypatch, capsys, terminal, processes, backend, case, outcome, exchanges):
    original_main, original_print = cli.main, cli._print
    original_settle, original_run = CostLedger.settle_usage, LinuxFixtureLauncher.run
    settled, launched, summaries = [], [], []

    def settle(ledger, *args, **kwargs):
        result = original_settle(ledger, *args, **kwargs)
        settled.append(ledger)
        return result

    def run(launcher, *args, **kwargs):
        assert launcher._witness_source is not None and launcher._approval_source is not None
        assert len(settled) == len(launched) + 1
        accounting = settled[-1].report()['summary']
        assert accounting['mode'] == 'simulation' and accounting['reserved_microusd'] == 0
        assert accounting['actual_microusd'] == len(settled) * 778
        assert accounting['unresolved_attempts'] == 0
        assert all(row['state'] == 'settled' for row in settled[-1].attempts())
        rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
        assert rows[-1]['event_type'] == 'execution_started'
        assert rows[-2]['event_type'] == 'approval_consumed'
        assert sum(row['event_type'] == 'assessment_planning_proposal_released' for row in rows) == len(settled)
        # Each fresh provider owner and worker is already reaped before any
        # approved assessment action crosses the independent launcher boundary.
        for process, argv, _ in processes:
            if any('/app/assessment_planning_tls_' + role + '.py' in argv for role in ('owner', 'worker')):
                assert process.poll() is not None
        launched.append(True)
        return original_run(launcher, *args, **kwargs)

    def capture(value):
        summaries.append(value)
        original_print(value)

    monkeypatch.setattr(CostLedger, 'settle_usage', settle)
    monkeypatch.setattr(LinuxFixtureLauncher, 'run', run)
    monkeypatch.setattr(cli, '_print', capture)
    monkeypatch.setattr(cli, 'main', lambda argv: original_main([*argv, *planning_options(tmp_path)]))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, backend)
    summary = summaries[-1]
    assert summary['live_calls_enabled'] is False
    assert summary['planning']['actual_provider_calls'] == 0
    assert summary['planning']['transport'] == 'owned_tls'
    assert_tls_receipt(summary['planning']['transport_receipt'])
    assert summary['broker']['calls_reserved'] == len(settled) == len(launched) == exchanges
    assert summary['coordinator_boundary_checks'] == summary['parser_boundary_checks'] == dict.fromkeys(BOUNDARY_NAMES, True)
    assert tls_process_count(processes, 'owner') == tls_process_count(processes, 'worker') == exchanges
    report = json.loads((tmp_path/'evidence'/'report.json').read_text())
    assert len(report['records']) == exchanges and report['integrity_issues'] == []
    files = {path: (path.read_bytes(), path.stat().st_mtime_ns)
             for directory in (tmp_path/'cost', tmp_path/'evidence')
             for path in directory.rglob('*') if path.is_file()}
    accounting, attempts, events = stored_accounting(tmp_path)
    assert accounting['summary']['actual_microusd'] == exchanges * 778
    assert len(attempts) == exchanges and all(row['state'] == 'settled' for row in attempts)
    assert sum(row['kind'] == 'cost_settled' for row in events) == exchanges
    assert inspect_assessment(tmp_path/'evidence') == report
    assert files == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files}
    assert_reaped(processes)


@pytest.mark.parametrize('scenario,state,status,requests', [
    ('refusal', 'settled', 'ok', 1), ('substituted_action', 'settled', 'ok', 1),
    ('missing_usage', 'uncertain', 'ok', 1), ('unknown_usage', 'uncertain', 'ok', 1),
    ('usage_overrun', 'settled', 'ok', 1), ('malformed', 'uncertain', 'malformed_response', 1),
    ('http_error', 'uncertain', 'http_error', 1), ('redirect', 'uncertain', 'http_error', 1),
    ('rate_limit', 'uncertain', 'http_error', 1), ('oversized', 'uncertain', 'response_too_large', 1),
    ('truncated', 'uncertain', 'malformed_response', 1),
    ('credential_echo', 'uncertain', 'credential_reflection', 1),
    ('escaped_credential_echo', 'uncertain', 'credential_reflection', 1),
    ('untrusted_certificate', 'uncertain', 'tls_error', 0), ('wrong_hostname', 'uncertain', 'tls_error', 0),
])
def test_untrusted_tls_planning_failure_never_requests_approval_or_execution(
        tmp_path, monkeypatch, capsys, processes, scenario, state, status, requests):
    forbid_launches(monkeypatch)
    assert cli.main(arguments(tmp_path, scenario)) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == 'provider_failed'
    assert summary['broker']['calls_reserved'] == 1 and summary['actions_succeeded'] == 0
    assert summary['owned_lab']['closure']['connection_count'] == 0
    assert summary['planning']['actual_provider_calls'] == 0
    assert_tls_receipt(summary['planning']['transport_receipt'], status=status, requests=requests)
    assert tls_process_count(processes, 'owner') == tls_process_count(processes, 'worker') == 1
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == state
    if state == 'uncertain':
        assert accounting['summary']['reserved_microusd'] > 0
        assert accounting['summary']['actual_microusd'] == 0
        assert accounting['summary']['unresolved_attempts'] == 1
    else:
        assert accounting['summary']['reserved_microusd'] == 0
        assert accounting['summary']['actual_microusd'] > 0
        assert accounting['summary']['unresolved_attempts'] == 0
    if scenario == 'usage_overrun':
        assert attempts[0]['reservation_overrun_microusd'] > 0
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
    rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
    assert not any(row['event_type'] in {'execution_started', 'assessment_planning_proposal_released'} for row in rows)
    assert_reaped(processes)


def test_planning_budget_refusal_prevents_tls_runtime_and_execution(tmp_path, monkeypatch, capsys):
    forbid_launches(monkeypatch)
    monkeypatch.setattr(LinuxOwnedPlanningTransport, 'exchange', lambda *_a, **_k: pytest.fail('TLS transport entered'))
    assert cli.main([*arguments(tmp_path), '--planning-budget-microusd', '0']) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == 'provider_failed' and summary['broker']['calls_reserved'] == 0
    assert summary['planning']['transport_receipt'] is None
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert accounting['summary']['committed_microusd'] == 0
    assert len(attempts) == 1 and attempts[0]['state'] == 'cancelled'
    assert inspect_assessment(tmp_path/'evidence')['records'] == []


@pytest.mark.parametrize('event,state', [
    ('assessment_planning_reserved', 'cancelled'),
    ('assessment_planning_dispatch_started', 'uncertain'),
])
def test_lost_pretransport_audit_ack_prevents_tls_runtime(
        tmp_path, monkeypatch, capsys, event, state):
    forbid_launches(monkeypatch)
    monkeypatch.setattr(LinuxOwnedPlanningTransport, 'exchange', lambda *_a, **_k: pytest.fail('TLS transport entered'))
    original = LinuxAuditSink.emit

    def emit(audit, value):
        original(audit, value)
        if value['event_type'] == event:
            raise AuditUnavailable('OWNED-LOST-PRETRANSPORT-ACK')

    monkeypatch.setattr(LinuxAuditSink, 'emit', emit)
    assert cli.main(arguments(tmp_path)) == 3
    assert json.loads(capsys.readouterr().out)['execution_status'] == 'audit_error'
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == state
    assert accounting['summary']['actual_microusd'] == 0
    assert (accounting['summary']['reserved_microusd'] > 0) is (state == 'uncertain')
    assert inspect_assessment(tmp_path/'evidence')['records'] == []


@pytest.mark.parametrize('execute', [False, True])
def test_dry_or_noninteractive_tls_planning_cannot_start_approval_or_assessment_lab(
        tmp_path, monkeypatch, capsys, processes, execute):
    forbid_launches(monkeypatch)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    assert cli.main(arguments(tmp_path, execute=execute)) == (2 if execute else 0)
    summary = json.loads(capsys.readouterr().out)
    assert summary['actions_succeeded'] == 0
    assert summary['owned_lab']['closure']['connection_count'] == 0
    assert_tls_receipt(summary['planning']['transport_receipt'])
    assert tls_process_count(processes, 'owner') == tls_process_count(processes, 'worker') == 1
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'settled'
    assert accounting['summary']['actual_microusd'] == 778
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
    assert_reaped(processes)


@pytest.mark.parametrize('stop', ['cancel', 'deadline'])
def test_stopping_active_planning_tls_reaps_namespace_trees_and_retains_hold(
        tmp_path, monkeypatch, capsys, processes, stop):
    forbid_launches(monkeypatch)
    original = provider_lab._send
    identities, observed_connection = {}, []

    def send(supervisor, process, raw, *, close=False):
        original(supervisor, process, raw, close=close)
        if not close or process is not supervisor.processes.get('worker'):
            return

        def connected():
            for pid in descendants(process.pid):
                try:
                    argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                    if (b'/app/assessment_planning_tls_worker.py' not in argv
                            or 'python' not in Path(os.fsdecode(argv[0])).name):
                        continue
                    rows = Path(f'/proc/{pid}/net/tcp').read_text().splitlines()[1:]
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if any(row.split()[3] == '01' and any(address.endswith(':20FB')
                       for address in row.split()[1:3]) for row in rows):
                    observed_connection.append(pid)
                    for child in supervisor.processes.values():
                        identities.update(descendants(child.pid))
                    return True
            return False

        supervisor.wait_for(connected, worker_may_exit=True)
        if stop == 'cancel':
            supervisor.control.cancelled.set()

    monkeypatch.setattr(provider_lab, '_send', send)
    started = time.monotonic()
    status = cli.main([*arguments(tmp_path, 'slow'), '--session-max-seconds', '5' if stop == 'deadline' else '30'])
    assert status == 2
    assert observed_connection and len(identities) >= 2
    assert time.monotonic() - started < 10
    summary = json.loads(capsys.readouterr().out)
    assert summary['stop_reason'] == ('session_cancelled' if stop == 'cancel' else 'session_timeout')
    assert summary['actions_succeeded'] == 0
    receipt = summary['planning']['transport_receipt']
    assert receipt['cleanup'] == {'worker_reaped': True, 'owner_reaped': True}
    if stop == 'deadline':
        assert receipt['status'] == 'deadline_exceeded'
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'uncertain'
    assert accounting['summary']['reserved_microusd'] > 0
    assert accounting['summary']['actual_microusd'] == 0
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
    assert_no_survivors(identities)
    assert_reaped(processes)


def test_lost_tls_settlement_audit_ack_preserves_charge_without_releasing_proposal(
        tmp_path, monkeypatch, capsys, processes):
    forbid_launches(monkeypatch)
    original = LinuxAuditSink.emit

    def emit(audit, event):
        original(audit, event)
        if event['event_type'] == 'assessment_planning_settled':
            raise AuditUnavailable('OWNED-LOST-TLS-SETTLEMENT-ACK')

    monkeypatch.setattr(LinuxAuditSink, 'emit', emit)
    assert cli.main(arguments(tmp_path)) == 3
    assert json.loads(capsys.readouterr().out)['execution_status'] == 'audit_error'
    accounting, attempts, _ = stored_accounting(tmp_path)
    assert len(attempts) == 1 and attempts[0]['state'] == 'settled'
    assert accounting['summary']['actual_microusd'] == 778
    assert accounting['summary']['reserved_microusd'] == 0
    rows = [json.loads(line) for line in (tmp_path/'events.jsonl').read_text().splitlines()]
    assert not any(row['event_type'] in {'execution_started', 'assessment_planning_proposal_released'} for row in rows)
    assert not (tmp_path/'evidence'/'report.json').exists()
    assert inspect_assessment(tmp_path/'evidence')['records'] == []
    assert tls_process_count(processes, 'owner') == tls_process_count(processes, 'worker') == 1
    assert_reaped(processes)


def test_planning_tls_worker_cannot_read_host_credentials_ledger_or_authority(
        tmp_path, monkeypatch, capsys, processes):
    forbid_launches(monkeypatch)
    sentinel = tmp_path/'host-private-key'
    sentinel.write_text('HOST_FILE_PLANNING_CANARY')
    sentinel.chmod(0o600)
    monkeypatch.setenv('OPENAI_API_KEY', 'HOST_ENV_PLANNING_CANARY')
    monkeypatch.setenv('HTTPS_PROXY', 'http://HOST_PROXY_PLANNING_CANARY.invalid')
    source_fd = os.open(sentinel, os.O_RDONLY)
    inherited_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD, 128)
    os.close(source_fd)
    os.set_inheritable(inherited_fd, True)
    source = Path(provider_lab.__file__).with_name('provider_worker.py').read_text()
    checks = (
        "    assert 'OPENAI_API_KEY' not in os.environ and 'HTTPS_PROXY' not in os.environ\n"
        f"    assert not os.path.exists({str(sentinel)!r})\n"
        f"    assert not os.path.exists({('/proc/' + str(os.getpid()) + '/root' + str(sentinel))!r})\n"
        f"    assert not os.path.exists('/proc/self/fd/{inherited_fd}')\n"
        f"    assert not os.path.exists({str(tmp_path/'cost')!r})\n"
        f"    assert not os.path.exists({str(tmp_path/'evidence')!r})\n"
        "    for path in ('/run/provider/server.key', '/run/provider/server.crt', '/usr/sbin/nft'):\n"
        "        assert not os.path.exists(path)\n"
        "    for name in ('cost_ledger', 'evidence', 'audit', 'approval', 'launch_admission', 'execution', 'coordinator'):\n"
        "        assert not os.path.exists('/app/recon_cockpit/secure_agent/' + name + '.py')\n"
        "    for fd in os.listdir('/proc/self/fd'):\n"
        "        try:\n"
        "            target = os.readlink('/proc/self/fd/' + fd)\n"
        "        except (FileNotFoundError, ProcessLookupError):\n"
        "            continue\n"
        "        assert not target.startswith(('user:[', 'net:[', 'mnt:[', 'pid:[', 'ipc:[', 'uts:[', 'cgroup:['))\n"
        "    for path in ('/proc/self/cmdline', '/proc/self/environ'):\n"
        "        with open(path, 'rb') as current:\n"
        "            assert launch['credential'].encode('ascii') not in current.read()\n"
    )
    assert source.count('def execute(launch):\n') == 1
    instrumented = tmp_path/'checked_planning_tls_worker.py'
    instrumented.write_text(source.replace('def execute(launch):\n', 'def execute(launch):\n' + checks))
    original_mounts, original_send = provider_lab._planning_mounts, provider_lab._send
    credentials = []

    def mounts(argv, *, owner):
        original_mounts(argv, owner=owner)
        if not owner:
            index = argv.index('/app/provider_worker.py')
            assert argv[index - 2] == '--ro-bind'
            argv[index - 1] = str(instrumented)

    def send(supervisor, process, raw, *, close=False):
        if close and process is supervisor.processes.get('worker'):
            credentials.append(json.loads(raw)['credential'])
        return original_send(supervisor, process, raw, close=close)

    monkeypatch.setattr(provider_lab, '_planning_mounts', mounts)
    monkeypatch.setattr(provider_lab, '_send', send)
    try:
        assert cli.main(arguments(tmp_path, execute=False)) == 0
    finally:
        os.close(inherited_fd)
    summary = json.loads(capsys.readouterr().out)
    assert len(credentials) == 1
    assert_tls_receipt(summary['planning']['transport_receipt'])
    exposed = (tmp_path/'events.jsonl').read_text() + json.dumps(summary)
    for _, argv, environment in processes:
        exposed += json.dumps(argv) + json.dumps(environment)
    for value in [*credentials, 'HOST_ENV_PLANNING_CANARY', 'HOST_PROXY_PLANNING_CANARY',
                  'HOST_FILE_PLANNING_CANARY']:
        assert value not in exposed
    assert_reaped(processes)
