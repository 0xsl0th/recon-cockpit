"""Native independent witness/admission enforcement for the stock SSH profile.

Scripted owned PTYs and privately instrumented workers are test mechanisms,
not personal approval evidence. Refusal tests guard against native startup;
the explicit approved O2 test executes one confined stock SSH key exchange.
"""

from contextlib import contextmanager
from copy import deepcopy
import json
import os
import sys
import threading
import time
from uuid import UUID, uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission, launcher_protocol
from recon_cockpit.secure_agent import stock_ssh_contract as contract
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.stock_ssh_backend import AuthorizedStockSshBackend
from recon_cockpit.secure_agent.stock_ssh_evidence import StockSshEvidenceStore, inspect_trial
from recon_cockpit.secure_agent.stock_ssh_lab import StockSshLab
from recon_cockpit.secure_agent.stock_ssh_runtime import inspect_runtime
from recon_cockpit.secure_agent.stock_ssh_client_runtime import inspect_client_runtime
from test_secure_approval_linux import terminal, scripted_review, instrument_worker
from test_secure_audit_witness import intent
from test_secure_audit_witness_linux import instrument_writer
from test_secure_fixture_launcher_linux import instrument

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def native_gate():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned stock authority enforcement')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.fixture(scope='module')
def installed_runtime():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('stock runtime inspection belongs to explicit native validation')
    control = ExecutionControl(time.monotonic() + 30)
    selected = contract.selection('A', 'O2')
    return {'daemon': inspect_runtime('A', 'O2', control),
            'client': inspect_client_runtime(selected, control)}


def _selection(runtime, case='O2'):
    assert runtime['daemon']['configuration'] == 'A'
    return contract.selection('A', case)


def guarded_launcher(tmp_path, monkeypatch):
    """The real launcher gates run; native run is an unreachable test tripwire."""
    def transform(source):
        selected = 'result = (owned.run('
        assert source.count(selected) == 1
        source = source.replace(selected,
            "os.write(2, b'UNEXPECTED_STOCK_NATIVE_START\\n')\n"
            "                time.sleep(2)\n"
            "                raise RuntimeError('UNEXPECTED_STOCK_NATIVE_START')\n                " + selected)
        ending = "    except Exception:\n        sys.stderr.write('fixture_launcher_refused\\n')"
        position = source.rfind(ending)
        assert position > source.index('def main():')
        return source[:position] + source[position:].replace(ending,
            "    except Exception as error:\n"
            "        sys.stderr.write('STOCK_ENFORCEMENT_REASON:' + str(error) + '\\n')\n"
            "        sys.stderr.flush()\n"
            "        time.sleep(0.05)\n"
            "        sys.stderr.write('fixture_launcher_refused\\n')", 1)
    instrument(tmp_path, monkeypatch, transform)


@contextmanager
def boundary(tmp_path, installed_runtime, *, required=True):
    selected, session = _selection(installed_runtime), str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=required)
    lab = StockSshLab(selected, session, limits, execute=True, runtime=installed_runtime)
    with LinuxAuditSink(tmp_path / 'audit.jsonl', launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        backend = AuthorizedStockSshBackend(policy, session, limits, lab, execute=True)
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session
    assert not lab.started


def emitted_intent(audit, action, policy, session):
    audit.emit(intent(action, policy, session, backend=contract.BACKEND))


def observe_ready(monkeypatch, launcher, transform=None):
    reached = []
    original = launcher._send
    def send(raw, **kwargs):
        value = launch_admission.decode(raw)
        if value.get('operation') == 'execute':
            reached.append(launcher._checks == dict.fromkeys(launcher_protocol.CHECKS, True))
            if transform is not None:
                transform(value)
                raw = launch_admission.encode(value)
        return original(raw, **kwargs)
    monkeypatch.setattr(launcher, '_send', send)
    return reached


def assert_refused(launcher, action, policy, control, *, ready=None, reason=None):
    with pytest.raises((IsolationUnavailable, ExecutionStopped)):
        launcher.run(action, policy, control=control)
    assert launcher._closed and launcher.snapshot['executions_reserved'] == 0
    if ready is not None:
        assert ready == [True], 'refusal must reach the real initialized launcher, not fail unrelated setup'
    if launcher._supervisor is not None:
        stderr = bytes(launcher._supervisor.buffers['worker_err'])
        assert b'UNEXPECTED_STOCK_NATIVE_START' not in stderr
        assert launcher._process.poll() is not None
        if reason is not None:
            assert reason.encode() in stderr, stderr
    with pytest.raises(IsolationUnavailable):
        launcher.run(action, policy, control=ExecutionControl(time.monotonic() + 5))


def test_scripted_required_approval_completes_owned_o2_and_replays_evidence(
        tmp_path, monkeypatch, terminal, installed_runtime, record_property):
    """Real approval, audit and execution; scripted PTY is not owner acceptance."""
    monkeypatch.setattr(StockSshLab, 'start',
                        lambda *a, **k: pytest.fail('host stock owner started'))
    monkeypatch.setattr(AuthorizedStockSshBackend, 'run',
                        lambda *a, **k: pytest.fail('host stock tool executed'))
    selected, session = _selection(installed_runtime), str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=True)
    lab = StockSshLab(selected, session, limits, execute=True, runtime=installed_runtime)
    original = AuthorizedStockSshBackend(policy, session, limits, lab, execute=True)
    action = parse_action(contract.action(selected))
    manifest = {'schema_version': '1', 'assessment_id': str(uuid4()), 'session_id': session,
        'selection': selected, 'policy': policy.to_dict(), 'limits': contract.limits(selected),
        'runtime': installed_runtime, 'identity': lab.identity}
    directory = tmp_path / 'evidence'
    started = time.monotonic()
    control = ExecutionControl(started + 60)
    with StockSshEvidenceStore(directory, manifest, deadline=control.deadline) as evidence:
        with LinuxAuditSink(directory / 'audit.jsonl', launch_witness=True) as audit, \
                LinuxApprovalService(policy, session, launch_witness=True) as approvals:
            with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as launcher:
                reference, _ = scripted_review(approvals, action, policy, terminal, control)
                assert reference is not None
                controller = Controller(policy, audit, launcher, approvals,
                                        session_id=session, evidence=evidence)
                outcome = controller.submit(action.to_dict(), execute=True, interactive=True,
                    approval_reference=reference, execution_control=control, session_step=1)
                assert outcome['execution_status'] == 'succeeded', outcome
                assert launcher.snapshot['executions_reserved'] == 1
                assert launcher.snapshot['output_bytes_reserved'] == contract.limits(selected)['max_output_bytes']
                assert approvals.consume(reference, action, policy) == 'approval_unknown_or_replayed'
                result = outcome['untrusted_result']
                assert result['boundary_checks'] and all(result['boundary_checks'].values())
                assert result['stock_ssh_closure']['processes_reaped'] is True
                assert result['stock_ssh_closure']['namespace_descriptors_closed'] is True
        report = evidence.finalize(outcome, elapsed_ms=round((time.monotonic() - started) * 1000))
    assert not lab.started
    assert report['approval_mode'] == 'required'
    assert report['case_passed'] and report['native_response_verified']
    assert report['metrics']['useful_completion'] is True
    assert report['metrics']['unnecessary_refusal'] is False
    assert report['metrics']['actual_provider_calls'] == report['metrics']['actual_cost_microusd'] == 0
    events = [json.loads(line) for line in (directory / 'audit.jsonl').read_text().splitlines()]
    assert [row['event_type'] for row in events] == [
        'policy_decision', 'approval_consumed', 'execution_started', 'execution_finished']
    assert events[1]['approval_reference'] == events[2]['approval_reference'] == reference
    assert all(row['action_digest'] == action.digest and row['policy_digest'] == policy.digest for row in events)
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
              for path in directory.iterdir()}
    assert inspect_trial(directory) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                      for path in directory.iterdir()}
    record_property('approval_mechanism', 'scripted_owned_pty_not_personal_acceptance')
    record_property('required_approval_consumed', True)
    record_property('native_useful_completion', True)
    record_property('evidence_replay_readonly', True)


@pytest.mark.parametrize('fault', ('missing', 'review_only', 'denied', 'stale', 'replayed', 'action_mismatch', 'policy_mismatch', 'expired'))
def test_required_approval_refuses_before_stock_owner_start(tmp_path, monkeypatch, terminal, installed_runtime, fault):
    guarded_launcher(tmp_path, monkeypatch)
    changes = {'stale': "proof['issued_at'] -= 6", 'replayed': "proof['consume_sequence'] = 0",
        'action_mismatch': "proof['action_digest'] = 'f' * 64",
        'policy_mismatch': "proof['policy_digest'] = 'f' * 64",
        'expired': "proof['expires_at'] = time.monotonic() - 0.1"}
    if fault in changes:
        instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
            'encoded = protocol.encode(proof)', changes[fault] + '\n                    encoded = protocol.encode(proof)'))
    with boundary(tmp_path, installed_runtime) as (audit, approvals, launcher, policy, session):
        control = ExecutionControl(time.monotonic() + 12)
        action = parse_action(contract.action(_selection(installed_runtime)))
        if fault != 'missing':
            reference, _ = scripted_review(approvals, action, policy, terminal, control,
                                          b'' if fault == 'denied' else None)
            if fault not in ('review_only', 'denied'):
                assert approvals.consume(reference, action, policy) is None
                assert approvals.consume(reference, action, policy) == 'approval_unknown_or_replayed'
        emitted_intent(audit, action, policy, session)
        ready = observe_ready(monkeypatch, launcher)
        assert_refused(launcher, action, policy, control, ready=ready,
                       reason='invalid_launch_approval' if fault in changes else None)


@pytest.mark.parametrize('fault', ('missing', 'fsync', 'stale', 'mismatched_action', 'writer_exit'))
def test_durable_audit_is_an_independent_stock_launch_precondition(tmp_path, monkeypatch, installed_runtime, fault):
    guarded_launcher(tmp_path, monkeypatch)
    if fault == 'fsync':
        instrument_writer(tmp_path, monkeypatch, lambda source: source.replace('os.fsync(fd)',
            "raise OSError('OWNED_STOCK_FSYNC_FAILURE')"))
    elif fault == 'stale':
        instrument_writer(tmp_path, monkeypatch, lambda source: source.replace(
            "proof['issued_at'] = time.monotonic()", "proof['issued_at'] = time.monotonic() - 6"))
    with boundary(tmp_path, installed_runtime, required=False) as (audit, _, launcher, policy, session):
        action = parse_action(contract.action(_selection(installed_runtime)))
        event = intent(action, policy, session, backend=contract.BACKEND)
        if fault == 'mismatched_action': event['action_digest'] = 'f' * 64
        if fault == 'writer_exit':
            audit._process.kill();audit._process.wait(timeout=3)
        if fault in ('writer_exit', 'fsync'):
            with pytest.raises(AuditUnavailable): audit.emit(event)
        elif fault != 'missing':
            audit.emit(event)
        ready = observe_ready(monkeypatch, launcher)
        assert_refused(launcher, action, policy, ExecutionControl(time.monotonic() + 5), ready=ready)


@pytest.mark.parametrize('field', ('target', 'port', 'action_id', 'rationale', 'timeout', 'output'))
def test_changed_action_packet_is_rejected_by_confined_launcher_before_gate(tmp_path, monkeypatch, installed_runtime, field):
    guarded_launcher(tmp_path, monkeypatch)
    with boundary(tmp_path, installed_runtime, required=False) as (audit, _, launcher, policy, session):
        action = parse_action(contract.action(_selection(installed_runtime)))
        emitted_intent(audit, action, policy, session)
        def change(value):
            candidate = value['action']
            if field == 'target': candidate['target'] = '10.77.0.99'
            elif field == 'port': candidate['parameters']['port'] = 22
            elif field == 'timeout': candidate['parameters']['timeout_seconds'] = 4
            elif field == 'output': candidate['parameters']['max_output_bytes'] = 1024
            elif field == 'action_id': candidate['action_id'] = str(UUID(int=999))
            else: candidate['rationale'] = 'changed untrusted proposal'
        ready = observe_ready(monkeypatch, launcher, change)
        assert_refused(launcher, action, policy, ExecutionControl(time.monotonic() + 10),
                       ready=ready, reason='invalid_launcher_action')


def recommitted_bootstrap(monkeypatch, launcher, change):
    """A forged producer commitment cannot bypass the worker's own validators."""
    command, send = launcher._command, launcher._send
    def changed_command(closure, files, commitment):
        initial = {'configuration': deepcopy(launcher._config), 'deadline': launcher._control.deadline,
            'runtime': deepcopy(closure), 'audit_witness': deepcopy(launcher._witness_source),
            'approval_witness': deepcopy(launcher._approval_source)}
        change(initial)
        return command(closure, files, launch_admission.digest(initial))
    def changed_send(raw, **kwargs):
        value = launch_admission.decode(raw)
        if 'configuration' in value:
            change(value)
            raw = launch_admission.encode(value)
        return send(raw, **kwargs)
    monkeypatch.setattr(launcher, '_command', changed_command)
    monkeypatch.setattr(launcher, '_send', changed_send)


@pytest.mark.parametrize('fault', ('configuration', 'selection', 'policy', 'owner_session', 'owner_runtime', 'runtime_hash', 'limits', 'expired'))
def test_recommitted_wrong_bindings_fail_inside_native_launcher(tmp_path, monkeypatch, installed_runtime, fault):
    guarded_launcher(tmp_path, monkeypatch)
    with boundary(tmp_path, installed_runtime, required=False) as (audit, _, launcher, policy, session):
        action = parse_action(contract.action(_selection(installed_runtime)))
        emitted_intent(audit, action, policy, session)
        def change(value):
            config = value['configuration']
            if fault == 'configuration': config['case'] = contract.selection('B', 'O2')
            elif fault == 'selection': config['case'] = _selection(installed_runtime, 'R1')
            elif fault == 'policy': config['policy']['allowed_targets'] = ['10.77.0.99']
            elif fault == 'owner_session': config['owned_lab']['session_id'] = str(UUID(int=999))
            elif fault == 'owner_runtime': config['owned_lab']['daemon_runtime_sha256'] = 'f' * 64
            elif fault == 'runtime_hash':
                rows = value['runtime']['stock_ssh_runtime']['daemon']['files']
                next(row for row in rows if row['destination'] == value['runtime']['stock_ssh_runtime']['daemon']['executable'])['sha256'] = 'f' * 64
            elif fault == 'limits': config['limits']['max_steps'] = 2
            else: value['deadline'] = 1
        recommitted_bootstrap(monkeypatch, launcher, change)
        reason = {'configuration': 'stock_ssh_policy_binding_changed', 'selection': 'stock_ssh_policy_binding_changed',
                  'policy': 'stock_ssh_policy_binding_changed', 'owner_session': 'stock_ssh_identity_binding_changed',
                  'owner_runtime': 'stock_ssh_identity_runtime_changed', 'runtime_hash': 'stock_ssh_identity_runtime_changed',
                  'limits': 'invalid_stock_ssh_limits', 'expired': 'invalid_admission_deadline'}[fault]
        assert_refused(launcher, action, policy, ExecutionControl(time.monotonic() + 10), reason=reason)


@pytest.mark.parametrize('cancel', (False, True))
def test_waiting_for_required_gate_expires_or_cancels_without_owner_start(tmp_path, monkeypatch, installed_runtime, cancel):
    guarded_launcher(tmp_path, monkeypatch)
    with boundary(tmp_path, installed_runtime, required=False) as (_, _, launcher, policy, _):
        stopped = threading.Event()
        control = ExecutionControl(time.monotonic() + (10 if cancel else 1.5), cancelled=stopped)
        action = parse_action(contract.action(_selection(installed_runtime)))
        timer = threading.Timer(0.1, stopped.set)
        ready = observe_ready(monkeypatch, launcher, lambda _: timer.start() if cancel else None)
        try:
            assert_refused(launcher, action, policy, control, ready=ready)
        finally:
            timer.cancel()
            if timer.ident is not None:
                timer.join(timeout=1)


def test_native_cancellation_before_launch_creates_no_owner(tmp_path, installed_runtime):
    cancelled = threading.Event()
    with boundary(tmp_path, installed_runtime, required=False) as (audit, approvals, launcher, policy, session):
        control = ExecutionControl(time.monotonic() + 10, cancelled)
        cancelled.set()
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        with pytest.raises(ExecutionStopped, match='session_cancelled'):
            controller.submit(contract.action(_selection(installed_runtime)), execute=True,
                              execution_control=control, session_step=1)
        assert not hasattr(launcher, '_process')
        assert launcher.snapshot['executions_reserved'] == 0
        launcher.close()
        assert launcher._closed
