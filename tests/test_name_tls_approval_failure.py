"""Portable checks of closed-owner evidence; synthetic rows are not grants."""

import base64
from copy import deepcopy
import os
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import approval_protocol as protocol
from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_evidence as evidence
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.routed import _Supervisor
from name_tls_approval_failure import drain_natural_exit
from test_name_tls_authority import Harness
from test_name_tls_evidence import n15_process


def approval_rows(*, pending=True):
    h = Harness(case='N15')
    h.dns()
    dns = contract.dns_action(h.selected, h.identity)
    service = contract.service_action(h.selected, h.identity, 'http', h.ledger.snapshot()['binding'])
    policy = contract.policy_for_selection(h.selected)
    broker = str(UUID(int=9001))
    chosen = {'selection': h.selected, 'session_id': h.identity['session_id'], 'policy': policy.to_dict()}
    initial = {'version': '1', 'broker_id': broker, 'session_id': chosen['session_id'],
               'policy': chosen['policy'], 'deadline': 60., 'terminal': [1, 2, 3], 'witness': [1, 4]}
    checks = dict.fromkeys(protocol.CHECKS, True)
    messages = [{'request': initial, 'reply': {'version': '1', 'bootstrap_digest': protocol.digest(initial),
                                             'ready': True, 'checks': checks}}]
    reviews = []
    for index, raw in enumerate((dns, service)):
        action = parse_action(raw)
        canonical = deepcopy(raw)
        canonical.pop('rationale')
        details = {'review_exact_action': canonical, 'action_digest': action.digest, 'policy_digest': policy.digest,
                   'policy_version': policy.policy_version, 'session_id': chosen['session_id'],
                   'name_binding_summary': contract.public.approval_summary(action.tool_id, canonical['parameters'])}
        prompt = protocol.encode(details) + b'\n' + ("Type 'approve " + action.digest[:16] + ' ' + 'a' * 32
                 + "' to approve once (blank denies): ").encode('ascii')
        reference = str(index + 1) * 48
        reviews.append({'reference': reference, 'prompt_base64': base64.b64encode(prompt).decode('ascii')})
        for offset, operation in enumerate(('review', 'consume'), 1):
            request = {'version': '1', 'broker_id': broker, 'session_id': chosen['session_id'],
                       'sequence': index * 2 + offset, 'operation': operation, 'action': raw, 'policy_digest': policy.digest}
            if operation == 'consume':
                request['reference'] = reference
            if index == 1 and operation == 'consume' and pending:
                pending_request = request
                continue
            messages.append({'request': request, 'reply': protocol.receipt(request, reference if operation == 'review' else None)})
    owner = {'manifest': chosen, 'approval_worker': {'broker_id': broker, 'pid': 1500, 'start_time_ticks': 9000, 'checks': checks},
             'approval_messages': messages, 'dns_review': reviews[0], 'service_review': reviews[1]}
    failure = {'stage': 'approval_consume_after_owner_close', 'exception_type': 'ApprovalUnavailable',
               'exception_code': 'approval_unavailable', 'pending_request': pending_request if pending else messages[-1]['request'],
               'reply': None, 'worker_stdout_base64': '',
               'worker_stderr_base64': base64.b64encode(b'approval_worker_refused\n').decode('ascii'),
               'supervised_pid': 1500, 'supervised_returncode': 78, 'capture_source': 'existing_supervisor_pipes',
               'capture_limit_bytes': 4096, 'capture_complete': True,
               'process_before': n15_process(3), 'process_after': n15_process(3, alive=False)}
    host = {name: name + ':[100]' for name in ('user', 'net', 'mnt', 'pid')}
    failure['process_binding'] = {'bootstrap_sha256': protocol.digest(initial),
        'argv': ['/usr/bin/python3', '-I', '-S', '/app/approval_runtime/approval_worker.py',
                 protocol.digest(initial), *(host[name] for name in ('user', 'net', 'mnt', 'pid')), 'launch-witness'],
        'host_namespaces': host, 'observer_pid': 500,
        'ancestry': [{'pid': 1203, 'parent_pid': 1400, 'start_time_ticks': 10003},
                     {'pid': 1400, 'parent_pid': 1500, 'start_time_ticks': 9500},
                     {'pid': 1500, 'parent_pid': 500, 'start_time_ticks': 9000}]}
    return owner, dns, service, failure


def test_closed_owner_requires_real_review_but_no_acknowledged_service_consume():
    owner, dns, service, failure = approval_rows()
    evidence._validate_n15_approvals(owner, dns, service, need_service=True, pending_service_consume=True)
    evidence._validate_n15_approval_failure(failure, owner, service, n15_process())
    owner['approval_messages'].append({'request': failure['pending_request'],
        'reply': protocol.receipt(failure['pending_request'], None)})
    with pytest.raises(ValueError, match='approval_transcript'):
        evidence._validate_n15_approvals(owner, dns, service, need_service=True, pending_service_consume=True)


def test_live_foreign_donor_still_requires_successful_real_service_consume_receipt():
    owner, dns, service, _ = approval_rows(pending=False)
    evidence._validate_n15_approvals(owner, dns, service, need_service=True)
    request = owner['approval_messages'][-1]['request']
    owner['approval_messages'][-1]['reply'] = protocol.receipt(request, 'approval_unknown_or_replayed')
    with pytest.raises(ValueError, match='real_grant_changed'):
        evidence._validate_n15_approvals(owner, dns, service, need_service=True)


@pytest.mark.parametrize('change', ('ready', 'checks', 'request_type'))
def test_approval_failure_receipts_reject_boolean_integer_confusion_and_nonobject_request(change):
    owner, dns, service, failure = approval_rows()
    if change == 'request_type':
        failure['pending_request'] = None
        with pytest.raises(ValueError):
            evidence._validate_n15_approval_failure(failure, owner, service, n15_process())
    else:
        if change == 'ready':
            owner['approval_messages'][0]['reply']['ready'] = 1
        else:
            owner['approval_worker']['checks']['namespaces_private'] = 1
        with pytest.raises(ValueError):
            evidence._validate_n15_approvals(owner, dns, service, need_service=True, pending_service_consume=True)


@pytest.mark.parametrize('changed', ('stage', 'exception', 'reply', 'stdout', 'stderr', 'duplicate_stderr',
    'exit_signal', 'exit_bool', 'incomplete', 'capture_bound', 'capture_bound_bool', 'supervised_pid',
    'sequence', 'reference', 'action', 'policy', 'broker', 'operation', 'process_alive', 'process_reused',
    'process_namespace', 'process_is_owner', 'process_is_wrapper', 'missing', 'extra'))
def test_failed_consume_evidence_cannot_be_substituted_or_promoted(changed):
    owner, _, service, failure = approval_rows()
    failure = deepcopy(failure)
    if changed == 'stage':
        failure['stage'] = 'observed_epipe'
    elif changed == 'exception':
        failure['exception_code'] = 'approval_expired'
    elif changed == 'reply':
        failure['reply'] = protocol.receipt(failure['pending_request'], None)
    elif changed in ('stdout', 'stderr', 'duplicate_stderr'):
        key = 'worker_stdout_base64' if changed == 'stdout' else 'worker_stderr_base64'
        raw = b'approval_worker_refused\n' * 2 if changed == 'duplicate_stderr' else b'other\n'
        failure[key] = base64.b64encode(raw).decode('ascii')
    elif changed in ('exit_signal', 'exit_bool'):
        failure['supervised_returncode'] = -9 if changed == 'exit_signal' else True
    elif changed == 'incomplete':
        failure['capture_complete'] = False
    elif changed in ('capture_bound', 'capture_bound_bool'):
        failure['capture_limit_bytes'] = 8192 if changed == 'capture_bound' else True
    elif changed == 'supervised_pid':
        failure['supervised_pid'] += 1
    elif changed in ('sequence', 'reference', 'policy', 'broker', 'operation'):
        field = {'policy': 'policy_digest', 'broker': 'broker_id'}.get(changed, changed)
        failure['pending_request'][field] = {'sequence': 5, 'reference': 'a' * 48, 'policy': 'f' * 64,
            'broker': str(UUID(int=9002)), 'operation': 'review'}[changed]
    elif changed == 'action':
        failure['pending_request']['action']['rationale'] += ' changed'
    elif changed == 'process_alive':
        failure['process_after'] = deepcopy(failure['process_before'])
    elif changed == 'process_reused':
        failure['process_after']['start_time_ticks'] += 1
    elif changed == 'process_namespace':
        failure['process_after']['namespaces']['net'] = 'net:[999]'
    elif changed == 'process_is_owner':
        failure['process_before'], failure['process_after'] = n15_process(), n15_process(alive=False)
    elif changed == 'process_is_wrapper':
        failure['process_before']['pid'] = failure['process_after']['pid'] = 1500
    elif changed == 'missing':
        failure.pop('reply')
    else:
        failure['grant_burned'] = True
    with pytest.raises((ValueError, KeyError)):
        evidence._validate_n15_approval_failure(failure, owner, service, n15_process())


@pytest.mark.parametrize('changed', ('bootstrap', 'argv_commitment', 'argv_isolation', 'argv_witness',
    'host_namespace', 'coherent_payload', 'first_pid', 'first_start', 'last_pid', 'last_start',
    'parent_link', 'cycle', 'start_order', 'bool_pid', 'bool_start', 'empty', 'too_long', 'observer', 'extra'))
def test_approval_process_pin_requires_its_recorded_broker_and_supervised_ancestry(changed):
    owner, _, service, failure = approval_rows()
    failure = deepcopy(failure)
    binding = failure['process_binding']
    rows = binding['ancestry']
    if changed == 'bootstrap':
        binding['bootstrap_sha256'] = 'f' * 64
    elif changed == 'argv_commitment':
        binding['argv'][4] = 'f' * 64
    elif changed == 'argv_isolation':
        binding['argv'].remove('-I')
    elif changed == 'argv_witness':
        binding['argv'].pop()
    elif changed == 'host_namespace':
        binding['host_namespaces']['net'] = failure['process_before']['namespaces']['net']
        binding['argv'][6] = binding['host_namespaces']['net']
    elif changed == 'coherent_payload':
        for field in ('process_before', 'process_after'):
            failure[field]['pid'] += 30
            failure[field]['start_time_ticks'] += 30
            failure[field]['namespaces'] = {name: name + ':[999]' for name in ('user', 'net', 'mnt', 'pid')}
    elif changed == 'first_pid':
        rows[0]['pid'] += 1
    elif changed == 'first_start':
        rows[0]['start_time_ticks'] += 1
    elif changed == 'last_pid':
        rows[-1]['pid'] += 1
        rows[-2]['parent_pid'] = rows[-1]['pid']
    elif changed == 'last_start':
        rows[-1]['start_time_ticks'] -= 1
    elif changed == 'parent_link':
        rows[0]['parent_pid'] += 1
    elif changed == 'cycle':
        rows[1]['pid'] = rows[0]['parent_pid'] = rows[0]['pid']
    elif changed == 'start_order':
        rows[1]['start_time_ticks'] = rows[0]['start_time_ticks'] + 1
    elif changed in ('bool_pid', 'bool_start'):
        rows[0]['pid' if changed == 'bool_pid' else 'start_time_ticks'] = True
    elif changed == 'empty':
        binding['ancestry'] = []
    elif changed == 'too_long':
        binding['ancestry'] = rows * 6
    elif changed == 'observer':
        binding['observer_pid'] += 1
    else:
        binding['not_a_trace'] = True
    with pytest.raises(ValueError):
        evidence._validate_n15_approval_failure(failure, owner, service, n15_process())


@pytest.mark.parametrize('mode', ('natural', 'wrong_exit', 'too_much_output', 'deadline', 'aggregate_limit'))
def test_failure_capture_requires_bounded_natural_exit_before_cleanup(mode):
    control = ExecutionControl(time.monotonic() + (.05 if mode == 'deadline' else 2))
    supervisor = _Supervisor(2, 8 if mode == 'aggregate_limit' else 65536, control=control)
    program = "import os; os.write(2,b'approval_worker_refused\\n'); raise SystemExit(78)"
    if mode == 'wrong_exit':
        program = 'raise SystemExit(0)'
    elif mode == 'too_much_output':
        program = "import os; os.write(2,b'x'*5000); raise SystemExit(78)"
    elif mode == 'deadline':
        program = 'import time; time.sleep(1)'
    process = supervisor.launch('worker', [sys.executable, '-I', '-S', '-c', program])
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    approvals = SimpleNamespace(_supervisor=supervisor, _process=process, _control=control)
    try:
        if mode == 'natural':
            captured = drain_natural_exit(approvals)
            assert captured['supervised_returncode'] == process.poll() == 78
            assert captured['worker_stdout_base64'] == ''
            assert base64.b64decode(captured['worker_stderr_base64']) == b'approval_worker_refused\n'
            assert supervisor.total == len(b'approval_worker_refused\n')
        else:
            with pytest.raises(AssertionError):
                drain_natural_exit(approvals)
    finally:
        supervisor.close()
