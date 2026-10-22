"""Portable host orchestration checks; no fixture grants native authority."""

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import engagement_live_session as module
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent.engagement_live_approval import _clipped_control
from recon_cockpit.secure_agent.execution import ExecutionControl
from test_secure_engagement_live_contract import opened, prepared, clock, uid, M

ROOT = Path(__file__).resolve().parents[1]


def cli():
    spec = importlib.util.spec_from_file_location('engagement_live_cli_test', ROOT/'scripts/engagement_live.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def service():
    obj = module.EngagementSession.__new__(module.EngagementSession)
    obj._pid = os.getpid()
    obj._control = ExecutionControl(time.monotonic()+60, threading.Event())
    obj._stop, obj._closing = threading.Event(), threading.Event()
    obj._close_lock, obj._state_lock = threading.Lock(), threading.Lock()
    obj._slot_locks = (threading.Lock(), threading.Lock())
    obj._closed = False
    obj._cleanup = obj._failure = obj._broker = obj._audit = obj._bundle = None
    obj._sessions = {}
    obj._operations = {}
    obj._roles = []
    obj._readiness = []
    obj._cleanup_receipts = []
    obj._startup_observations = []
    obj._used_slots = set()
    obj._monitor_thread = None
    obj._observer_rows = []
    selected, value = opened(), prepared()
    row = {'opened': selected, 'ingress': 0, 'stopped': False,
           'reviewer': None, 'endpoint': None, 'launcher': None}
    obj._sessions[selected['binding']['session_id']] = row
    obj._operations[value['envelope']['dispatch_id']] = {'session': selected, 'prepared': value,
        'result': None, 'client': None, 'meter': None,
        'elapsed_ms': dict.fromkeys(('review','admission','native','parser','cleanup','action'))}
    return obj, row, value


def test_default_cli_is_inert_without_execute(tmp_path):
    store, audit, output = (tmp_path/name for name in ('store','audit','evidence'))
    result = subprocess.run([sys.executable, str(ROOT/'scripts/engagement_live.py'),
        '--store-directory', str(store), '--audit-path', str(audit), '--output-directory', str(output)],
        capture_output=True, timeout=3)
    assert result.returncode == 0 and result.stderr == b''
    assert json.loads(result.stdout) == {'schema_version':'1', 'profile':cli().PROFILE,
                                         'execute':False, 'description':cli().DESCRIPTION}
    assert not any(path.exists() for path in (store,audit,output))


def test_rejects_unknown_duplicated_or_expanded_options():
    value = cli()
    for args in (['--execute','--execute'], ['--review-mode=terminal'], ['--unknown'],
                 ['--review-mode','automatic'], ['--store-directory','a\n'], ['--execute'],
                 ['--output-directory'], ['--help','--help']):
        with pytest.raises(ValueError, match='invalid_input'):
            value.parse_options(args)


def test_owned_scope_and_runtime_are_broker_bound():
    obj, row, value = service()
    assert obj._prepared(value)[0] == value
    for field, change in (('scope_sha256','e'*64), ('runtime_sha256','f'*64),
                          ('broker_id',uid(90)), ('ledger_owner_id',uid(91))):
        modified = deepcopy(value)
        modified['envelope'][field] = change
        with pytest.raises(c.LiveError):
            obj._prepared(modified)


def test_session_original_control_cannot_be_replaced():
    obj, row, value = service()
    replacement = ExecutionControl(obj._control.deadline+60, obj._control.cancelled)
    for method in (lambda:obj.review(value,control=replacement),
                   lambda:obj.execute(value,'a'*48,control=replacement)):
        with pytest.raises(c.LiveError, match='invalid_input'):
            method()
    obj._control.cancelled.set()
    with pytest.raises(Exception, match='session_cancelled'):
        obj._check(obj._control)


def test_prepare_echo_cannot_change_revision_or_scope():
    obj, row, value = service()
    obj._operations.clear()
    reached = []
    row['launcher'] = SimpleNamespace(prepare=lambda *a:reached.append(True))
    for field, change in (('revision',2),('scope_sha256','f'*64)):
        modified = deepcopy(value)
        modified['envelope'][field] = change
        obj._broker = SimpleNamespace(prepare=lambda *a, **kw:{'prepared':modified,'preparation':None})
        with pytest.raises(c.LiveError):
            obj.prepare(value['envelope']['session_id'],'http_identify')
    assert not reached and not obj._operations
    obj._broker = SimpleNamespace(prepare=lambda *a,**kw:{'prepared':value,'preparation':None})
    def partial_setup(*a):
        raise c.LiveError('engagement_live_unavailable')
    row['launcher'].prepare = partial_setup
    with pytest.raises(c.LiveError,match='unavailable'):
        obj.prepare(value['envelope']['session_id'],'http_identify')
    assert obj._operations[value['envelope']['dispatch_id']]['result'] is None


def test_execute_requires_actual_review_reference():
    obj, row, value = service()
    attempted = []
    row['reviewer'] = SimpleNamespace(consume=lambda *a, **kw: attempted.append(a) or {'accepted':False})
    for reference in (True, None, {'approved':True}):
        with pytest.raises(c.LiveError, match='approval_unknown_or_replayed'):
            obj.execute(value,reference,control=obj._control)
    assert not attempted
    with pytest.raises(c.LiveError, match='approval_unknown_or_replayed'):
        obj.execute(value,'a'*48,control=obj._control)
    assert len(attempted) == 1


def test_startup_failure_closes_every_created_role(monkeypatch):
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    from recon_cockpit.secure_agent import engagement_live_broker as broker
    from recon_cockpit.secure_agent import engagement_live_audit as audit
    calls = []
    now = time.monotonic_ns()
    receipt = {'schema_version':'1','started_at_ns':now,'finished_at_ns':now,
               'deadline_ns':now+2000000000,'status':'complete','processes':[], 'descriptors_closed':True}
    class Broker:
        def __init__(self, **kw):pass
        def start(self):return {'readiness':{'portable_observation':True}}
        def _interrupt(self):calls.append('broker_interrupt')
        def _close(self, deadline):calls.append(('broker_close',deadline));return receipt
    class Audit:
        def __init__(self, *a, **kw):pass
        def start(self):raise c.LiveError('engagement_live_audit_unavailable')
        def _interrupt(self):calls.append('audit_interrupt')
        def _close(self, deadline):calls.append(('audit_close',deadline));return receipt
    monkeypatch.setattr(runtime,'inspect_runtime',lambda control:{'pure_fixture':True})
    monkeypatch.setattr(broker,'preallocate_role_bundle',lambda mode:SimpleNamespace(close=lambda:calls.append('bundle_close')))
    monkeypatch.setattr(broker,'EngagementBroker',Broker)
    monkeypatch.setattr(audit,'EngagementAuditService',Audit)
    with pytest.raises(c.LiveError, match='audit_unavailable') as caught:
        module.EngagementSession.start('unused','unused',review_mode='terminal',
                                      control=ExecutionControl(time.monotonic()+60))
    deadlines = [v[1] for v in calls if type(v)is tuple]
    assert len(deadlines)==2 and len(set(deadlines))==1
    assert calls.index('audit_interrupt') < next(i for i,v in enumerate(calls) if type(v)is tuple)
    assert caught.value.engagement_session._closed


def test_cancel_and_eof_do_not_start_followup():
    obj, row, value = service()
    events = []
    row['reviewer'] = SimpleNamespace(_interrupt=lambda:events.append('review_interrupted'))
    obj._broker = SimpleNamespace(cancel=lambda sid:events.append('broker_cancel'))
    obj.cancel(value['envelope']['session_id'])
    assert events == ['review_interrupted','broker_cancel']
    with pytest.raises(c.LiveError, match='session_unavailable'):
        obj.review(value,control=obj._control)
    obj._stop.set()
    with pytest.raises(c.LiveError, match='session_unavailable'):
        obj.prepare(value['envelope']['session_id'],'http_headers')


def test_lease_narrowing_never_renews_original_deadline():
    obj, row, value = service()
    original = obj._control
    tighter = _clipped_control(original,int((original.deadline-3)*c.SECOND),obj._stop)
    assert tighter.original is original and tighter.deadline <= original.deadline-3
    assert tighter.cancelled is original.cancelled and tighter.clock is original.clock
    attempted_renewal = _clipped_control(original,int((original.deadline+100)*c.SECOND),obj._stop)
    assert attempted_renewal.deadline == original.deadline
    obj._stop.set()
    with pytest.raises(c.LiveError, match='cancelled'):
        tighter.check()


def test_uncertain_dispatch_is_never_retried():
    obj, row, value = service()
    events = []
    row['reviewer'] = SimpleNamespace(consume=lambda *a, **kw:
        {'accepted':True,'reference_sha256':'a'*64,'consume_sequence':1,'witness_sha256':'b'*64})
    obj._audit = SimpleNamespace(emit=lambda *a, **kw:events.append('audit') or {'sequence':1})
    def dispatch(*a, **kw):
        events.append('dispatch')
        raise c.LiveError('engagement_live_unavailable')
    obj._broker = SimpleNamespace(_dispatch_with_control=dispatch)
    with pytest.raises(c.LiveError, match='unavailable'):
        obj.execute(value,'a'*48,control=obj._control)
    assert events == ['audit','dispatch']
    assert obj._operations[value['envelope']['dispatch_id']]['result'] is None


def test_recovery_opens_fresh_owner_without_replenishing(tmp_path):
    from test_secure_engagement_dispatch_store import new_store
    obj, row, value = service()
    created = new_store(tmp_path)
    before = created.snapshot()
    old_owner = created.owner_reference
    obj._store_directory = created.directory
    created.close()
    with pytest.raises(c.LiveError, match='cleanup_incomplete'):
        obj._recover_ledger()
    obj._closed = True
    obj._cleanup = {'status':'failed'}
    receipt={'status':'failed','descriptors_closed':True,'processes':[{
        'pid':123,'start_time_ticks':456,'wrapper_pid':122,'wrapper_returncode':0,
        'exit_observed':True,'reaped_observed':False}]}
    obj._cleanup_receipts=[receipt]
    with pytest.raises(c.LiveError,match='cleanup_incomplete'):
        obj._recover_ledger()
    receipt['processes'][0]['reaped_observed']=True
    raw, proof = obj._recover_ledger()
    assert json.loads(raw) == before and proof['owner_id'] != old_owner
    assert proof['read_only'] and proof['closed']
    assert proof['ledger_state_sha256'] == before['events'][-1]['receipt']['state_sha256']
    assert proof['finished_at_ns']-proof['started_at_ns'] <= 2000000000


def test_cli_output_is_bounded_and_never_reports_late_success(monkeypatch):
    value = cli()
    with pytest.raises(ValueError, match='limit_exceeded'):
        value._output(b'x'*8193,time.monotonic()+1)
    monkeypatch.setattr(value,'parse_options',lambda args:{'help':False,'execute':True})
    monkeypatch.setattr(value,'_run',lambda options, deadline:{'status':'complete'})
    written = []
    def expired_output(raw,deadline):
        written.append(raw)
        raise ValueError('engagement_live_timeout')
    monkeypatch.setattr(value,'_output',expired_output)
    assert value.main([]) == 2
    assert json.loads(written[-1])['error'] == 'engagement_live_timeout'
    written.clear()
    def partial_output(raw,deadline):
        written.append(raw[:5])
        error = ValueError('engagement_live_timeout')
        error.output_started = True
        raise error
    monkeypatch.setattr(value,'_output',partial_output)
    assert value.main([]) == 2 and len(written) == 1
