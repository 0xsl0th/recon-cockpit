"""Native T04 production evidence and synthetic authority gates; no personal approval claim."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import action, BACKEND, BOUNDARY_FIELDS as BASE_BOUNDARY_FIELDS
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.network_tools_runtime import inspect_tool_runtime
from recon_cockpit.secure_agent.network_tools_web_hierarchy_spec import (
    CASES, TOOL_ID, LIMITS, BOUNDARY_FIELDS, MAX_OWNER_BYTES, OWNER_REPRESENTATION, case_parts,
)
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import descendants, instrument
from test_secure_nmap_cli import GATES
from test_secure_owned_launcher_linux import assert_reaped
from test_secure_network_tools_robustness_linux import _FixedProposal

pytestmark = pytest.mark.integration
POLICY = Path('examples/secure-agent-web-hierarchy-policy.json')


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned native trials')
    assert sys.platform=='linux' and os.geteuid()!=0
    monkeypatch.setattr(NetworkToolsLab,'start',lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend,'run',lambda *a,**k: pytest.fail('host tool executed'))
    original_run = LinuxFixtureLauncher.run
    def diagnosed_run(launcher, *args, **kwargs):
        try:
            return original_run(launcher, *args, **kwargs)
        except Exception as exc:
            supervisor = getattr(launcher, '_supervisor', None)
            details = b'' if supervisor is None else bytes(supervisor.buffers['worker_err'])
            print(type(exc).__name__, str(exc), details.decode('ascii', 'backslashreplace'), file=sys.stderr)
            raise
    monkeypatch.setattr(LinuxFixtureLauncher, 'run', diagnosed_run)


@contextmanager
def boundary(tmp_path,control,*,case='web-hierarchy-nested',approval_required=True):
    definition=json.loads(POLICY.read_text())
    definition.update(require_approval=approval_required,policy_version='synthetic-web-hierarchy-test-v1')
    policy,session=parse_policy(definition),str(uuid4())
    limits=SessionLimits(**LIMITS)
    backend=AuthorizedNetworkToolsBackend(policy,session,limits,NetworkToolsLab(case,session,limits),execute=True)
    backend._network_tools_manifest=inspect_tool_runtime(TOOL_ID,control)
    with LinuxAuditSink(tmp_path/'audit.jsonl',launch_witness=True) as audit, LinuxApprovalService(policy,session,launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend,audit=audit,approvals=approvals) as launcher:
            yield audit,approvals,launcher,policy,session


@pytest.mark.parametrize('case',CASES)
def test_native_secure_hierarchy_and_both_inspectors(tmp_path,capsys,record_property,case):
    variant=case_parts(case)
    useful=variant in {'nested','empty','hostile'}
    policy=json.loads(POLICY.read_text())
    policy.update(require_approval=False,policy_version='synthetic-unattended-web-hierarchy-v1')
    policy_path=tmp_path/'policy.json';policy_path.write_text(json.dumps(policy))
    evidence,audit=tmp_path/'evidence',tmp_path/'audit.jsonl'
    started=time.monotonic()
    code=cli.main(['--network-tool-assessment',case,'--assessment-dir',str(evidence),
        '--audit',str(audit),'--policy',str(policy_path),*GATES,'--execute'])
    captured=capsys.readouterr()
    summary=json.loads(captured.out)
    assert code in (0,2),(summary,captured.err)
    assert summary['steps_attempted']==1 and summary['output_reserved_bytes']==8192
    assert summary['actions_succeeded']==int(variant!='stalled'),(summary,captured.err)
    assert summary['actual_provider_calls']==0 and summary['live_calls_enabled'] is False
    elapsed=time.monotonic()-started
    assert elapsed<60
    report=json.loads((evidence/'report.json').read_text())
    assert report['integrity_issues']==[],(report,captured.err)
    assert report['metrics']['useful_actions_completed']==int(useful)
    assert report['metrics']['actual_cost_microusd']==report['metrics']['actual_provider_calls']==0
    closure=report['owned_lab']['closure']
    assert closure['status']=='closed'
    row=report['records'][0]
    result=json.loads((evidence/row['artifact']['filename']).read_bytes())
    assert set(result['boundary_checks'])==BASE_BOUNDARY_FIELDS|BOUNDARY_FIELDS
    assert all(v is True for v in result['boundary_checks'].values())
    stdout=base64.b64decode(result['raw_output_base64'],validate=True)
    stderr=base64.b64decode(result['raw_stderr_base64'],validate=True)
    assert result['bytes_received']==len(stdout)+len(stderr)<=8192
    artifact=result['web_hierarchy_owner']
    assert artifact['filename']=='web-hierarchy-owner-'+row['execution_id']+'.json'
    assert artifact['representation']==OWNER_REPRESENTATION
    owner_path=evidence/artifact['filename'];owner_raw=owner_path.read_bytes()
    assert owner_path.stat().st_mode&0o777==0o600
    assert len(owner_raw)==artifact['bytes']<=MAX_OWNER_BYTES
    assert hashlib.sha256(owner_raw).hexdigest()==artifact['sha256']==result['owned_lab']['web_hierarchy_owner_sha256']
    owner=json.loads(owner_raw)
    assert owner['request_count']==closure['request_count']
    assert owner['connection_count']==closure['connection_count']
    assert owner['diagnostic']['max_active_requests']==1
    if variant!='stalled':
        assert owner['diagnostic']['errors']==[]
        assert owner['request_count']==12
        assert len(owner['diagnostic']['ledger'])==12
        details=row['observation']['details']
        assert details['useful_task_completed'] is useful
        assert details['owner_sha256']==artifact['sha256']
        assert details['outcome']==('empty' if variant=='empty' else 'observed_responses' if useful else 'ambiguous')
    else:
        # The pinned native ffuf client may retry timed-out paths. Retain
        # those attempts honestly; partial or duplicate evidence is never useful.
        assert 1<=owner['request_count']<=16
        assert set(owner['diagnostic']['errors']) <= {'duplicate_path'}
        assert all(not item['completed'] for item in owner['diagnostic']['ledger'])
        assert result['tool_observation'] is None
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment',str(evidence)])==0
    assert json.loads(capsys.readouterr().out)==report
    assert inspect_saved_assessment(evidence)==report
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_mode) for p in evidence.iterdir()}
    events=[json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(e['event_type']=='execution_started' for e in events)==1
    assert sum(e['event_type']=='execution_finished' for e in events)==1
    record_property('trial_kind','ordinary' if variant in {'nested','empty'} else 'robustness')
    record_property('useful_completion',int(useful))
    record_property('unnecessary_refusals',0 if variant in {'nested','empty'} else 'not_applicable')
    record_property('end_to_end_elapsed_ms',round(elapsed*1000))
    record_property('requests',owner['request_count'])
    record_property('client_bytes',len(stdout)+len(stderr))
    record_property('actual_provider_calls',0)
    record_property('actual_cost_microusd',0)


def test_fresh_synthetic_approval_consumed_once(tmp_path,terminal):
    control=ExecutionControl(time.monotonic()+45)
    selected=parse_action(action('web-hierarchy-nested'))
    with boundary(tmp_path,control) as (audit,approvals,launcher,policy,session):
        reference,prompt=scripted_review(approvals,selected,policy,terminal,control)
        assert reference is not None and selected.digest.encode() in prompt
        controller=Controller(policy,audit,launcher,approvals,session_id=session)
        result=controller.submit(selected.to_dict(),execute=True,interactive=True,approval_reference=reference,execution_control=control)
        assert result['execution_status']=='succeeded',result
        assert result['untrusted_result']['tool_observation']['useful_task_completed'] is True
        replay=controller.submit(selected.to_dict(),execute=True,interactive=True,approval_reference=reference,execution_control=control)
        assert replay['execution_status']=='blocked' and replay['reasons']==['approval_unknown_or_replayed']
        assert dict(launcher.snapshot)=={'executions_reserved':1,'output_bytes_reserved':8192}
        assert launcher.close()['request_count']==12


@pytest.mark.parametrize('missing',['audit','consumed_approval'])
def test_missing_launch_preconditions_block_before_admission(tmp_path,monkeypatch,missing):
    instrument(tmp_path,monkeypatch,lambda source:source.replace('granted = gate.admit(',"os.write(2, b'UNEXPECTED-HIERARCHY-ADMISSION')\n                granted = gate.admit("))
    control=ExecutionControl(time.monotonic()+30)
    selected=parse_action(action('web-hierarchy-nested'))
    with boundary(tmp_path,control) as (audit,approvals,launcher,policy,session):
        if missing=='consumed_approval':
            event=intent(selected,policy,session,backend=BACKEND);event['approval_reference']='a'*48;audit.emit(event)
        with pytest.raises((IsolationUnavailable,ExecutionStopped)):
            launcher.run(selected,policy,control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot)=={'executions_reserved':0,'output_bytes_reserved':0}
        assert b'UNEXPECTED-HIERARCHY-ADMISSION' not in bytes(launcher._supervisor.buffers['worker_err'])
        assert launcher.close()['request_count']==0


def test_denial_and_changed_action_cannot_launch(tmp_path,terminal):
    control=ExecutionControl(time.monotonic()+45)
    selected=parse_action(action('web-hierarchy-nested'))
    with boundary(tmp_path,control) as (audit,approvals,launcher,policy,session):
        reference,_=scripted_review(approvals,selected,policy,terminal,control,answer=b'')
        assert reference is None
        controller=Controller(policy,audit,launcher,approvals,session_id=session)
        denied=controller.submit(selected.to_dict(),execute=True,interactive=False,execution_control=control)
        assert denied['execution_status']=='blocked'
        reference,_=scripted_review(approvals,selected,policy,terminal,control)
        changed={**selected.to_dict(),'rationale':'changed after exact review'}
        denied=controller.submit(changed,execute=True,interactive=True,approval_reference=reference,execution_control=control)
        assert denied['reasons']==['approval_action_changed']
        replay=controller.submit(selected.to_dict(),execute=True,interactive=True,approval_reference=reference,execution_control=control)
        assert replay['reasons']==['approval_unknown_or_replayed']
        assert dict(launcher.snapshot)=={'executions_reserved':0,'output_bytes_reserved':0}
        assert launcher.close()['request_count']==0


def test_active_native_cancellation_reaps_owner_and_client(tmp_path):
    control=ExecutionControl(time.monotonic()+40)
    observed=set()
    with boundary(tmp_path,control,case='web-hierarchy-stalled',approval_required=False) as (audit,approvals,launcher,policy,session):
        runner=AuthoritySession(policy,audit,launcher,LinuxOfflineCoordinator(),SessionLimits(**LIMITS),
            session_id=session,provider=_FixedProposal('web-hierarchy-stalled'),approvals=approvals,deadline=control.deadline)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(runner.run,execute=True,interactive=False)
            try:
                seen=False;expiry=time.monotonic()+25
                while time.monotonic()<expiry and not pending.done():
                    process=getattr(launcher,'_process',None)
                    if process is not None:
                        observed.add(process.pid);observed.update(descendants(process.pid))
                    for pid in tuple(observed):
                        try:
                            command=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0',1)[0]
                        except (FileNotFoundError,ProcessLookupError):
                            continue
                        seen|=command==b'/tool/ffuf'
                    if seen:break
                    time.sleep(0.01)
                assert seen and not pending.done(),'confined ffuf did not reach active execution'
                runner.cancel();summary=pending.result(timeout=8)
            finally:runner.cancel()
        assert summary['stop_reason']=='session_cancelled' and summary['actions_succeeded']==0
        assert launcher._closed and launcher._process.poll() is not None
        assert launcher.close()['status']=='closed'
        assert_reaped(observed)


@pytest.mark.parametrize('field,value', [('target', '127.0.0.2'), ('port', 8081)])
def test_out_of_scope_proposal_is_denied_without_owner_execution(tmp_path, field, value):
    control = ExecutionControl(time.monotonic() + 30)
    selected = action('web-hierarchy-nested')
    if field == 'target':
        selected[field] = value
    else:
        selected['parameters'][field] = value
    with boundary(tmp_path, control, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected, execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked' and result['decision'] == 'deny'
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}
        assert launcher.close()['request_count'] == 0
    events = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert any(event['event_type'] == 'policy_decision' and event['decision'] == 'deny' for event in events)
    assert not any(event['event_type'] == 'execution_started' for event in events)
