"""S42C-B01..B24: actual durable transactions and bounded non-native sinks."""
from contextlib import contextmanager,ExitStack
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest
from recon_cockpit.secure_agent import engagement_live_contract as c
from recon_cockpit.secure_agent import engagement_live_protocol as p
from recon_cockpit.secure_agent import engagement_live_broker as host
from recon_cockpit.secure_agent import engagement_live_broker_worker as b
from recon_cockpit.secure_agent import engagement_live_witness as w
from recon_cockpit.secure_agent import engagement_dispatch_contract as d
from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger
from test_secure_engagement_live_contract import roe,uid
from test_secure_engagement_live_runtime import declared_runtime
from test_secure_engagement_live_witness import approval,audit,direct


class Rows:
    def __init__(self):self.rows=[];self.full=False
    def reserve(self,amount=32768,*,terminal=False):
        if self.full and not terminal:c.fail('limit_exceeded')
    def record(self,kind,data,**kw):
        self.reserve(terminal=kw.get('terminal',False));self.rows.append((kind,deepcopy(data)))


@contextmanager
def lab(tmp_path,monkeypatch,*,limits=None):
    origin=time.monotonic_ns();utc=1792540800000000000
    sample=lambda:{'utc_ns':utc+time.monotonic_ns()-origin,'mono_before_ns':time.monotonic_ns(),'mono_after_ns':time.monotonic_ns()}
    monkeypatch.setattr(c,'sample_clock',sample)
    selected=roe()
    if limits:selected['limits'].update(limits)
    directory=tmp_path/'ledger';store=DispatchLedger.create(directory,engagement_id=uid(1),roe=selected,event_id=uid(2))
    pair=socket.socketpair();pair[0].setblocking(False);pair[1].setblocking(False)
    rows=Rows();bundle=declared_runtime();specs=[{'slot_index':i,'reviewer_id':uid(20+i),'review_mode':'terminal','ingress_channel_id':uid(30+i)} for i in range(2)]
    core=b.BrokerCore(store,broker_id=uid(3),runtime=bundle,slot_specs=specs,deadline_ns=origin+120*c.SECOND,transcript=rows,launcher_channels=[(pair[0],p.ChannelSequence(uid(40),'launcher')),None])
    stack=ExitStack();reader,writer,_=stack.enter_context(direct(monkeypatch));audit_reader,audit_writer,source=stack.enter_context(direct(monkeypatch,kind='audit'))
    try:
        yield core,store,rows,pair,(reader,writer,audit_reader,audit_writer)
    finally:stack.close();pair[0].close();pair[1].close();store.close()


def ready(core):
    opened=core.open_session(0);value=core.prepare(opened['binding']['session_id'],'http_identify')
    row=core.dispatches[value['envelope']['dispatch_id']];core.transition(row,'preparing');core.transition(row,'ready_for_review')
    return row


def proofs(core,row,channels):
    reader,writer,audit_reader,audit_writer=channels;value=row['prepared'];now=c.sample_clock()['mono_after_ns']
    a=approval(value,issued=now,expires=value['envelope']['action_deadline_ns']);raw=c.canonical(a)
    writer.send(raw);packet=reader.poll();core.approval_packet(packet[0],now,reader)
    from test_secure_engagement_live_runtime import portable_socket_identity
    raw,source=audit(value,issued=now/c.SECOND);fd=audit_reader.channel.fileno();info=os.fstat(fd)
    declared=portable_socket_identity({'device':info.st_dev,'inode':info.st_ino},fd)
    source.update(device=declared['device'],inode=declared['inode'])
    core.audit_source=source;audit_writer.send(raw);packet=audit_reader.poll();core.audit_packet(packet[0],now,audit_reader)
    return {'prepared_sha256':c.prepared_digest(value),'reference_sha256':a['reference_sha256'],'consume_sequence':1,'audit_sequence':1}


def refused(function,*args,**kwargs):
    with pytest.raises((c.LiveError,d.DispatchLedgerError)):function(*args,**kwargs)


def recovered(directory):
    value=DispatchLedger.open(directory,read_only=True)
    try:return value.snapshot()
    finally:value.close()


def test_bootstrap_preallocates_exact_two_slots(tmp_path,monkeypatch):
    _preallocated_child_custody(tmp_path,monkeypatch)
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        assert len(core.slots)==2 and store.snapshot()['sessions']==[]
        first=core.open_session(0);second=core.open_session(1)
        assert first['binding']['session_id']!=second['binding']['session_id']
        assert len(store.snapshot()['sessions'])==2
        refused(core.open_session,0);refused(core.open_session,2)


def test_bootstrap_and_role_channel_mismatch_refuse(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);reader,writer,*_=channels
        bad=approval(row['prepared'],issued=c.sample_clock()['mono_after_ns']);bad['reviewer_id']=uid(999)
        writer.send(c.canonical(bad));raw,_=reader.poll();refused(core.approval_packet,raw,c.sample_clock()['mono_after_ns'],reader)
        assert not store.snapshot()['reservations']
        value={'schema_version':'1','channel_id':uid(999),'sequence':1,'operation':'GO','body':{}}
        refused(p.ChannelSequence(uid(40),'launcher').accept,value)


def test_prepare_requires_actual_current_state(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        opened=core.open_session(0);store.append_revision(roe(),expected_revision=1,expected_generation=0,event_id=uid(55))
        refused(core.prepare,opened['binding']['session_id'],'http_identify')
        assert not store.snapshot()['reservations']
    # Startup itself rejects unsupported fixed-prefix policies before it can
    # provide READY or create a session, not merely at a later prepare call.
    for index,change in enumerate(('excluded','missing_identify','missing_headers')):
        selected=roe()
        if change=='excluded':selected['excluded_services']=['http']
        else:selected['allowed_profiles']=[('configurable_http_headers_v1' if change=='missing_identify' else 'configurable_nmap_service_v1')]
        with DispatchLedger.create(tmp_path/str(index),engagement_id=uid(101+index),roe=selected,event_id=uid(111+index)) as store:
            before=store.snapshot();rows=Rows()
            refused(b.BrokerCore,store,broker_id=uid(3),runtime=declared_runtime(),
                slot_specs=[{'slot_index':i,'reviewer_id':uid(20+i),'review_mode':'terminal','ingress_channel_id':uid(30+i)} for i in range(2)],
                deadline_ns=time.monotonic_ns()+120*c.SECOND,transcript=rows,launcher_channels=[None,None])
            assert store.snapshot()==before and rows.rows==[]


def test_actual_witnesses_precede_reservation(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);pointers={'prepared_sha256':c.prepared_digest(row['prepared']),'reference_sha256':'f'*64,'consume_sequence':1,'audit_sequence':1}
        refused(core.reserve,pointers);assert not store.snapshot()['reservations']
        with pytest.raises(BlockingIOError):pair[1].recv(32768)


def test_fixed_reservation_charges_before_go(tmp_path,monkeypatch):
    _fixed_crash_precommit_rollback(tmp_path)
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));snapshot=store.snapshot()
        assert snapshot['state']['usage']==row['prepared']['envelope']['cost']
        core.guarded_go(row);frame=p.decode_frame(pair[1].recv(32768),role='launcher',direction='request')
        assert frame['operation']=='GO' and frame['body']['reservation_event_id']==snapshot['events'][-1]['event_id']


def test_last_allowance_transactions_have_one_winner(tmp_path,monkeypatch):
    _budget_error_propagation(tmp_path,monkeypatch)
    _budget_refusal_keeps_sibling(tmp_path,monkeypatch)
    with lab(tmp_path,monkeypatch,limits={'max_actions':1}) as (core,store,*_):
        barrier=threading.Barrier(2);answers=[]
        def compete(i):
            handle=DispatchLedger.open(tmp_path/'ledger')
            try:
                sid=uid(200+i);sample=c.sample_clock();handle.record_session(session_id=sid,clock=sample,original_deadline_ns=sample['mono_after_ns']+60*c.SECOND,event_id=uid(210+i),expected_revision=1,expected_generation=0)
                barrier.wait(timeout=2)
                try:handle.reserve(dispatch_id=uid(220+i),session_id=sid,slot='http_identify',approval={'broker_id':uid(230+i),'consume_sequence':1,'witness_sha256':'a'*64},audit={'writer_id':uid(240+i),'audit_sequence':1,'event_sha256':'b'*64},clock=c.sample_clock(),event_id=uid(250+i),expected_revision=1,expected_generation=0)
                except d.DispatchLedgerError:answers.append(False)
                else:answers.append(True)
            finally:handle.close()
        threads=[threading.Thread(target=compete,args=(i,)) for i in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(3);assert not thread.is_alive()
        assert sorted(answers)==[False,True] and store.snapshot()['state']['usage']['actions']==1


def _budget_error_propagation(tmp_path,monkeypatch):
    # Exercise the broker's bounded transaction, not only DispatchLedger. A
    # prior real reservation exhausts one limit; fresh direct witnesses still
    # cannot acquire another allowance or cause a release.
    for key,limit in (('max_actions',1),('max_connections',3),('max_request_bytes',4096),
                      ('max_response_bytes',4096),('max_engagement_ms',30000)):
        directory=tmp_path/key;directory.mkdir(mode=0o700)
        with lab(directory,monkeypatch,limits={key:limit,'max_action_ms':30000}) as (core,store,rows,pair,channels):
            sample=c.sample_clock()
            store.record_session(session_id=uid(200),clock=sample,
                original_deadline_ns=sample['mono_after_ns']+60*c.SECOND,event_id=uid(210),
                expected_revision=1,expected_generation=0)
            store.reserve(dispatch_id=uid(220),session_id=uid(200),slot='http_identify',
                approval={'broker_id':uid(230),'consume_sequence':1,'witness_sha256':'a'*64},
                audit={'writer_id':uid(240),'audit_sequence':1,'event_sha256':'b'*64},
                clock=c.sample_clock(),event_id=uid(250),expected_revision=1,expected_generation=0)
            row=ready(core);pointers=proofs(core,row,channels);before=store.snapshot()
            with pytest.raises(c.LiveError) as caught:core.reserve(pointers)
            assert caught.value.code=='engagement_live_allowance_exhausted'
            assert store.snapshot()==before and row['admission'] is None
            with pytest.raises(BlockingIOError):pair[1].recv(32768)


def _budget_refusal_keeps_sibling(tmp_path,monkeypatch):
    """A real pre-admission budget denial cannot stop an admitted sibling."""
    for fault in (False,True):
        directory=tmp_path/('guard-fault' if fault else 'budget-denial');directory.mkdir(mode=0o700)
        with lab(directory,monkeypatch,limits={'max_actions':2 if fault else 1}) as (core,store,rows,pair,channels):
            winner=ready(core);core.reserve(proofs(core,winner,channels));core.guarded_go(winner)
            pair[1].recv(32768)
            opened=core.open_session(1);value=core.prepare(opened['binding']['session_id'],'http_identify')
            loser=core.dispatches[value['envelope']['dispatch_id']]
            core.transition(loser,'preparing');core.transition(loser,'ready_for_review')
            with direct(monkeypatch) as (reader,writer,_):
                now=c.sample_clock()['mono_after_ns'];proof=approval(value,issued=now,expires=value['envelope']['action_deadline_ns'])
                writer.send(c.canonical(proof));packet=reader.poll();core.approval_packet(*packet,reader)
                raw,_=audit(value,sequence=2,audit_sequence=2,issued=now/c.SECOND)
                channels[3].send(raw);packet=channels[2].poll();core.audit_packet(*packet,channels[2])
            loser['pending_pointers']={'prepared_sha256':c.prepared_digest(value),
                'reference_sha256':proof['reference_sha256'],'consume_sequence':1,'audit_sequence':2}
            loop=b.BrokerLoop.__new__(b.BrokerLoop);loop.core=core
            loop.pending={1:({'operation':'DISPATCH'},loser)};replies=[];stops=[]
            loop.reply=lambda index,request,**kwargs:replies.append(kwargs['data'])
            loop.cancel_slot=lambda slot,reason:stops.append((slot['session_id'],reason))
            if fault:
                def fail_guard(row):c.fail('timeout')
                core.guarded_go=fail_guard
            loop.advance()
            assert winner['state']=='running' and not loop.pending and len(replies)==1
            assert store.snapshot()['state']['usage']['actions']==(2 if fault else 1)
            if fault:
                assert replies[0]['outcome']=='unresolved' and stops==[(opened['binding']['session_id'],'engagement_live_timeout')]
            else:
                assert replies[0]['outcome']=='denied' and replies[0]['reason']=='engagement_live_allowance_exhausted'
                assert replies[0]['admission'] is None and replies[0]['release'] is None and not stops
                assert loser['state']=='terminal_unresolved'
            with pytest.raises(BlockingIOError):pair[1].recv(32768)


def test_same_direct_proof_cannot_release_twice(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);pointers=proofs(core,row,channels);core.reserve(pointers);core.guarded_go(row)
        pair[1].recv(32768);before=store.snapshot();refused(core.reserve,pointers);refused(core.guarded_go,row)
        assert store.snapshot()==before
        with pytest.raises(BlockingIOError):pair[1].recv(32768)


def test_guard_holds_writer_lock_through_single_send(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));seen=[];original=p.send_once
        def observed(channel,raw):
            connection=sqlite3.connect(tmp_path/'ledger/records.sqlite3',timeout=0)
            try:
                with pytest.raises(sqlite3.OperationalError):connection.execute('BEGIN IMMEDIATE')
                seen.append('blocked');return original(channel,raw)
            finally:connection.close()
        monkeypatch.setattr(p,'send_once',observed);core.guarded_go(row)
        connection=sqlite3.connect(tmp_path/'ledger/records.sqlite3',timeout=0)
        try:connection.execute('BEGIN IMMEDIATE');connection.rollback()
        finally:connection.close()
        assert seen==['blocked']


def test_revoke_before_guard_prevents_send(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));store.revoke(expected_revision=1,expected_generation=0,event_id=uid(66))
        refused(core.guarded_go,row);assert recovered(tmp_path/'ledger')['state']['usage']['actions']==1
        with pytest.raises(BlockingIOError):pair[1].recv(32768)


def test_revoke_after_go_is_inflight_and_consumed(tmp_path,monkeypatch):
    _external_revoke_at_fixed_post_go_barrier(tmp_path,monkeypatch)
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));core.guarded_go(row);assert pair[1].recv(32768)
        store.revoke(expected_revision=1,expected_generation=0,event_id=uid(66));refused(core.watch,force=True)
        assert core.terminal_reason=='engagement_live_revoked' and store.snapshot()['state']['usage']['actions']==1


def _external_revoke_at_fixed_post_go_barrier(tmp_path,monkeypatch):
    """Execute the exact owned N39 hook against two actual ledger owners."""
    import ast
    from types import MethodType
    from engagement_live_native import broker_fault_transform
    source=broker_fault_transform('S42C-N39')(Path(b.__file__).read_text())
    function=next(node for node in ast.parse(source).body
        if isinstance(node,ast.FunctionDef) and node.name=='_fixed_fault_mark')
    directory=tmp_path/'post-go-barrier';directory.mkdir(mode=0o700)
    with lab(directory,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels))
        barrier=threading.Event();results=[];errors=[];observed=[]
        def mark(owner,dispatch,phase,stage,**kwargs):
            b.BrokerCore.mark(owner,dispatch,phase,stage,**kwargs)
            if getattr(owner,'_owned_fault_installed',False):
                observed.append((phase,stage,time.monotonic_ns()));barrier.set()
        namespace={'c':c,'time':time,'_fault_original_mark':mark}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<fixed N39 barrier>','exec'),namespace)
        monkeypatch.setattr(core,'mark',MethodType(namespace['_fixed_fault_mark'],core))
        def revoke():
            try:
                assert barrier.wait(2),'actual fixed barrier absent'
                with d._deadline_context(min(time.monotonic()+2,
                        row['prepared']['envelope']['action_deadline_ns']/c.SECOND)):
                    with DispatchLedger.open(directory/'ledger') as external:
                        state=external.snapshot()['state']
                        results.append(external.revoke(expected_revision=state['revision'],
                            expected_generation=state['generation'],event_id=uid(66)))
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=revoke);worker.start()
        try:core.guarded_go(row)
        finally:worker.join(2)
        assert not worker.is_alive() and not errors,errors
        assert len(results)==1 and results[0]['disposition']=='recorded'
        assert observed[0][:2]==('guard','end')
        assert pair[1].recv(32768)
        with pytest.raises(BlockingIOError):pair[1].recv(32768)
        snapshot=store.snapshot()
        assert len(snapshot['reservations'])==1 and not snapshot['completions']
        assert snapshot['state']['usage']==row['prepared']['envelope']['cost']
        assert snapshot['events'][-2]['request']['operation']=='reserve'
        assert snapshot['events'][-1]['request']['operation']=='revoke'
        refused(core.watch,force=True)
        assert core.terminal_reason=='engagement_live_revoked'


def test_send_eagain_short_and_unknown_never_retry(tmp_path,monkeypatch):
    for number,mode in enumerate(('eagain','short','unknown')):
        path=tmp_path/str(number);path.mkdir(mode=0o700)
        with lab(path,monkeypatch) as (core,store,rows,pair,channels):
            row=ready(core);core.reserve(proofs(core,row,channels));calls=[]
            def send(*args):
                calls.append(mode)
                if mode=='eagain':raise BlockingIOError()
                if mode=='unknown':raise OSError()
                return 1
            with monkeypatch.context() as patch:
                patch.setattr(p,'send_once',send);refused(core.guarded_go,row);refused(core.guarded_go,row)
            assert calls==[mode] and row['result']['outcome']=='unresolved' and recovered(path/'ledger')['state']['usage']['actions']==1


def test_guard_postsend_failure_retains_uncertainty(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));original=core.check;sent=p.send_once
        def send(channel,raw):
            count=sent(channel,raw);monkeypatch.setattr(core,'check',lambda:c.fail('timeout'));return count
        monkeypatch.setattr(p,'send_once',send);refused(core.guarded_go,row);monkeypatch.setattr(core,'check',original)
        assert pair[1].recv(32768) and row['result']['outcome']=='unresolved' and not store.snapshot()['completions']


def test_lost_ack_cannot_reissue_historical_receipt(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));event=store.snapshot()['events'][-1]
        request=event['request']
        fresh=DispatchLedger.open(tmp_path/'ledger')
        try:assert fresh.retry(request)['disposition']=='already_recorded';assert fresh.owner_reference!=core.owner_id
        finally:fresh.close()
        refused(core.reserve,row['pointers']);assert row['release']is None


def test_revision_narrowing_preserves_historical_usage(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));usage=store.snapshot()['state']['usage'];new=roe();new['limits']['max_actions']=1
        store.append_revision(new,expected_revision=1,expected_generation=0,event_id=uid(77));refused(core.watch,force=True)
        assert store.snapshot()['state']['usage']==usage and core.terminal_reason=='engagement_live_revision_changed'


def test_watch_priority_precedes_every_continuation(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));core.next_watch_ns=time.monotonic_ns();original=store.snapshot;order=[]
        def snapshot():order.append('watch');return original()
        send=p.send_once
        def observe(channel,raw):order.append('send');return send(channel,raw)
        monkeypatch.setattr(store,'snapshot',snapshot);monkeypatch.setattr(p,'send_once',observe);core.guarded_go(row)
        assert order[0]=='watch' and order[-1]=='send'


def test_watch_read_failure_cancels_instead_of_cache(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        old=deepcopy(core.snapshot_value)
        monkeypatch.setattr(store,'snapshot',lambda:(_ for _ in ()).throw(d.DispatchLedgerError('engagement_dispatch_timeout')))
        refused(core.watch,force=True);assert core.snapshot_value==old and core.terminal_reason=='engagement_live_timeout'
        refused(core.open_session,0)


def test_clock_failure_before_and_after_admission(tmp_path,monkeypatch):
    for admitted in (False,True):
        path=tmp_path/str(admitted);path.mkdir(mode=0o700)
        with lab(path,monkeypatch) as (core,store,rows,pair,channels):
            row=ready(core);pointers=proofs(core,row,channels)
            if admitted:core.reserve(pointers)
            now=c.sample_clock();now['utc_ns']+=60*c.SECOND;monkeypatch.setattr(c,'sample_clock',lambda:now)
            refused(core.guarded_go,row) if admitted else refused(core.reserve,pointers)
            assert store.snapshot()['state']['usage']['actions']==int(admitted)
            with pytest.raises(BlockingIOError):pair[1].recv(32768)


def test_cancel_eof_and_late_role_messages_are_terminal(tmp_path,monkeypatch):
    _broker_stop_frame_cases(tmp_path,monkeypatch)
    _reserved_window_barrier_stop(tmp_path,monkeypatch)
    _stopped_session_channel_eof(monkeypatch)
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        row=ready(core);core.stop('engagement_live_cancelled');refused(core.prepare,core.slots[0]['session_id'],'http_headers');refused(core.open_session,1)
        core.transition(row,'terminal_unresolved','engagement_live_cancelled');refused(core.transition,row,'running')
        assert not store.snapshot()['reservations']


def _broker_stop_frame_cases(tmp_path,monkeypatch):
    """Two open sessions share at most one local and one aggregate notice."""
    for prior in (0,1,2):
        directory=tmp_path/('stop-frames-'+str(prior));directory.mkdir(mode=0o700)
        with lab(directory,monkeypatch) as (core,store,rows,pair,channels):
            core.open_session(0);core.open_session(1)
            loop=b.BrokerLoop.__new__(b.BrokerLoop);loop.core=core;loop.lifecycle=pair[0]
            loop.lifecycle_sequence=p.ChannelSequence(core.broker_id,'lifecycle');loop.stopping=False
            loop.sequences={(role,index):None for role in ('launcher','endpoint') for index in (0,1)}
            cancelled=[];loop.send_role=lambda role,index,operation,body:cancelled.append((role,index,operation))
            for index in range(prior):
                loop.cancel_slot(core.slots[index],'engagement_live_cancelled')
                if index==0:
                    assert p.decode_frame(pair[1].recv(32768),role='lifecycle',direction='request')['operation']=='SESSION_STOP'
                else:
                    with pytest.raises(BlockingIOError):pair[1].recv(32768)
                loop.cancel_slot(core.slots[index],'engagement_live_cancelled')
                with pytest.raises(BlockingIOError):pair[1].recv(32768)
            loop.stop('engagement_live_cancelled')
            frame=p.decode_frame(pair[1].recv(32768),role='lifecycle',direction='request')
            assert frame['operation']=='BROKER_STOP'
            assert loop.lifecycle_sequence.sent_terminal==1+bool(prior)
            assert sorted(cancelled)==sorted((role,index,'CANCEL') for role in ('launcher','endpoint') for index in (0,1))
            loop.stop('engagement_live_cancelled')
            with pytest.raises(BlockingIOError):pair[1].recv(32768)


def _reserved_window_barrier_stop(tmp_path,monkeypatch):
    """The fixed native barrier must unwind on its real existing peer.

    The ledger reservation is real; the portable clock positions only this
    extracted instrumentation near its immutable tail bound. No native claim.
    """
    import ast
    import select
    from engagement_live_native import broker_fault_transform
    source=broker_fault_transform('S42C-N32')(Path(b.__file__).read_text())
    function=next(node for node in ast.parse(source).body
        if isinstance(node,ast.FunctionDef) and node.name=='_fixed_fault_mark')
    for signal_kind in ('eof','terminal_traffic'):
        directory=tmp_path/signal_kind;directory.mkdir(mode=0o700)
        with lab(directory,monkeypatch) as (core,store,rows,pair,channels):
            row=ready(core);core.reserve(proofs(core,row,channels));before=store.snapshot()
            envelope=deepcopy(row['prepared']['envelope']);started=time.monotonic_ns()
            clock=SimpleNamespace(time_ns=lambda:envelope['window_end_utc_ns']-1,
                monotonic_ns=lambda:envelope['action_deadline_ns']+40_000_000+time.monotonic_ns()-started,
                sleep=time.sleep)
            namespace={'c':c,'time':clock,'_fault_select':select,'_fault_original_mark':b.BrokerCore.mark}
            exec(compile(ast.Module(body=[function],type_ignores=[]),'<fixed N32 barrier>','exec'),namespace)
            if signal_kind=='eof':pair[1].close()
            else:pair[1].send(b'actual terminal traffic')
            with pytest.raises(c.LiveError) as caught:
                namespace['_fixed_fault_mark'](core,row,'reserve','end',related=row['admission'])
            assert caught.value.code=='engagement_live_cancelled'
            assert store.snapshot()==before and before['state']['usage']==envelope['cost']
            assert row['prepared']['envelope']==envelope and row['release'] is None
            assert any(kind=='phase' and data['phase']=='reserve' and data['stage']=='end'
                for kind,data in rows.rows)
            if signal_kind=='terminal_traffic':
                with pytest.raises(BlockingIOError):pair[1].recv(32768)


def _stopped_session_channel_eof(monkeypatch):
    """Real peer closure in a retired session must not stop its live sibling.

    The actual selector and witness decoder run; the final ingress callback is
    a bounded test sink, not a native dispatch or authority witness.
    """
    for state in ('stopping','closed','active'):
        with ExitStack() as stack:
            def pair():
                left,right=socket.socketpair();left.setblocking(False);right.setblocking(False)
                stack.callback(left.close);stack.callback(right.close);return left,right
            host_pair=pair();lifecycle=pair();ingress=[pair(),pair()]
            launchers=[pair(),pair()];endpoints=[pair(),pair()]
            readers=[stack.enter_context(direct(monkeypatch)) for _ in range(2)]
            audit_reader=stack.enter_context(direct(monkeypatch,kind='audit'))[0]
            core=SimpleNamespace(broker_id=uid(1700),dispatches={},
                slots=[{'ingress_channel_id':uid(1710+i),'state':state if i==0 else 'active'} for i in range(2)],
                watch=lambda:None,next_watch_ns=time.monotonic_ns()+20_000_000)
            loop=b.BrokerLoop(core,host=host_pair[0],lifecycle=lifecycle[0],
                ingress=[x[0] for x in ingress],launchers=[x[0] for x in launchers],
                endpoints=[x[0] for x in endpoints],approval_readers=[x[0] for x in readers],audit_reader=audit_reader)
            loop.advance=lambda:None;stopped=[];completed=[]
            def stop(reason):stopped.append(reason);loop.stopping=True
            def receive(index):
                assert index==1 and ingress[index][0].recv(64)==b'independent continuation'
                completed.append(index);loop.stopping=True
            loop.stop=stop;loop.ingress_request=receive
            readers[0][1].close();launchers[0][1].close();endpoints[0][1].close()
            ingress[1][1].send(b'independent continuation')
            loop.run()
            if state=='active':assert stopped==['engagement_live_invalid_witness'] and not completed
            else:assert not stopped and completed==[1]


def test_success_requires_actual_parser_meter_crosslinks(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));core.guarded_go(row)
        row['client']={'status':'succeeded'};row['meter']={'accepted_connections':1,'received_request_bytes':1,'sent_response_bytes':1}
        refused(core.complete,row);assert not store.snapshot()['completions']


def test_completion_after_revoke_is_data_only(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));e=row['prepared']['envelope'];store.revoke(expected_revision=1,expected_generation=0,event_id=uid(66))
        result=store.complete(dispatch_id=e['dispatch_id'],session_id=e['session_id'],outcome='reported_failure',observation=None,clock=c.sample_clock(),event_id=uid(67))
        assert result['kind']=='data_only';refused(core.guarded_go,row)
        assert not recovered(tmp_path/'ledger')['completions'][0]['continuation_eligible']


def test_completion_write_fault_keeps_admission_charged(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));e=row['prepared']['envelope'];before=store.snapshot()
        original=store._persist
        def broken(before,after):original(before,after);raise OSError('injected precommit write failure')
        monkeypatch.setattr(store,'_persist',broken)
        with pytest.raises((OSError,d.DispatchLedgerError)):store.complete(dispatch_id=e['dispatch_id'],session_id=e['session_id'],outcome='unresolved',observation=None,clock=c.sample_clock(),event_id=uid(68))
        monkeypatch.setattr(store,'_persist',original)
        assert recovered(tmp_path/'ledger')==before


def test_transcript_capacity_is_reserved_before_effect(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));rows.full=True;refused(core.guarded_go,row)
        with pytest.raises(BlockingIOError):pair[1].recv(32768)
        rows.record('state',{'to_state':'terminal_unresolved'},terminal=True)
        assert store.snapshot()['state']['usage']['actions']==1


    # Exact partition boundaries include the original terminal reserve.
    with tempfile.TemporaryFile() as stream:
        transcript=b.Transcript.__new__(b.Transcript);transcript.fd=stream.fileno();transcript.sealed=False
        transcript.bytes=c.BROKER_TRANSCRIPT_BYTES-8192-16
        transcript.sequence=c.BROKER_TRANSCRIPT_ROWS-8-1
        transcript.reserve(16)
        refused(transcript.reserve,17)
        transcript.sequence+=1;refused(transcript.reserve,1)
        transcript.bytes=c.BROKER_TRANSCRIPT_BYTES-16;transcript.sequence=c.BROKER_TRANSCRIPT_ROWS-1
        transcript.reserve(16,terminal=True);refused(transcript.reserve,17,terminal=True)
        transcript.sequence+=1;refused(transcript.reserve,1,terminal=True)


def test_exports_are_bounded_sealed_phase_snapshots(tmp_path,monkeypatch):
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        with tempfile.TemporaryFile() as file:
            seals={file.fileno():0};original=fcntl.fcntl
            get=getattr(fcntl,'F_GET_SEALS',1034);add=getattr(fcntl,'F_ADD_SEALS',1033)
            monkeypatch.setattr(fcntl,'F_GET_SEALS',get,raising=False);monkeypatch.setattr(fcntl,'F_ADD_SEALS',add,raising=False)
            def controlled(fd,op,*args):
                if fd==file.fileno() and op==get:return seals[fd]
                if fd==file.fileno() and op==add:seals[fd]|=args[0];return 0
                return original(fd,op,*args)
            monkeypatch.setattr(fcntl,'fcntl',controlled)
            ref=b.seal_export(file.fileno(),store.snapshot(),'initial',deadline=time.monotonic()+2)
            assert ref['seals']==15 and ref['sha256']==c.digest(os.pread(file.fileno(),ref['bytes'],0))
            refused(b.seal_export,file.fileno(),store.snapshot(),'final',deadline=time.monotonic()+2)


def test_original_deadline_covers_lock_phase_and_cleanup(tmp_path,monkeypatch):
    _fixed_crash_hold_deadline_cases()
    _fixed_crash_host_signal_cases()
    _broker_stop_deadline_cases(tmp_path,monkeypatch)
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));before=store.snapshot();core.deadline_ns=time.monotonic_ns()-1
        refused(core.guarded_go,row);assert store.snapshot()==before
        with pytest.raises(BlockingIOError):pair[1].recv(32768)
        with pytest.raises(c.LiveError):
            with c._deadline_context(time.monotonic()-1):store.snapshot()
        from recon_cockpit.secure_agent.execution import ExecutionControl,ExecutionStopped
        transport=host.EngagementBroker.__new__(host.EngagementBroker)
        transport._pid=os.getpid();transport._closed=False;transport._stop=threading.Event()
        transport._cleanup_epoch=None
        transport.control=ExecutionControl(time.monotonic()+2);transport._deadline_ns=int(transport.control.deadline*c.SECOND)
        transport._owner=object();transport._locks=[threading.Lock(),threading.Lock()];transport._observations=[]
        transport._sequence=[p.ChannelSequence(uid(70),'ingress'),p.ChannelSequence(uid(71),'ingress')]
        transport.bundle=SimpleNamespace(slots=[SimpleNamespace(ingress_host=pair[0]),None])
        digest=c.prepared_digest(row['prepared']);transport._prepared={digest:row['prepared']}
        original=ExecutionControl(time.monotonic()+.06);began=time.monotonic()
        with pytest.raises((c.LiveError,ExecutionStopped)):
            transport._dispatch_with_control(digest,'a'*64,1,1,control=original)
        assert time.monotonic()-began<.3
        assert p.decode_frame(pair[1].recv(32768),role='ingress',direction='request')['operation']=='DISPATCH'
        lock=threading.Lock();lock.acquire();began=time.monotonic()
        try:
            with pytest.raises((c.LiveError,ExecutionStopped)):
                with host._locked(lock,ExecutionControl(time.monotonic()+.04)):
                    pytest.fail('held lock was acquired')
            assert lock.locked() and time.monotonic()-began<.3
        finally:lock.release()
    # A failed persistent startup inherits the first stop, while constructing
    # and using an ordinary startup clip does not itself stop the session.
    from recon_cockpit.secure_agent.engagement_live_session import _CleanupEpoch
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    now=[100.0]
    with monkeypatch.context() as patch:
        patch.setattr(time,'monotonic',lambda:now[0])
        patch.setattr(time,'monotonic_ns',lambda:int(now[0]*c.SECOND))
        original=ExecutionControl(200.0,clock=time.monotonic);epoch=_CleanupEpoch(original)
        phase=host._ClippedControl(original,150*c.SECOND,cleanup_epoch=epoch)
        phase.check();assert phase.deadline==150 and epoch.snapshot() is None
        assert phase.cleanup_deadline==101.9
        with pytest.raises(c.LiveError,match='cancelled'):phase.check()
        now[0]=100.5
        assert runtime._failure_deadline(phase)==101.9
        # Its ten-second startup wrapper must not replace the original lifetime.
        startup=runtime._ClippedControl(phase,110.0)
        assert startup.deadline==110 and phase.deadline==150
        seen=[];receipt={'status':'complete'}
        def cleanup(processes,pins,*,deadline):seen.append(deadline);return receipt
        patch.setattr(runtime,'cleanup_owned',cleanup)
        broker=host.EngagementBroker.__new__(host.EngagementBroker)
        broker._pid=os.getpid();broker.control=original;broker._deadline_ns=150*c.SECOND
        broker._cleanup_epoch=epoch;broker._closed=False;broker._stop=threading.Event();broker._cleanup=None
        broker._owner=SimpleNamespace(process=SimpleNamespace(poll=lambda:0),pin=object(),
            channel=SimpleNamespace(shutdown=lambda how:None,close=lambda:None))
        broker.bundle=SimpleNamespace(take_evidence_readers=lambda:{},close=lambda:None)
        assert broker._close(150.0) is receipt and seen==[101.9]
        now[0]=101.0
        assert broker._close(180.0) is receipt and seen==[101.9]
        assert epoch.snapshot()['deadline_ns']==101_900_000_000


def _fixed_crash_namespace(case_id, clock, mark):
    """Load the reviewed sealed hook itself, with no process/signal namespace."""
    import ast
    from engagement_live_native import broker_fault_transform
    source=broker_fault_transform(case_id)(Path(b.__file__).read_text())
    names={'_FixedFaultConnection','_fixed_crash_hold','_fixed_fault_mark'}
    nodes=[node for node in ast.parse(source).body
           if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names]
    assert {node.name for node in nodes}==names
    namespace={'c':c,'time':clock,'_fault_sqlite':sqlite3,'_fault_original_mark':mark}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<fixed owned crash barrier>','exec'),namespace)
    return namespace


def _fixed_crash_precommit_rollback(tmp_path):
    """The actual N42 commit hook cannot make an uncommitted insert durable."""
    from test_secure_engagement_live_contract import prepared
    row={'prepared':prepared()};original=deepcopy(row);events=[];rows=Rows()
    owner=SimpleNamespace(transcript=rows)
    def mark(*args,**kwargs):
        b.BrokerCore.mark(*args,**kwargs)
        events.append('marker')
    def expired():
        events.append('clock')
        return row['prepared']['envelope']['action_deadline_ns']
    clock=SimpleNamespace(monotonic_ns=expired,
        sleep=lambda amount:pytest.fail('expired crash hold must not sleep'))
    namespace=_fixed_crash_namespace('S42C-N42',clock,mark)
    path=tmp_path/'fixed-crash-precommit.sqlite3'
    connection=sqlite3.connect(path,isolation_level=None)
    reader=sqlite3.connect(path,isolation_level=None)
    try:
        connection.execute('CREATE TABLE reservations (dispatch_id TEXT PRIMARY KEY)')
        connection.execute('CREATE TABLE metadata (value TEXT)')
        wrapped=namespace['_FixedFaultConnection'](connection,owner,row,'reserve','reservations','kill_precommit')
        # A non-target transaction commits normally; this is a reservation
        # precommit fault, not a wrapper that rejects every SQLite commit.
        wrapped.execute('BEGIN IMMEDIATE')
        wrapped.execute('INSERT INTO metadata (value) VALUES (?)',('baseline',))
        wrapped.commit()
        assert reader.execute('SELECT value FROM metadata').fetchall()==[('baseline',)]
        assert not wrapped.wrote and not wrapped.fired and events==[]
        with pytest.raises(RuntimeError,match='owned crash barrier expired without host signal'):
            with connection:
                wrapped.execute('BEGIN IMMEDIATE')
                wrapped.execute('INSERT INTO reservations (dispatch_id) VALUES (?)',
                    (row['prepared']['envelope']['dispatch_id'],))
                assert connection.in_transaction and wrapped.wrote
                assert connection.execute('SELECT count(*) FROM reservations').fetchone()==(1,)
                assert reader.execute('SELECT count(*) FROM reservations').fetchone()==(0,)
                wrapped.commit()
                pytest.fail('expired precommit hold returned to its caller')
        assert wrapped.fired and not connection.in_transaction
        assert connection.execute('SELECT count(*) FROM reservations').fetchone()==(0,)
        assert reader.execute('SELECT count(*) FROM reservations').fetchone()==(0,)
        assert events[0]=='marker' and events[1:] and set(events[1:])=={'clock'}
        assert len(rows.rows)==1
        kind,marker=rows.rows[0]
        assert kind=='phase' and (marker['phase'],marker['stage'],marker['reason'])==('reserve','begin',None)
        assert marker['related_sha256'] is not None and row==original
    finally:
        reader.close();connection.close()
    reopened=sqlite3.connect(path)
    try:
        assert reopened.execute('SELECT count(*) FROM reservations').fetchone()==(0,)
        assert reopened.execute('SELECT value FROM metadata').fetchall()==[('baseline',)]
    finally:reopened.close()


def _fixed_crash_hold_deadline_cases():
    """Declared clock advancement tests bounded refusal, never a native crash."""
    from test_secure_engagement_live_contract import prepared
    row={'prepared':prepared()};original=deepcopy(row)
    hard=row['prepared']['envelope']['action_deadline_ns']
    for start in (hard,hard+1,hard-20_000_000,hard-2*c.SECOND):
        now=[start];sleeps=[]
        def sleep(amount):
            assert 0<amount<=.005
            sleeps.append(amount);now[0]+=round(amount*c.SECOND)
        clock=SimpleNamespace(monotonic_ns=lambda:now[0],sleep=sleep)
        namespace=_fixed_crash_namespace('S42C-N42',clock,b.BrokerCore.mark)
        with pytest.raises(RuntimeError,match='owned crash barrier expired without host signal'):
            namespace['_fixed_crash_hold'](SimpleNamespace(),row)
            pytest.fail('fixed crash hold returned')
        assert now[0]==max(start,min(hard,start+c.SECOND))
        assert len(sleeps)<=201 and (bool(sleeps)==(start<hard))
        assert row==original
    for case_id,phase in (('S42C-N43','reserve'),('S42C-N44','go')):
        events=[];rows=Rows();owner=SimpleNamespace(transcript=rows)
        def mark(*args,**kwargs):
            b.BrokerCore.mark(*args,**kwargs);events.append('marker')
        def expired():events.append('clock');return hard
        clock=SimpleNamespace(monotonic_ns=expired,
            sleep=lambda amount:pytest.fail('expired crash hold must not sleep'))
        namespace=_fixed_crash_namespace(case_id,clock,mark)
        with pytest.raises(RuntimeError,match='owned crash barrier expired without host signal'):
            namespace['_fixed_fault_mark'](owner,row,phase,'end')
            pytest.fail('marked crash stage resumed execution')
        assert owner._owned_fault_installed and row==original
        assert events[:2]==['marker','marker'] and events[2:] and set(events[2:])=={'clock'}
        assert len(rows.rows)==2
        kind,marker=rows.rows[-1]
        assert kind=='phase' and (marker['phase'],marker['stage'],marker['reason'])==(phase,'end',None)
        assert marker['related_sha256'] is not None


def _fixed_crash_host_signal_cases():
    """The actual host selector can reach only a declared owned signal sink."""
    import ast
    import engagement_live_native as native
    from test_secure_engagement_live_contract import prepared
    value=prepared();env=value['envelope'];hard=env['action_deadline_ns']
    start=hard-2*c.SECOND
    nodes=[node for node in ast.parse(Path(native.__file__).read_text()).body
           if isinstance(node,ast.FunctionDef) and node.name=='_signal_at_fixed_crash_phase']
    assert len(nodes)==1
    code=compile(ast.Module(body=nodes,type_ignores=[]),'<fixed owned host signal>','exec')
    marker={'kind':'phase','broker_id':env['broker_id'],'observer_id':env['broker_id'],
        'session_id':env['session_id'],'dispatch_id':env['dispatch_id'],'observed_at_ns':start,
        'data':{'phase':'reserve','stage':'end','related_sha256':native.sha(native.canonical(value)),
            'original_deadline_ns':hard,'reason':None,
            'clock':{'utc_ns':0,'mono_before_ns':start-1,'mono_after_ns':start}}}
    def run(batches,*,error=None,match=None,ticket_delay_ns=0):
        now=[start];reads=[];signals=[];observations=[];sleeps=[]
        pidfd=object();sigkill=object();ticket=object()
        service=SimpleNamespace(_control=SimpleNamespace(deadline=(start+20_000_000)/c.SECOND),
            _broker=SimpleNamespace(pidfd=pidfd))
        pending=SimpleNamespace(done=lambda:False,
            result=lambda:pytest.fail('unfinished declared operation has no result'))
        def live_rows(selected):
            assert selected is service and not signals
            rows=batches[min(len(reads),len(batches)-1)];reads.append(deepcopy(rows))
            return deepcopy(rows)
        def sleep(amount):
            assert 0<amount<=.005
            sleeps.append(amount);now[0]+=max(1,round(amount*c.SECOND))
        def sample():return {'utc_ns':0,'mono_before_ns':now[0],'mono_after_ns':now[0]}
        def observe(selected,prepared_value,phase,stage,**kwargs):
            assert selected is service and prepared_value is value and phase=='reserve'
            observations.append((stage,kwargs))
        def phase_ticket(selected):
            assert selected is service
            now[0]+=ticket_delay_ns
            return ticket
        def signal_sink(*args):signals.append((args,len(reads),now[0]))
        namespace={'sha':native.sha,'canonical':native.canonical,
            'contract':SimpleNamespace(SECOND=c.SECOND,sample_clock=sample),
            'time':SimpleNamespace(monotonic=lambda:now[0]/c.SECOND,sleep=sleep),
            'signal':SimpleNamespace(pidfd_send_signal=signal_sink,SIGKILL=sigkill),
            '_live_rows':live_rows,'_phase_observation':observe,'_phase_ticket':phase_ticket}
        exec(code,namespace)
        invoke=lambda:namespace['_signal_at_fixed_crash_phase'](service,value,'reserve','end',pending=pending)
        if error is None:
            invoke()
            assert len(signals)==1 and signals[0][0]==(pidfd,sigkill,None,0)
            assert [stage for stage,kwargs in observations]==['begin','end']
            assert observations[-1][1]['ticket'] is ticket
        else:
            with pytest.raises(error,match=match):invoke()
            assert signals==[]
        assert not pending.done() and now[0]<hard
        return reads,signals,observations,sleeps
    ordinary=deepcopy(marker);ordinary['data']['related_sha256']=None
    reads,signals,observations,sleeps=run([[ordinary],[ordinary,marker]])
    assert len(reads)==2 and len(sleeps)==1 and signals[0][1]==2
    # Each mismatch must exhaust the host's finite wait without a signal,
    # even though the original action and declared pending work remain live.
    for section,key,replacement in (
        (None,'broker_id',uid(999)),(None,'observer_id',uid(999)),
        (None,'session_id',uid(999)),(None,'dispatch_id',uid(999)),
        ('data','phase','go'),('data','stage','begin'),
        ('data','related_sha256','f'*64),('data','original_deadline_ns',hard+1)):
        wrong=deepcopy(marker)
        (wrong if section is None else wrong[section])[key]=replacement
        reads,signals,observations,sleeps=run([[ordinary,wrong]],
            error=TimeoutError,match='actual fixed crash barrier')
        assert reads and sleeps and observations==[]
    run([[marker,deepcopy(marker)]],error=AssertionError,match='one exact fixed crash marker required')
    for age_ns in (c.SECOND,c.SECOND+1):
        expired=deepcopy(marker);observed=start-age_ns
        expired['observed_at_ns']=observed
        expired['data']['clock'].update(mono_before_ns=observed-1,mono_after_ns=observed)
        reads,signals,observations,sleeps=run([[expired]],
            error=TimeoutError,match='fixed crash barrier expired')
        assert len(reads)==1 and not sleeps
    # A marker live at lookup may expire during host observation/ticket work.
    expiring=deepcopy(marker);observed=start-c.SECOND+5_000_000
    expiring['observed_at_ns']=observed
    expiring['data']['clock'].update(mono_before_ns=observed-1,mono_after_ns=observed)
    run([[expiring]],error=TimeoutError,match='fixed crash barrier expired',ticket_delay_ns=5_000_000)


def _broker_stop_deadline_cases(tmp_path,monkeypatch):
    """Real fixed-channel stop packets retain original and first-stop bounds."""
    for stage in ('broker','session','action','early'):
        directory=tmp_path/stage;directory.mkdir(mode=0o700)
        with lab(directory,monkeypatch) as (core,store,rows,pair,channels):
            if stage in ('action','early'):
                row=ready(core);hard=row['prepared']['envelope']['action_deadline_ns']
            elif stage=='session':hard=core.open_session(0)['binding']['session_deadline_ns']
            else:hard=core.deadline_ns
            loop=b.BrokerLoop.__new__(b.BrokerLoop);loop.core=core;loop.lifecycle=pair[0]
            loop.lifecycle_sequence=p.ChannelSequence(core.broker_id,'lifecycle');loop.sequences={};loop.stopping=False
            now=[hard-4*c.SECOND if stage=='early' else hard-1_000_000]
            expected=hard-2*c.SECOND if stage=='early' else hard
            with monkeypatch.context() as patch:
                patch.setattr(time,'monotonic_ns',lambda:now[0])
                if stage=='broker':loop.stop('engagement_live_timeout')
                else:loop.cancel_slot(core.slots[0],'engagement_live_timeout')
                frame=p.decode_frame(pair[1].recv(32768),role='lifecycle',direction='request')
                assert frame['body']['cleanup_deadline_ns']==expected
                if stage!='broker':
                    # A later duplicate stop cannot renew an already-expired
                    # original bound or lose it after the slot is closed.
                    core.slots[0]['state']='closed'
                    now[0]=hard-3*c.SECOND if stage=='early' else hard+1_000_000
                    loop.stop('engagement_live_timeout')
                    frame=p.decode_frame(pair[1].recv(32768),role='lifecycle',direction='request')
                    assert frame['operation']=='BROKER_STOP' and frame['body']['cleanup_deadline_ns']==expected


def _preallocated_child_custody(tmp_path, monkeypatch):
    # Real portable pairs/files; Linux flags and memfd sealing are separately
    # native gates. This checks transfer, queued bytes and physical closure.
    with monkeypatch.context() as patch:
        created=[]
        def pair():
            a,z=socket.socketpair();a.setblocking(False);z.setblocking(False)
            created.extend((a,z));return a,z
        def one_way():
            from test_secure_engagement_live_runtime import portable_halfclose
            a,z=pair();portable_halfclose(a,z);return a,z
        count=[0]
        def memfd(name):
            count[0]+=1;path=tmp_path/('evidence-memory-'+str(count[0]))
            writer=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            reader=os.open(path,os.O_RDONLY)
            return reader,writer
        original=host._pair_identity
        def identity(peer):
            from test_secure_engagement_live_runtime import portable_socket_identity
            return portable_socket_identity(original(peer),peer.fileno())
        patch.setattr(host,'_pair',pair);patch.setattr(host,'_one_way',one_way)
        patch.setattr(host,'_memfd',memfd);patch.setattr(host,'_pair_identity',identity)
        bundle=host.preallocate_role_bundle('terminal');transferred={};ends={};readers={}
        try:
            rows=[row for slot in bundle.slots for row in slot.child_slot_bindings]
            assert len(rows)==12 and len({row['worker_id'] for row in rows})==12
            assert len({(row['pair'][side]['device'],row['pair'][side]['inode']) for row in rows
                        for side in ('request_endpoint','child_endpoint')})==24
            slot=bundle.slots[0];writer=bundle._peek('identify_client_request_0');reader=bundle._peek('identify_client_child_0')
            writer.send(b'not an INITIAL')
            before=set(bundle._owned)
            refused(slot.take_launcher_bootstrap)
            assert set(bundle._owned)==before and reader.recv(1024)==b'not an INITIAL'
            transferred=slot.take_launcher_bootstrap();ends=slot.take_child_endpoints()
            assert set(transferred)=={'host','child','broker_control','endpoint_arm',*(name+'_request' for name in c.CHILD_SLOTS)}
            assert set(ends)==set(c.CHILD_SLOTS)
            refused(slot.take_launcher_bootstrap);refused(slot.take_child_endpoints)
            for declaration in rows[:6]:
                name=declaration['child_slot']
                assert identity(ends[name])==declaration['pair']['child_endpoint']
                assert identity(transferred[name+'_request'])==declaration['pair']['request_endpoint']
                transferred[name+'_request'].send(b'x');assert ends[name].recv(1)==b'x'
            bundle.close_remaining_channels()
            refused(bundle.slots[1].take_launcher_bootstrap)
            refused(bundle.take_audit_writer)
            readers=bundle.take_evidence_readers()
            assert set(readers)=={'initial','final','transcript'}
            for fd in readers.values():
                assert os.fstat(fd).st_size==0
                with pytest.raises(OSError):os.write(fd,b'forbidden')
        finally:
            bundle.close()
            for peer in [*transferred.values(),*ends.values()]:peer.close()
            for fd in readers.values():os.close(fd)
        assert all(peer.fileno()==-1 for peer in created)
        # A failed close never becomes a later successful not_started fence.
        bundle=host.preallocate_role_bundle('terminal')
        class BrokenChannel:
            def close(self):raise OSError('declared close failure')
        bundle._owned['declared_broken_channel']=BrokenChannel()
        refused(bundle.close_remaining_channels)
        refused(bundle.close_remaining_channels)
        refused(bundle.close)
        refused(bundle.close)
