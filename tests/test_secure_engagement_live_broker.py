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
    raw,source=audit(value,issued=now/c.SECOND);info=os.fstat(audit_reader.channel.fileno());source.update(device=info.st_dev,inode=info.st_ino)
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
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));snapshot=store.snapshot()
        assert snapshot['state']['usage']==row['prepared']['envelope']['cost']
        core.guarded_go(row);frame=p.decode_frame(pair[1].recv(32768),role='launcher',direction='request')
        assert frame['operation']=='GO' and frame['body']['reservation_event_id']==snapshot['events'][-1]['event_id']


def test_last_allowance_transactions_have_one_winner(tmp_path,monkeypatch):
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
    with lab(tmp_path,monkeypatch) as (core,store,rows,pair,channels):
        row=ready(core);core.reserve(proofs(core,row,channels));core.guarded_go(row);assert pair[1].recv(32768)
        store.revoke(expected_revision=1,expected_generation=0,event_id=uid(66));refused(core.watch,force=True)
        assert core.terminal_reason=='engagement_live_revoked' and store.snapshot()['state']['usage']['actions']==1


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
    with lab(tmp_path,monkeypatch) as (core,store,*_):
        row=ready(core);core.stop('engagement_live_cancelled');refused(core.prepare,core.slots[0]['session_id'],'http_headers');refused(core.open_session,1)
        core.transition(row,'terminal_unresolved','engagement_live_cancelled');refused(core.transition,row,'running')
        assert not store.snapshot()['reservations']


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
        assert phase.cleanup_deadline==102.0
        with pytest.raises(c.LiveError,match='cancelled'):phase.check()
        now[0]=100.5
        assert runtime._failure_deadline(phase)==102.0
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
        assert broker._close(150.0) is receipt and seen==[102.0]
        now[0]=101.0
        assert broker._close(180.0) is receipt and seen==[102.0]
        assert epoch.snapshot()['deadline_ns']==102*c.SECOND


def _preallocated_child_custody(tmp_path, monkeypatch):
    # Real portable pairs/files; Linux flags and memfd sealing are separately
    # native gates. This checks transfer, queued bytes and physical closure.
    with monkeypatch.context() as patch:
        created=[]
        def pair():
            a,z=socket.socketpair();a.setblocking(False);z.setblocking(False)
            created.extend((a,z));return a,z
        def one_way():
            a,z=pair();a.shutdown(socket.SHUT_WR);z.shutdown(socket.SHUT_RD);return a,z
        count=[0]
        def memfd(name):
            count[0]+=1;path=tmp_path/('evidence-memory-'+str(count[0]))
            writer=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            reader=os.open(path,os.O_RDONLY)
            return reader,writer
        original=host._pair_identity
        def identity(peer):
            actual=original(peer)
            # The platform flags do not purport to be Linux kernel evidence.
            return {**actual,'inode':actual['inode'] or 100000+peer.fileno(),'flags':2050}
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
