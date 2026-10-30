"""S42C-M01..M16: actual syscall return models, no native gate claims."""
from copy import deepcopy
import errno
import hashlib
from types import SimpleNamespace

import pytest
from recon_cockpit.secure_agent import engagement_live_endpoint_worker as e
from recon_cockpit.secure_agent import engagement_live_runtime as r
from recon_cockpit.secure_agent import engagement_live_contract as c
from test_secure_engagement_live_contract import prepared, opened, release, clock, uid, M


class Stream:
    def __init__(self,chunks=(),sends=()):self.chunks=list(chunks);self.sends=list(sends);self.read_calls=[];self.write_calls=[];self.delivered=bytearray()
    def recv(self,n):
        self.read_calls.append(n)
        item=self.chunks.pop(0)
        if isinstance(item,BaseException):raise item
        head,tail=item[:n],item[n:]
        if tail:self.chunks.insert(0,tail)
        return head
    def send(self,data):
        self.write_calls.append(bytes(data));count=self.sends.pop(0) if self.sends else len(data)
        if isinstance(count,BaseException):raise count
        self.delivered.extend(data[:count]);return count


@pytest.fixture
def meter(monkeypatch):
    monkeypatch.setattr(c,'sample_clock',lambda:clock())
    monkeypatch.setattr(e.time,'monotonic_ns',lambda:M+1000)
    def build(slot='http_headers'):
        value=prepared(slot);obj=e.Meter(value,uid(40),opened()['scope']);obj.arm(release(value));return obj
    return build


def refused(function,*args):
    with pytest.raises(c.LiveError):function(*args)


def test_exact_identify_and_headers_grammar(meter):
    h=meter();h.admit();s=Stream([h.expected]);assert h.receive(s)==e.HEADER_RESPONSE;assert h.send(s)
    assert bytes(s.delivered)==e.HEADER_RESPONSE and r.validate_meter(h.snapshot())['reason']=='complete'
    n=meter('http_identify');n.admit();assert n.receive(Stream([b'']))==b'';n.admit();s=Stream([e.IDENTIFY_REQUEST]);assert n.receive(s)==e.IDENTIFY_RESPONSE;assert n.send(s)
    assert bytes(s.delivered)==e.IDENTIFY_RESPONSE


def test_bounded_empty_native_probe_connections(meter):
    for endings in (('eof',),('reset',),('eof','eof'),('eof','reset'),('reset','eof'),('reset','reset')):
        m=meter('http_identify')
        for connection,kind in enumerate(endings,1):
            m.admit();before=deepcopy(m.events)
            s=Stream([b'' if kind=='eof' else ConnectionResetError(errno.ECONNRESET,'actual reset')])
            assert m.receive(s)==b'' and s.read_calls==[4096] and not s.write_calls
            assert m.events[:-1]==before and m.events[-1]['kind']==kind
            assert m.events[-1]['connection']==m.connections==connection
            assert all(m.events[-1][key]==0 for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after'))
            assert m.events[-1]['reason']is None and m.reason is None
            assert not m.requests and not m.responses and not m.current
        m.admit();s=Stream([m.expected]);assert m.receive(s)==m.reply;assert m.send(s)
        settled=r.validate_meter(m.snapshot())
        assert settled['accepted_connections']==len(endings)+1
        assert settled['received_request_bytes']==len(m.expected) and settled['sent_response_bytes']==len(m.reply)
        assert bytes(m.requests)==m.expected and bytes(m.responses)==bytes(s.delivered)==m.reply
        assert [row['kind'] for row in m.events if row['kind'] in ('eof','reset')]==list(endings)
    for slot in ('http_headers','http_identify'):
        for kind in ('eof','reset'):
            m=meter(slot)
            if slot=='http_identify':
                for _ in range(2):m.admit();assert m.receive(Stream([b'']))==b''
            m.admit();before=deepcopy(m.events)
            s=Stream([b'' if kind=='eof' else ConnectionResetError(errno.ECONNRESET,'actual reset')])
            with pytest.raises(c.LiveError) as caught:m.receive(s)
            assert caught.value.code=='engagement_live_meter_refused' and m.reason=='peer_eof'
            assert m.events[:-2]==before and [row['kind'] for row in m.events[-2:]]==[kind,'close']
            assert len(s.read_calls)==1 and not s.write_calls and not m.requests and not m.responses
            assert r.validate_meter(m.snapshot())['accepted_connections']==(3 if slot=='http_identify' else 1)
    other=OSError('not a ConnectionResetError');other.errno=errno.ECONNRESET
    for error in (ConnectionResetError(),ConnectionResetError(errno.EPIPE,'wrong errno'),OSError(errno.EIO,'other error'),other):
        m=meter('http_identify');m.admit();before=deepcopy(m.events);s=Stream([error])
        with pytest.raises(type(error)) as caught:m.receive(s)
        assert caught.value is error and s.read_calls==[4096] and not s.write_calls
        assert m.events==before and m.connections==1 and m.reason is None and not m.requests and not m.responses
    m=meter('http_identify');m.admit();refused(m.receive,Stream([m.expected]));assert not m.responses


def test_extra_or_unsupported_request_refused(meter):
    for content in (b'POST / HTTP/1.0\r\n\r\n',b'CONNECT x:443 HTTP/1.0\r\n\r\n',b'GET /x HTTP/1.0\r\n\r\n'):
        m=meter();m.admit();s=Stream([content]);refused(m.receive,s);assert not s.write_calls and m.reason=='malformed_request'


def test_segmented_request_not_responded_early(meter):
    m=meter();m.admit();s=Stream([m.expected[:8],m.expected[8:]])
    assert m.receive(s)is None and not s.write_calls
    assert m.receive(s)==m.reply and len(s.read_calls)==2


def test_one_request_no_pipeline_or_extra_data(meter):
    m=meter();m.admit();s=Stream([m.expected+m.expected]);refused(m.receive,s)
    assert m.reason=='malformed_request' and not s.write_calls
    m=meter();m.admit();s=Stream([m.expected]);m.receive(s);m.send(s)
    refused(m.admit);refused(m.send,s)
    assert len(s.write_calls)==1 # No second response can be generated after terminal settlement.


def test_connection_capacity_before_admission(meter):
    for slot,cap in (('http_identify',3),('http_headers',1)):
        m=meter(slot)
        for _ in range(cap):m.admit()
        refused(m.admit);assert m.connections==cap and m.reason=='connection_limit'


def test_read_never_exceeds_remaining(meter,tmp_path,monkeypatch):
    m=meter();m.admit();m.requests.extend(b'x'*255);s=Stream([b'GZ'])
    assert m.receive(s)is None and s.read_calls==[1] and s.chunks==[b'Z']
    refused(m.receive,s);assert s.read_calls==[1] and m.reason=='request_limit'
    _fixed_meter_fixture_peer_cases(meter,tmp_path,monkeypatch)


def _fixed_meter_fixture_peer_cases(meter,tmp_path,monkeypatch):
    """Actual fixed fixture path; declared transports/owners supply no gate proof."""
    import ast
    import base64
    from contextlib import contextmanager
    import json
    import os
    from pathlib import Path
    from recon_cockpit.secure_agent.engagement_live_context import BOUNDARY_CASES
    source=Path(__file__).with_name('engagement_live_native.py').read_text()
    tree=ast.parse(source)
    names={'canonical','sha','private_write','_read_test_observation','_meter_primitive_source','_drain_meter_peer','_meter_runtime_case'}
    functions=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in names]
    assert {node.name for node in functions}==names
    addition=ast.literal_eval(next(node.value for node in tree.body if isinstance(node,ast.Assign)and
        any(isinstance(target,ast.Name)and target.id=='_METER_PRIMITIVE_SOURCE'for target in node.targets)))
    worker_source=Path(e.__file__).read_text();original_worker_hash=hashlib.sha256(worker_source.encode()).hexdigest()
    scenarios=[]
    for identifier,case in BOUNDARY_CASES.items():
        if case['kind']in('meter_boundary','clock_boundary')and 'connection_cap'not in case['variant']:
            scenarios.append({'case_id':identifier,**case})
    assert {case['case_id']for case in scenarios}=={'S42C-X47','S42C-X48','S42C-X49','S42C-X50','S42C-X51','S42C-X52','S42C-X56','S42C-X57','S42C-X58'}

    class Peer:
        def __init__(self):self.input=[];self.output=[];self.reads=[];self.sent=[];self.blocking=False
        def send_input(self,raw):self.input.append(bytes(raw));return len(raw)
        def getblocking(self):return self.blocking
        def recv(self,maximum):
            self.reads.append(maximum);value=self.output.pop(0)
            if isinstance(value,BaseException):raise value
            assert len(value)<=maximum
            return value
    class Child:
        def __init__(self,peer):self.peer=peer;self.reads=[];self.detached=False
        def setblocking(self,value):assert value is False
        def recv(self,maximum):
            self.reads.append(maximum)
            if not self.peer.input:raise BlockingIOError()
            value=self.peer.input.pop(0);assert len(value)<=maximum
            return value
        def send(self,raw):self.peer.output.append(bytes(raw));self.peer.sent.append(bytes(raw));return len(raw)
        def detach(self):self.detached=True
    class DeclaredControl:
        deadline=10
        def check(self):pass
        def remaining(self):return 9

    for number,case in enumerate(scenarios):
        endings=('quiescent','eof','reset')+(('reset_hash_mismatch','other_error')if case['case_id']=='S42C-X47'else())
        for ending in endings:
            directory=tmp_path/(str(number)+'-'+ending);directory.mkdir()
            peer=Peer();child=Child(peer);stderr=bytearray();published=[];events=[];holders={}
            pipe=SimpleNamespace(fileno=lambda:987654)
            def select_backend(reads,writes,errors,timeout):
                assert not writes and not errors and 0<=timeout<=.1
                return ([value for value in reads if (value is pipe and stderr)or(value is peer and peer.output)or(value is child and peer.input)],[],[])
            class OS:
                def __getattr__(self,name):return getattr(os,name)
                def read(self,fd,maximum):
                    assert fd==987654
                    value=bytes(stderr[:maximum]);del stderr[:maximum];return value
            class Runtime:
                def __getattr__(self,name):return getattr(r,name)
                def _send_bytes(self,channel,raw,control):assert channel is peer;peer.send_input(raw)
                def runtime_digest(self,value):assert value=={'declared_runtime':True};return 'd'*64
            class Variants:
                def __init__(self,path,**configuration):self.records=[];self.configuration=configuration;self._host_runtime=False;self.instrumentation=[]
                def source(self,module,transform):
                    assert module=='engagement_live_endpoint_worker'
                    self.text=transform(worker_source);compile(self.text,'declared-meter-source','exec')
                    self.records.append({'module':module,'before_sha256':original_worker_hash,'after_sha256':hashlib.sha256(self.text.encode()).hexdigest()})
                def __enter__(self):return self
                def __exit__(self,*args):events.append('source_context_closed')
            @contextmanager
            def terminal():yield
            @contextmanager
            def session(path,source_variants):
                class Service:
                    _control=DeclaredControl();_runtime={'declared_runtime':True}
                    _sessions={'declared-session':{'endpoint':SimpleNamespace(owner=SimpleNamespace(channel=peer,process=SimpleNamespace(stderr=pipe),ready={'declared_control':True}))}}
                    def open_session(self):return {'binding':{'session_id':'declared-session'},'scope':opened()['scope']}
                    def prepare(self,sid,slot):
                        assert sid=='declared-session';base=meter(slot)
                        role_tree=ast.parse(source_variants.text)
                        selected=[node for node in role_tree.body if isinstance(node,ast.ClassDef)and node.name in('Meter','_LiveShortSocket')or
                                  isinstance(node,ast.FunctionDef)and node.name in('_live_drive_meter','_live_meter_clock')or
                                  isinstance(node,ast.Assign)and any(isinstance(target,ast.Name)and target.id.startswith('_LIVE_')for target in node.targets)]
                        role={'contract':c,'runtime':r,'time':SimpleNamespace(monotonic_ns=lambda:M+1000),
                              'hashlib':hashlib,'base64':base64,'headers_request':e.headers_request,
                              'IDENTIFY_REQUEST':e.IDENTIFY_REQUEST,'IDENTIFY_RESPONSE':e.IDENTIFY_RESPONSE,'HEADER_RESPONSE':e.HEADER_RESPONSE,
                              'socket':SimpleNamespace(socket=lambda **kw:child),'select':SimpleNamespace(select=select_backend),
                              'os':SimpleNamespace(write=lambda fd,raw:(stderr.extend(raw)or len(raw))if fd==2 else(_ for _ in()).throw(AssertionError('foreign fd')))}
                        exec(compile(ast.Module(body=selected,type_ignores=[]),'actual-fixed-meter-role','exec'),role)
                        base.__class__=role['Meter'];holders.update(meter=base,role=role)
                        return base.prepared
                    def execute(self,value,reference,control):
                        assert value is holders['meter'].prepared and reference=='declared-reference'
                        holders['actual_meter']=holders['role']['_live_drive_meter'](holders['meter'])
                        holders['marker']=bytes(stderr)
                        if ending=='eof':peer.output.append(b'')
                        elif ending=='reset':peer.output.append(ConnectionResetError(errno.ECONNRESET,'declared peer reset'))
                        elif ending=='reset_hash_mismatch':peer.output.extend([b'x',ConnectionResetError(errno.ECONNRESET,'declared peer reset')])
                        elif ending=='other_error':peer.output.append(OSError(errno.EIO,'declared unrelated I/O failure'))
                        raise c.LiveError('engagement_live_invalid_frame')
                    def _evidence_payload(self,**kwargs):published.append(kwargs);return {'declared':True},{}
                try:yield Service()
                finally:events.append('session_closed')
            namespace={'__name__':'declared_complete_meter_fixture','Path':Path,'os':OS(),'json':json,'hashlib':hashlib,'deepcopy':deepcopy,
                       'time':SimpleNamespace(monotonic=lambda:1.0,monotonic_ns=lambda:M+1000),'select':SimpleNamespace(select=select_backend),
                       'runtime':Runtime(),'contract':c,'SourceVariants':Variants,'terminal_input':terminal,'native_session':session,
                       '_METER_PRIMITIVE_SOURCE':addition,'review_actual':lambda *args:'declared-reference',
                       '_useful':lambda *args:events.append('declared_identify_prerequisite'),
                       '_write_case_payload':lambda directory,payload:('declared-output',payload)}
            exec(compile(ast.Module(body=deepcopy(functions),type_ignores=[]),'actual-meter-harness-functions','exec'),namespace)
            if ending in('reset_hash_mismatch','other_error'):
                with pytest.raises(AssertionError if ending=='reset_hash_mismatch'else OSError):namespace['_meter_runtime_case'](case,directory)
                assert not published and events[-2:]==['session_closed','source_context_closed']
                assert json.loads((directory/'meter-observation.json').read_bytes())==json.loads(holders['marker'][len(b'LIVE-METER-OBS '):-1])
                retained=(directory/'meter-peer-output.bin').read_bytes();record=json.loads((directory/'meter-peer-drain.json').read_bytes())
                assert retained==(b'x'if ending=='reset_hash_mismatch'else b'')
                assert record['termination']==('reset'if ending=='reset_hash_mismatch'else'error')
                assert record['error_type']==('AssertionError'if ending=='reset_hash_mismatch'else'OSError')
                continue
            result=namespace['_meter_runtime_case'](case,directory)
            assert result[0]=='declared-output'and len(published)==1 and events[-2:]==['session_closed','source_context_closed']
            marker=json.loads((directory/'meter-observation.json').read_bytes());actual_marker=json.loads(holders['marker'][len(b'LIVE-METER-OBS '):-1])
            assert marker==actual_marker and not stderr and child.detached
            output=(directory/'meter-peer-output.bin').read_bytes();drain=json.loads((directory/'meter-peer-drain.json').read_bytes())
            assert output==b''.join(peer.sent)and drain['termination']==ending and drain['retained_bytes']==len(output)
            assert drain['retained_sha256']==hashlib.sha256(output).hexdigest()and drain['error_type']is None
            assert drain['errno']==(errno.ECONNRESET if ending=='reset'else None)
            assert drain['output_hash_checked']==(case['kind']=='meter_boundary')
            assert drain['expected_output_sha256']==(marker['output_sha256']if case['kind']=='meter_boundary'else None)
            assert published[0]['boundary_observations'][0]['observation'].get('output_sha256')==marker.get('output_sha256')
            if 'request_cap'in case['variant']:
                cap=4096 if case['variant'].endswith('identify')else 256
                assert child.reads==[cap]and peer.input==[b'x']and output==b''and holders['meter'].reason=='request_limit'
            if case['kind']=='clock_boundary':assert 'output_sha256'not in marker
            assert all(1<=n<=4097 for n in peer.reads)

    # Direct helper failures retain exact prefixes and keep the primary error.
    helper=namespace['_drain_meter_peer'];kind={'kind':'meter_boundary'};empty={'output_sha256':hashlib.sha256(b'').hexdigest()}
    plain_reset=OSError('not a specialized reset');plain_reset.errno=errno.ECONNRESET
    negatives=[('wrong_reset_errno',[ConnectionResetError(errno.EPIPE,'wrong errno')],empty,ConnectionResetError),
               ('other_io_error',[OSError(errno.EIO,'other I/O')],empty,OSError),
               ('plain_oserror104',[plain_reset],empty,OSError),
               ('partial_then_reset',[b'x',ConnectionResetError(errno.ECONNRESET,'reset')],empty,AssertionError),
               ('over_cap',[b'x'*4097],empty,AssertionError)]
    for name,chunks,raw,error_type in negatives:
        directory=tmp_path/name;directory.mkdir();peer=Peer();peer.output=list(chunks)
        namespace['select']=SimpleNamespace(select=lambda reads,*args:([peer]if peer.output else[],[],[]))
        with pytest.raises(error_type):helper(peer,directory,kind,raw,10)
        output=(directory/'meter-peer-output.bin').read_bytes();record=json.loads((directory/'meter-peer-drain.json').read_bytes())
        assert len(output)<=4096 and record['error_type']==error_type.__name__ and record['retained_bytes']==len(output)
        if name=='partial_then_reset':assert output==b'x'and record['termination']=='reset'and record['output_hash_checked']is True
        if name=='over_cap':assert output==b'x'*4096 and record['output_overflow']is True and record['received_return_bytes']==4097
    for name,blocking,deadline in(('blocking_peer',True,10),('expired_original',False,1)):
        directory=tmp_path/name;directory.mkdir();peer=Peer();peer.blocking=blocking;peer.output=[b'']
        with pytest.raises(AssertionError):helper(peer,directory,kind,empty,deadline)
        assert peer.reads==[]and (directory/'meter-peer-output.bin').read_bytes()==b''
    directory=tmp_path/'deadline_during_drain';directory.mkdir();peer=Peer();peer.output=[b'']
    ticks=iter((1,10));oldtime=namespace['time'];namespace['time']=SimpleNamespace(monotonic=lambda:next(ticks))
    try:
        with pytest.raises(AssertionError):helper(peer,directory,kind,empty,10)
        record=json.loads((directory/'meter-peer-drain.json').read_bytes())
        assert peer.reads==[4097]and record['termination']=='eof'and record['error_type']=='AssertionError'
    finally:namespace['time']=oldtime
    directory=tmp_path/'primary_error_retained';directory.mkdir();peer=Peer();error=OSError(errno.EIO,'primary');peer.output=[error]
    oldwrite=namespace['private_write'];namespace['private_write']=lambda *args:(_ for _ in()).throw(OSError(errno.ENOSPC,'retention'))
    try:
        with pytest.raises(OSError)as caught:helper(peer,directory,kind,empty,10)
        assert caught.value is error and caught.value.meter_peer_retention_error.errno==errno.ENOSPC
    finally:namespace['private_write']=oldwrite
    assert hashlib.sha256(Path(e.__file__).read_bytes()).hexdigest()==original_worker_hash


def test_partial_read_counts_irreversible(meter):
    m=meter();m.admit();s=Stream([b'GE',BlockingIOError(),b'wrong'])
    assert m.receive(s)is None;assert m.receive(s)is None;refused(m.receive,s)
    assert bytes(m.requests)==b'GEwrong' and sum(x['actual_bytes'] for x in m.events if x['kind']=='recv')==7
    assert m.snapshot()['received_request_bytes']==7
    for slot,connection in (('http_headers',1),('http_identify',1),('http_identify',2),('http_identify',3)):
        m=meter(slot)
        for _ in range(connection-1):m.admit();assert m.receive(Stream([b'']))==b''
        m.admit();s=Stream([b'GE',ConnectionResetError(errno.ECONNRESET,'actual reset')])
        assert m.receive(s)is None;before=deepcopy(m.events)
        with pytest.raises(c.LiveError) as caught:m.receive(s)
        assert caught.value.code=='engagement_live_meter_refused' and m.reason=='peer_eof'
        assert s.read_calls==[m.request_limit,m.request_limit-2] and not s.write_calls
        assert m.events[:-2]==before and [row['kind'] for row in m.events[-2:]]==['reset','close']
        assert bytes(m.requests)==bytes(m.current)==b'GE' and not m.responses
        assert sum(row['actual_bytes'] for row in m.events if row['kind']=='recv')==2
        settled=r.validate_meter(m.snapshot())
        assert settled['received_request_bytes']==2 and settled['accepted_connections']==connection
        refused(m.receive,s);refused(m.admit)
        assert len(s.read_calls)==2 and m.connections==connection and bytes(m.requests)==b'GE'


def test_write_never_exceeds_remaining(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));m.responses.extend(b'x'*2047);s=Stream(sends=[1])
    assert not m.send(s) and s.write_calls==[m.reply[:1]]
    refused(m.send,s);assert len(s.write_calls)==1 and m.reason=='response_limit'


def test_partial_write_counts_irreversible(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));s=Stream(sends=[7,BlockingIOError(),5])
    assert not m.send(s);assert not m.send(s);assert not m.send(s)
    m.cancel();assert bytes(m.responses)==m.reply[:12] and bytes(s.delivered)==m.reply[:12]
    assert m.snapshot()['sent_response_bytes']==12


def test_eagain_no_refund_or_spin(meter):
    m=meter();m.admit();s=Stream([BlockingIOError()]);count=len(m.events)
    assert m.receive(s)is None and len(s.read_calls)==1 and len(m.events)==count
    m.receive(Stream([m.expected]));s=Stream(sends=[BlockingIOError()]);count=len(m.events)
    assert not m.send(s) and len(s.write_calls)==1 and len(m.events)==count
    assert not m.responses


def test_cancel_eof_priority_over_io(meter):
    m=meter();m.admit();s=Stream([m.expected]);m.cancel('channel_eof')
    refused(m.receive,s);refused(m.send,s);assert not s.read_calls and not s.write_calls
    assert m.reason=='channel_eof'


def test_late_arm_cannot_resurrect(meter):
    m=meter();m.cancel();before=deepcopy(m.snapshot())
    refused(m.arm,release(m.prepared));assert m.snapshot()==before
    m=meter();refused(m.arm,release(m.prepared));assert len([x for x in m.events if x['kind']=='arm'])==1


def test_current_clock_before_accept_read_write(meter,monkeypatch):
    for operation in ('admit','receive','send'):
        m=meter();s=Stream([m.expected]);
        if operation!='admit':m.admit()
        if operation=='send':m.receive(s);s.read_calls.clear()
        monkeypatch.setattr(c,'sample_clock',lambda:clock(100*c.SECOND))
        refused(getattr(m,operation),*(() if operation=='admit' else (s,)))
        assert not s.read_calls and not s.write_calls
        monkeypatch.setattr(c,'sample_clock',lambda:clock())


def test_deadline_after_partial_before_next_send(meter,monkeypatch):
    m=meter();m.admit();m.receive(Stream([m.expected]));s=Stream(sends=[9])
    assert not m.send(s);monkeypatch.setattr(c,'sample_clock',lambda:clock(10*c.SECOND))
    refused(m.send,s);assert len(s.write_calls)==1 and len(m.responses)==9
    m.cancel('timeout');assert m.snapshot()['sent_response_bytes']==9


def test_settlement_digest_and_unknown_delivery(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));unknown=r.validate_meter(m.snapshot())
    assert unknown['delivery_known'] is False and unknown['sent_response_bytes']is None
    m.send(Stream());known=r.validate_meter(m.snapshot());assert known['delivery_known'] and known['response_sha256']==hashlib.sha256(m.reply).hexdigest()
    bad=deepcopy(known);bad['sent_response_bytes']+=1;refused(r.validate_meter,bad)
    bad=deepcopy(known);bad['events'][2]['actual_bytes']+=1;refused(r.validate_meter,bad)
    n=meter('http_identify');n.admit()
    assert n.receive(Stream([ConnectionResetError(errno.ECONNRESET,'actual reset')]))==b''
    empty_unknown=r.validate_meter(n.snapshot());termination=deepcopy(empty_unknown['events'][-1])
    assert termination['kind']=='reset' and r.validate_meter_event(termination)==termination
    assert empty_unknown['delivery_known'] is False
    assert all(empty_unknown[key]is None for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'))
    n.admit();s=Stream([n.expected]);assert n.receive(s)==n.reply
    payload_unknown=r.validate_meter(n.snapshot())
    assert payload_unknown['request_sha256']==hashlib.sha256(n.expected).hexdigest()
    assert all(payload_unknown[key]is None for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'))
    assert n.send(s);settled=r.validate_meter(n.snapshot())
    assert settled['delivery_known'] and settled['accepted_connections']==2
    assert settled['received_request_bytes']==len(n.expected) and settled['sent_response_bytes']==len(n.reply)
    assert settled['response_sha256']==hashlib.sha256(n.reply).hexdigest()
    for kind in ('eof','reset'):
        event=deepcopy(termination);event['kind']=kind
        assert r.validate_meter_event(event)==event
        invalid=[]
        for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after'):
            bad=deepcopy(event);bad[key]=1;invalid.append(bad)
        # These mutations satisfy the generic arithmetic but still cannot be a
        # non-payload termination event, including in a direct witness row.
        bad=deepcopy(event);bad.update(requested_bytes=1,actual_bytes=1,remaining_before=1,remaining_after=0);invalid.append(bad)
        bad=deepcopy(event);bad.update(remaining_before=1,remaining_after=1);invalid.append(bad)
        bad=deepcopy(event);bad['reason']='peer_eof';invalid.append(bad)
        bad=deepcopy(event);bad['kind']='rst';invalid.append(bad)
        for bad_event in invalid:
            refused(r.validate_meter_event,bad_event)
            for snapshot in (empty_unknown,payload_unknown,settled):
                bad=deepcopy(snapshot);bad['events'][termination['sequence']-1]=bad_event
                refused(r.validate_meter,bad)
    for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'):
        bad=deepcopy(payload_unknown);bad[key]=0;refused(r.validate_meter,bad)
